#!/usr/bin/env python3
"""
Anti-obfuscation detection system for repository submissions.
Detects various forms of code obfuscation to ensure code transparency.
Functional version: no classes, all logic in functions.
"""

import ast
import logging
import math
import os
import re
import subprocess
import sys
import tempfile
from enum import Enum
from urllib.parse import urlparse


# from validator.utils.logging import get_logger


# logger = get_logger(__name__)
logger = logging.getLogger("anti_obfuscation")

# --- Risk Level Enum ---
class RiskLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# --- Data Structures ---
def make_file_analysis_result(file_path: str, score: int = 0, issues: list[str] = None, ast_parseable: bool = True, readability_score: float = 1.0) -> dict:
    return {
        'file_path': file_path,
        'score': score,
        'issues': issues or [],
        'ast_parseable': ast_parseable,
        'readability_score': readability_score,
    }

def make_repository_analysis_result(
    repository: str,
    total_score: int,
    average_score: float,
    file_count: int,
    suspicious_files: list[dict],
    high_risk_files: list[str],
    risk_level: RiskLevel,
    is_obfuscated: bool,
    recommendation: str
) -> dict:
    return {
        'repository': repository,
        'total_score': total_score,
        'average_score': average_score,
        'file_count': file_count,
        'suspicious_files': suspicious_files,
        'high_risk_files': high_risk_files,
        'risk_level': risk_level,
        'is_obfuscated': is_obfuscated,
        'recommendation': recommendation,
    }

# --- Patterns and Scores ---
def get_suspicious_patterns() -> dict[str, any]:
    return {
        'base64_strings': re.compile(
            r'base64\.b64decode\s*\([^)]*["\"][A-Za-z0-9+/=]{50,}["\"]|'
            r'b64decode\s*\([^)]*["\"][A-Za-z0-9+/=]{50,}["\"]'
        ),
        'dynamic_execution': re.compile(
            r'\bexec\s*\(\s*["\"][^"\']*base64|'
            r'eval\s*\(\s*["\"][^"\']*base64|'
            r'\bexec\s*\(\s*.*\.decode\(|'
            r'\beval\s*\(\s*.*\.decode\('
        ),
        'simple_obfuscation': re.compile(
            r'\bexec\s*\(\s*base64\.b64decode|'
            r'\beval\s*\(\s*base64\.b64decode|'
            r'time\.sleep\s*\(\s*\d+\s*\).*exec|'
            r'time\.sleep\s*\(\s*\d+\s*\).*eval'
        ),
        'long_lines': lambda line: len(line.strip()) > 500,
        'hex_strings': re.compile(r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}'),
        'unicode_escapes': re.compile(r'\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}'),
        'suspicious_vars': re.compile(r'\b_{10,}[a-zA-Z0-9_]*\b|\b[a-zA-Z0-9_]*_{10,}\b'),
        'compression_markers': re.compile(r'zlib\.decompress\s*\(.*base64|gzip\.decompress\s*\(.*base64'),
        'serialization': re.compile(r'marshal\.loads\s*\(.*base64|pickle\.loads\s*\(.*base64'),
        'string_manipulation': re.compile(
            r'["\"][^"\']{50,}["\'].*\[::\-1\]|'
            r'chr\s*\(\s*ord.*chr\s*\(\s*ord.*chr\s*\(\s*ord'
        ),
    }

def get_obfuscation_scores() -> dict[str, int]:
    return {
        'base64_strings': 50,
        'dynamic_execution': 60,
        'simple_obfuscation': 80,
        'long_lines': 15,
        'hex_strings': 20,
        'unicode_escapes': 20,
        'suspicious_vars': 15,
        'compression_markers': 40,
        'serialization': 50,
        'string_manipulation': 25,
    }

ALLOWED_HOSTS = {'github.com', 'gitlab.com', 'bitbucket.org'}
MAX_REPO_SIZE_MB = 100

# --- Detection Functions ---
def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in char_counts.values():
        probability = count / text_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy

def detect_string_obfuscation(content: str) -> int:
    score = 0
    string_pattern = re.compile(r'["\"]([^"\'\\]|\\.){30,}["\"]')
    strings = string_pattern.findall(content)
    high_entropy_count = 0
    for string_match in strings:
        string_content = string_match[0] if string_match else ''
        if len(string_content) > 30:
            entropy = calculate_entropy(string_content)
            if entropy > 4.5:
                high_entropy_count += 1
    if high_entropy_count > 3:
        score += 30
    elif high_entropy_count > 0:
        score += 15
    return score

def detect_code_structure_anomalies(content: str) -> int:
    score = 0
    lines = content.splitlines()
    if not lines:
        return score
    non_empty_lines = [line for line in lines if line.strip()]
    if non_empty_lines:
        avg_line_length = sum(len(line) for line in non_empty_lines) / len(non_empty_lines)
        if avg_line_length > 120:
            score += 20
    semicolon_lines = sum(1 for line in lines if line.count(';') > 2)
    if semicolon_lines > len(lines) * 0.1:
        score += 25
    nested_def_pattern = re.compile(r'^\s{8,}(def|class)\s+')
    deep_nesting = sum(1 for line in lines if nested_def_pattern.match(line))
    if deep_nesting > 5:
        score += 15
    return score

def calculate_readability(content: str) -> float:
    if not content.strip():
        return 1.0
    lines = content.splitlines()
    total_lines = len(lines)
    comment_lines = sum(1 for line in lines if line.strip().startswith('#'))
    empty_lines = sum(1 for line in lines if not line.strip())
    docstring_lines = content.count('"""') + content.count("'''")
    meaningful_identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b', content)
    single_char_vars = re.findall(r'\b[a-z]\s*=\s*', content)
    acceptable_single_chars = {'i', 'j', 'k', 'x', 'y', 'z', 'n', 'm'}
    suspicious_single_chars = [var for var in single_char_vars if var[0] not in acceptable_single_chars]
    total_identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', content)
    identifier_ratio = len(meaningful_identifiers) / max(len(total_identifiers), 1)
    documentation_ratio = (comment_lines + empty_lines + docstring_lines) / max(total_lines, 1)
    single_char_penalty = len(suspicious_single_chars) / max(total_lines, 1)
    readability = (identifier_ratio + documentation_ratio) / 2 - single_char_penalty
    return max(0.0, readability)

def analyze_file(file_path: str, suspicious_patterns: dict[str, any], obfuscation_scores: dict[str, int]) -> dict:
    result = make_file_analysis_result(file_path)
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        logger.error(f"Error reading {file_path}: {e}")
        result['score'] = 100
        result['issues'].append(f"Failed to read file: {e}")
        return result
    if len(content.strip()) < 50:
        return result
    try:
        ast.parse(content)
    except:
        result['ast_parseable'] = False
        result['score'] += 40
        result['issues'].append("AST parse failed")
    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        for pattern_name, pattern in suspicious_patterns.items():
            if pattern_name == 'long_lines':
                if pattern(line):
                    result['score'] += obfuscation_scores[pattern_name]
                    result['issues'].append(f"Line {line_num}: Long line ({len(line)} chars)")
            elif isinstance(pattern, re.Pattern):
                matches = pattern.findall(line)
                if matches:
                    count = min(len(matches), 3)
                    result['score'] += obfuscation_scores[pattern_name] * count
                    result['issues'].append(f"Line {line_num}: {pattern_name} ({count} matches)")
    entropy_score = detect_string_obfuscation(content)
    if entropy_score > 0:
        result['score'] += entropy_score
        result['issues'].append(f"High entropy strings (+{entropy_score})")
    structure_score = detect_code_structure_anomalies(content)
    if structure_score > 0:
        result['score'] += structure_score
        result['issues'].append(f"Code structure anomalies (+{structure_score})")
    result['readability_score'] = calculate_readability(content)
    if result['readability_score'] < 0.2:
        result['score'] += 25
        result['issues'].append(f"Low readability: {result['readability_score']:.2f}")
    return result

def validate_repository_url(repo_url: str) -> tuple[bool, str]:
    if not repo_url.startswith(('https://', 'http://')):
        return False, "Only HTTPS/HTTP URLs are allowed"
    try:
        parsed = urlparse(repo_url)
        host = parsed.netloc.lower()
        if host.startswith('www.'):
            host = host[4:]
        if host not in ALLOWED_HOSTS:
            return False, f"Host '{host}' not in allowed list"
    except:
        return False, "Invalid URL format"
    suspicious_patterns = ['..', '\\', ';', '|', '&', '$', '`', '>', '<', '(', ')', '\n', '\r', '\x00']
    for pattern in suspicious_patterns:
        if pattern in repo_url:
            return False, f"URL contains suspicious pattern: {repr(pattern)}"
    return True, "URL validation passed"

def clone_repository(repo_url: str, temp_dir: str) -> tuple[bool, str]:
    logger.info(f"Validating URL: {repo_url}")
    is_valid, message = validate_repository_url(repo_url)
    if not is_valid:
        logger.warning(f"URL validation failed: {message}")
        return False, message
    repo_path = os.path.join(temp_dir, 'repo')
    clone_cmd = ['git', 'clone', '--depth', '1', repo_url, repo_path]
    logger.info("Cloning repository...")
    try:
        result = subprocess.run(
            clone_cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=60
        )
        logger.info("Clone successful")
    except subprocess.TimeoutExpired:
        logger.error("Clone timed out")
        return False, "Clone timeout"
    except subprocess.CalledProcessError as e:
        logger.error(f"Clone failed: {e.stderr}")
        return False, f"Clone failed: {e.stderr}"
    try:
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(repo_path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                try:
                    if os.path.isfile(file_path) and not os.path.islink(file_path):
                        total_size += os.path.getsize(file_path)
                except (OSError, FileNotFoundError):
                    continue
        size_mb = total_size / (1024 * 1024)
        logger.info(f"Repository size: {size_mb:.2f} MB")
        if size_mb > MAX_REPO_SIZE_MB:
            logger.warning(f"Repository too large: {size_mb:.2f}MB")
            return False, f"Repository too large (> {MAX_REPO_SIZE_MB}MB)"
    except Exception as e:
        logger.error(f"Size check failed: {e}")
        return False, f"Size check failed: {e}"
    return True, repo_path

def analyze_repository(repo_path: str, suspicious_patterns: dict[str, any], obfuscation_scores: dict[str, int]) -> dict:
    logger.info(f"Analyzing repository: {repo_path}")
    python_files = []
    suspicious_file_types = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {
            '.git', '__pycache__', 'node_modules', 'venv', '.venv',
            'build', 'dist', '.pytest_cache', '.mypy_cache'
        }]
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith('.py'):
                python_files.append(file_path)
            elif file.endswith(('.b64', '.base64', '.enc', '.encrypted', '.obf', '.obfuscated')):
                suspicious_file_types.append(file_path)
                logger.warning(f"Suspicious file type: {file_path}")
            elif any(keyword in file.lower() for keyword in ['payload', 'shell', 'exploit', 'malware', 'virus']):
                suspicious_file_types.append(file_path)
                logger.warning(f"Suspicious filename: {file_path}")
    total_score = 0
    suspicious_files = []
    high_risk_files = []
    if suspicious_file_types:
        total_score += len(suspicious_file_types) * 100
    for file_path in python_files:
        file_result = analyze_file(file_path, suspicious_patterns, obfuscation_scores)
        if file_result['score'] > 0:
            suspicious_files.append(file_result)
            total_score += file_result['score']
            if file_result['score'] >= 150:
                high_risk_files.append(file_path)
                logger.warning(f"High risk file: {file_path} (score: {file_result['score']})")
    file_count = len(python_files)
    avg_score = total_score / max(file_count, 1)
    suspicious_ratio = len(suspicious_files) / max(file_count, 1)
    is_obfuscated = (
        len(high_risk_files) > 0 or
        len(suspicious_file_types) > 0 or
        avg_score >= 30 or
        suspicious_ratio > 0.5
    )
    if len(high_risk_files) > 0 or len(suspicious_file_types) > 0:
        risk_level = RiskLevel.CRITICAL
        recommendation = "REJECT - Critical obfuscation indicators detected"
    elif avg_score >= 30:
        risk_level = RiskLevel.HIGH
        recommendation = "REJECT - High obfuscation score"
    elif avg_score >= 15 or suspicious_ratio > 0.3:
        risk_level = RiskLevel.MEDIUM
        recommendation = "MANUAL_REVIEW - Moderate obfuscation indicators"
    elif avg_score >= 5:
        risk_level = RiskLevel.LOW
        recommendation = "CAUTION - Minor obfuscation indicators"
    else:
        risk_level = RiskLevel.SAFE
        recommendation = "ACCEPT - No significant obfuscation detected"
    return make_repository_analysis_result(
        repository=repo_path,
        total_score=int(total_score),
        average_score=avg_score,
        file_count=file_count,
        suspicious_files=suspicious_files,
        high_risk_files=high_risk_files,
        risk_level=risk_level,
        is_obfuscated=is_obfuscated,
        recommendation=recommendation
    )

def check_repository(repo_url: str) -> tuple[bool, dict]:
    suspicious_patterns = get_suspicious_patterns()
    obfuscation_scores = get_obfuscation_scores()
    with tempfile.TemporaryDirectory() as temp_dir:
        success, result = clone_repository(repo_url, temp_dir)
        if not success:
            failed_result = make_repository_analysis_result(
                repository=repo_url,
                total_score=1000,
                average_score=1000,
                file_count=0,
                suspicious_files=[],
                high_risk_files=[],
                risk_level=RiskLevel.CRITICAL,
                is_obfuscated=True,
                recommendation=f"REJECT - {result}"
            )
            return False, failed_result
        repo_path = result
        analysis_result = analyze_repository(repo_path, suspicious_patterns, obfuscation_scores)
        analysis_result['repository'] = repo_url
        is_safe = not analysis_result['is_obfuscated']
        return is_safe, analysis_result

def is_repository_safe(repo_url: str) -> bool:
    is_safe, _ = check_repository(repo_url)
    return is_safe

# --- CLI Interface ---
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Anti-obfuscation detection system (functional version)")
    parser.add_argument('--repo', type=str, required=True, help='GitHub repo URL to analyze')
    args = parser.parse_args()
    repo_url = args.repo
    print(f"Analyzing repository: {repo_url}")
    is_safe, result = check_repository(repo_url)
    print(f"\n{'='*60}")
    print(f"Repository: {result['repository']}")
    print(f"Risk Level: {result['risk_level'].value}")
    print(f"Total Score: {result['total_score']}")
    print(f"Average Score: {result['average_score']:.1f}")
    print(f"Files Analyzed: {result['file_count']}")
    print(f"Suspicious Files: {len(result['suspicious_files'])}")
    print(f"High Risk Files: {len(result['high_risk_files'])}")
    print(f"Recommendation: {result['recommendation']}")
    print(f"{'='*60}\n")
    print("true" if is_safe else "false")
    sys.exit(0 if is_safe else 1)

if __name__ == "__main__":
    main()