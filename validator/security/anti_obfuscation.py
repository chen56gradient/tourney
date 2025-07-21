#!/usr/bin/env python3
"""
Anti-obfuscation detection system for repository submissions.
Detects various forms of code obfuscation to ensure code transparency.
"""

import ast
import os
import re
import subprocess
import tempfile
import sys
from urllib.parse import urlparse
from dataclasses import dataclass
from enum import Enum

from validator.utils.logging import get_logger

logger = get_logger(__name__)


class RiskLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class FileAnalysisResult:
    file_path: str
    score: int
    issues: list[str]
    ast_parseable: bool = True
    readability_score: float = 1.0


@dataclass
class RepositoryAnalysisResult:
    repository: str
    total_score: int
    average_score: float
    file_count: int
    suspicious_files: list[FileAnalysisResult]
    high_risk_files: list[str]
    risk_level: RiskLevel
    is_obfuscated: bool
    recommendation: str


class ObfuscationDetector:
    """Core obfuscation detection logic."""
    
    def __init__(self):
        self.suspicious_patterns = self._get_suspicious_patterns()
        self.obfuscation_scores = self._get_obfuscation_scores()
        self.allowed_hosts = {'github.com', 'gitlab.com', 'bitbucket.org'}
        self.max_repo_size_mb = 100
        
    def _get_suspicious_patterns(self) -> dict:
        """Get regex patterns for detecting obfuscation."""
        return {
            'base64_strings': re.compile(
                r'base64\.b64decode\s*\([^)]*["\'][A-Za-z0-9+/=]{50,}["\']|'
                r'b64decode\s*\([^)]*["\'][A-Za-z0-9+/=]{50,}["\']'
            ),
            'dynamic_execution': re.compile(
                r'\bexec\s*\(\s*["\'][^"\']*base64|'
                r'eval\s*\(\s*["\'][^"\']*base64|'
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
                r'["\'][^"\']{50,}["\'].*\[::-1\]|'
                r'chr\s*\(\s*ord.*chr\s*\(\s*ord.*chr\s*\(\s*ord'
            ),
        }
    
    def _get_obfuscation_scores(self) -> dict[str, int]:
        """Get scoring weights for different obfuscation patterns."""
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
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
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
                entropy -= probability * (probability.bit_length() - 1)
        return entropy
    
    def detect_string_obfuscation(self, content: str) -> int:
        """Detect obfuscated strings based on entropy."""
        score = 0
        string_pattern = re.compile(r'["\']([^"\'\\]|\\.){30,}["\']')
        strings = string_pattern.findall(content)
        
        high_entropy_count = 0
        for string_match in strings:
            string_content = string_match[0] if string_match else ''
            if len(string_content) > 30:
                entropy = self.calculate_entropy(string_content)
                if entropy > 4.5:
                    high_entropy_count += 1
        
        if high_entropy_count > 3:
            score += 30
        elif high_entropy_count > 0:
            score += 15
            
        return score
    
    def detect_code_structure_anomalies(self, content: str) -> int:
        """Detect anomalies in code structure."""
        score = 0
        lines = content.splitlines()
        if not lines:
            return score
        
        # Check average line length
        non_empty_lines = [line for line in lines if line.strip()]
        if non_empty_lines:
            avg_line_length = sum(len(line) for line in non_empty_lines) / len(non_empty_lines)
            if avg_line_length > 120:
                score += 20
        
        # Check for excessive semicolons
        semicolon_lines = sum(1 for line in lines if line.count(';') > 2)
        if semicolon_lines > len(lines) * 0.1:
            score += 25
        
        # Check for deep nesting
        nested_def_pattern = re.compile(r'^\s{8,}(def|class)\s+')
        deep_nesting = sum(1 for line in lines if nested_def_pattern.match(line))
        if deep_nesting > 5:
            score += 15
        
        return score
    
    def calculate_readability(self, content: str) -> float:
        """Calculate code readability score."""
        if not content.strip():
            return 1.0
        
        lines = content.splitlines()
        total_lines = len(lines)
        
        # Count documentation
        comment_lines = sum(1 for line in lines if line.strip().startswith('#'))
        empty_lines = sum(1 for line in lines if not line.strip())
        docstring_lines = content.count('"""') + content.count("'''")
        
        # Analyze identifiers
        meaningful_identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b', content)
        single_char_vars = re.findall(r'\b[a-z]\s*=', content)
        
        acceptable_single_chars = {'i', 'j', 'k', 'x', 'y', 'z', 'n', 'm'}
        suspicious_single_chars = [var for var in single_char_vars if var[0] not in acceptable_single_chars]
        total_identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', content)
        
        identifier_ratio = len(meaningful_identifiers) / max(len(total_identifiers), 1)
        documentation_ratio = (comment_lines + empty_lines + docstring_lines) / max(total_lines, 1)
        single_char_penalty = len(suspicious_single_chars) / max(total_lines, 1)
        
        readability = (identifier_ratio + documentation_ratio) / 2 - single_char_penalty
        return max(0.0, readability)
    
    def analyze_file(self, file_path: str) -> FileAnalysisResult:
        """Analyze a single file for obfuscation."""
        result = FileAnalysisResult(
            file_path=file_path,
            score=0,
            issues=[]
        )
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            result.score = 100
            result.issues.append(f"Failed to read file: {e}")
            return result
        
        # Skip very small files
        if len(content.strip()) < 50:
            return result
        
        # Check if AST parseable
        try:
            ast.parse(content)
        except:
            result.ast_parseable = False
            result.score += 40
            result.issues.append("AST parse failed")
        
        # Check patterns
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern in self.suspicious_patterns.items():
                if pattern_name == 'long_lines':
                    if pattern(line):
                        result.score += self.obfuscation_scores[pattern_name]
                        result.issues.append(f"Line {line_num}: Long line ({len(line)} chars)")
                elif isinstance(pattern, re.Pattern):
                    matches = pattern.findall(line)
                    if matches:
                        count = min(len(matches), 3)  # Cap multiplier
                        result.score += self.obfuscation_scores[pattern_name] * count
                        result.issues.append(f"Line {line_num}: {pattern_name} ({count} matches)")
        
        # Check string obfuscation
        entropy_score = self.detect_string_obfuscation(content)
        if entropy_score > 0:
            result.score += entropy_score
            result.issues.append(f"High entropy strings (+{entropy_score})")
        
        # Check structure anomalies
        structure_score = self.detect_code_structure_anomalies(content)
        if structure_score > 0:
            result.score += structure_score
            result.issues.append(f"Code structure anomalies (+{structure_score})")
        
        # Check readability
        result.readability_score = self.calculate_readability(content)
        if result.readability_score < 0.2:
            result.score += 25
            result.issues.append(f"Low readability: {result.readability_score:.2f}")
        
        return result
    
    def validate_repository_url(self, repo_url: str) -> tuple[bool, str]:
        """Validate repository URL for safety."""
        if not repo_url.startswith(('https://', 'http://')):
            return False, "Only HTTPS/HTTP URLs are allowed"
        
        try:
            parsed = urlparse(repo_url)
            host = parsed.netloc.lower()
            if host.startswith('www.'):
                host = host[4:]
            
            if host not in self.allowed_hosts:
                return False, f"Host '{host}' not in allowed list"
        except:
            return False, "Invalid URL format"
        
        # Check for injection attempts
        suspicious_patterns = ['..', '\\', ';', '|', '&', '$', '`', '>', '<', '(', ')', '\n', '\r', '\x00']
        for pattern in suspicious_patterns:
            if pattern in repo_url:
                return False, f"URL contains suspicious pattern: {repr(pattern)}"
        
        return True, "URL validation passed"
    
    def clone_repository(self, repo_url: str, temp_dir: str) -> tuple[bool, str]:
        """Safely clone repository with security checks."""
        logger.info(f"Validating URL: {repo_url}")
        
        is_valid, message = self.validate_repository_url(repo_url)
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
        
        # Check repository size
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
            
            if size_mb > self.max_repo_size_mb:
                logger.warning(f"Repository too large: {size_mb:.2f}MB")
                return False, f"Repository too large (>{self.max_repo_size_mb}MB)"
                
        except Exception as e:
            logger.error(f"Size check failed: {e}")
            return False, f"Size check failed: {e}"
        
        return True, repo_path
    
    def analyze_repository(self, repo_path: str) -> RepositoryAnalysisResult:
        """Analyze entire repository for obfuscation."""
        logger.info(f"Analyzing repository: {repo_path}")
        
        # Find Python files and suspicious files
        python_files = []
        suspicious_file_types = []
        
        for root, dirs, files in os.walk(repo_path):
            # Skip common non-code directories
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
        
        # Initialize results
        total_score = 0
        suspicious_files = []
        high_risk_files = []
        
        # Penalize suspicious file types heavily
        if suspicious_file_types:
            total_score += len(suspicious_file_types) * 100
            
        # Analyze Python files
        for file_path in python_files:
            file_result = self.analyze_file(file_path)
            if file_result.score > 0:
                suspicious_files.append(file_result)
                total_score += file_result.score
                
                if file_result.score >= 150:
                    high_risk_files.append(file_path)
                    logger.warning(f"High risk file: {file_path} (score: {file_result.score})")
        
        # Calculate metrics
        file_count = len(python_files)
        avg_score = total_score / max(file_count, 1)
        suspicious_ratio = len(suspicious_files) / max(file_count, 1)
        
        # Determine risk level and recommendation
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
        
        return RepositoryAnalysisResult(
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
    
    def check_repository(self, repo_url: str) -> tuple[bool, RepositoryAnalysisResult]:
        """Main entry point for repository checking."""
        with tempfile.TemporaryDirectory() as temp_dir:
            success, result = self.clone_repository(repo_url, temp_dir)
            if not success:
                # Create a failed result
                failed_result = RepositoryAnalysisResult(
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
            analysis_result = self.analyze_repository(repo_path)
            
            # Update repository path to URL in result
            analysis_result.repository = repo_url
            
            is_safe = not analysis_result.is_obfuscated
            return is_safe, analysis_result


def is_repository_safe(repo_url: str) -> bool:
    """Simple function for checking if a repository is safe."""
    detector = ObfuscationDetector()
    is_safe, _ = detector.check_repository(repo_url)
    return is_safe


# CLI Interface
def main():
    """Command-line interface for standalone usage."""
    if len(sys.argv) != 2:
        print("Usage: python anti_obfuscation.py <github_repo_url>")
        sys.exit(1)
    
    repo_url = sys.argv[1]
    detector = ObfuscationDetector()
    
    print(f"Analyzing repository: {repo_url}")
    is_safe, result = detector.check_repository(repo_url)
    
    print(f"\n{'='*60}")
    print(f"Repository: {result.repository}")
    print(f"Risk Level: {result.risk_level.value}")
    print(f"Total Score: {result.total_score}")
    print(f"Average Score: {result.average_score:.1f}")
    print(f"Files Analyzed: {result.file_count}")
    print(f"Suspicious Files: {len(result.suspicious_files)}")
    print(f"High Risk Files: {len(result.high_risk_files)}")
    print(f"Recommendation: {result.recommendation}")
    print(f"{'='*60}\n")
    
    # Output for script usage
    print("true" if is_safe else "false")
    sys.exit(0 if is_safe else 1)


if __name__ == "__main__":
    main()