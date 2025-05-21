import json
import re
from typing import Any

from fiber import Keypair

from core.models.utility_models import Message
from validator.utils.call_endpoint import post_to_nineteen_chat
from validator.utils.logging import get_logger


logger = get_logger(__name__)


def convert_to_nineteen_payload(
    messages: list[Message], model: str, temperature: float, max_tokens: int = 1000, stream: bool = False
) -> dict:
    return {
        "messages": [message.model_dump() for message in messages],
        "model": model,
        "temperature": temperature,
        "stream": stream,
        "max_tokens": max_tokens,
    }


def remove_reasoning_part(content: str, end_of_reasoning_tag: str) -> str:
    if not content:
        return ""
        
    # Check for explicit end of reasoning tag
    if end_of_reasoning_tag and end_of_reasoning_tag in content:
        parts = content.split(end_of_reasoning_tag)
        if len(parts) > 1:
            return parts[1].strip()
            
    # If not found, look for "<think>...</think>" pattern
    think_start = "<think>"
    think_end = "</think>"
    
    if think_start in content and think_end in content:
        try:
            parts = content.split(think_end, 1)
            if len(parts) > 1:
                return parts[1].strip()
        except:
            pass
            
    # If "</think>" not found but "<think>" exists, try to extract content after think block
    if think_start in content and think_end not in content:
        try:
            think_content = content.split(think_start, 1)[1]
            # Look for double newline which often separates thinking from response
            if "\n\n" in think_content:
                return think_content.split("\n\n", 1)[1].strip()
        except:
            pass
    
    # If we couldn't extract thinking, return original content as fallback
    return content


def extract_json_from_response(response: str) -> dict:
    """
    Extract JSON from an API response with more robust handling for different formats.
    """
    try:
        # First check if the full response is valid JSON
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Not a valid JSON, continue to extraction methods
            pass
            
        # Try to use regex patterns to find JSON objects
        # First try to find content in triple backticks
        matches = re.findall(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", response)
        if matches:
            for potential_json in matches:
                try:
                    return json.loads(potential_json)
                except:
                    continue
                    
        # Try to find JSON block with curly braces on their own lines
        lines = response.split('\n')
        potential_json = ""
        in_json_block = False
        for line in lines:
            line = line.strip()
            if line == '{':
                potential_json = '{'
                in_json_block = True
            elif line == '}' and in_json_block:
                potential_json += '}'
                try:
                    return json.loads(potential_json)
                except:
                    in_json_block = False
                    potential_json = ""
            elif in_json_block:
                potential_json += line
                
        # Last resort: try to find any text that looks like JSON
        pattern = r"\{[\s\S]*?\}"  # Non-greedy match to find the first valid JSON block
        json_match = re.search(pattern, response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except:
                # If that fails, try a more greedy match to get the largest JSON block
                pattern = r"\{[\s\S]*\}"
                json_match = re.search(pattern, response)
                if json_match:
                    return json.loads(json_match.group())
                
        raise ValueError(f"No valid JSON found in response")
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Failed to parse JSON from response: {response}")
        raise e


async def post_to_nineteen_chat_with_reasoning(
    payload: dict[str, Any], keypair: Keypair, end_of_reasoning_tag: str
) -> str | None:
    response = await post_to_nineteen_chat(payload, keypair)
    return remove_reasoning_part(response, end_of_reasoning_tag)
