"""
Shared helpers for calling the LLM safely and parsing its output.

Fixes:
- Issue #8: fragile ```json fence stripping
- Issue #10: no logging of LLM calls
- Issue #14: no timeout on LLM calls
- Issue #15: prompts asking for invalid-JSON enum syntax
"""

import json
import logging
import re
import concurrent.futures as cf
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Matches a fenced code block: ```json ... ``` / ```JSON ... ``` / ``` ... ```
# case-insensitive, tolerant of leading/trailing whitespace on the fence line.
_FENCE_RE = re.compile(r"```[ \t]*[jJ][sS][oO][nN]?[ \t]*\n?(.*?)```", re.DOTALL)
# Fallback: grab the first {...} block if fences aren't present at all.
_BRACE_RE = re.compile(r"\{.*\}", re.DOTALL)

DEFAULT_LLM_TIMEOUT_SECONDS = 30


class LLMTimeoutError(Exception):
    pass


class LLMParseError(Exception):
    pass


def call_llm_with_timeout(
    llm,
    prompt: str,
    *,
    timeout: int = DEFAULT_LLM_TIMEOUT_SECONDS,
    event_id: str = "",
    stage: str = "",
):
    """
    Wraps llm.invoke(prompt) with a hard timeout.
    """

    logger.debug("[%s][%s] LLM prompt:\n%s", stage, event_id, prompt)

    print(f"Calling LLM... timeout={timeout}")

    with cf.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(llm.invoke, prompt)

        print("Waiting for LLM response...")

        try:
            response = future.result(timeout=timeout)
            print("LLM response received")

        except cf.TimeoutError:
            print("LLM TIMED OUT")
            logger.error(
                "[%s][%s] LLM call exceeded %ss timeout",
                stage,
                event_id,
                timeout
            )
            raise LLMTimeoutError(
                f"LLM call timed out after {timeout}s"
            )

    content = getattr(response, "content", response)

    logger.debug(
        "[%s][%s] LLM response:\n%s",
        stage,
        event_id,
        content
    )

    return response


def parse_llm_json(raw_content: str, *, required_keys: Optional[list] = None) -> Dict[str, Any]:
    """
    Robustly extract a JSON object from an LLM response (Issue #8).

    Handles:
    - ```json fences, ```JSON fences, bare ``` fences, extra whitespace
    - responses with prose before/after the JSON block
    - falls back to grabbing the first {...} span if no fence is present

    Raises LLMParseError with the offending content attached if nothing
    parseable is found, or if required_keys are missing -- callers should
    catch this and apply their own explicit fail-safe default rather than
    silently guessing.
    """
    if raw_content is None:
        raise LLMParseError("empty LLM response")

    text = raw_content.strip()

    fence_match = _FENCE_RE.search(text)
    candidate = fence_match.group(1).strip() if fence_match else text

    try:
        result = json.loads(candidate)
    except json.JSONDecodeError:
        brace_match = _BRACE_RE.search(text)
        if not brace_match:
            raise LLMParseError(f"no JSON object found in LLM response: {text[:200]!r}")
        try:
            result = json.loads(brace_match.group(0))
        except json.JSONDecodeError as e:
            raise LLMParseError(f"could not parse JSON from LLM response: {e}; content={text[:200]!r}")

    if not isinstance(result, dict):
        raise LLMParseError(f"expected a JSON object, got {type(result).__name__}")

    if required_keys:
        missing = [k for k in required_keys if k not in result]
        if missing:
            raise LLMParseError(f"LLM JSON missing required keys {missing}: {result}")

    return result
