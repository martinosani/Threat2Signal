"""Shared DeepSeek API client: lifecycle, telemetry, and cost computation."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import openai
from openai import OpenAI

logger = logging.getLogger(__name__)


class InsufficientBalanceError(Exception):
    """DeepSeek 402 -- account balance exhausted; halt the batch."""


@dataclass(frozen=True)
class Telemetry:
    """Per-call LLM telemetry captured from the API response."""

    model: str
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    reasoning_tokens: int
    finish_reason: str
    latency_ms: int
    cost_usd: float


def create_client(settings: dict) -> OpenAI:
    """Create a reusable OpenAI client configured for DeepSeek."""
    ds = settings["deepseek"]
    return OpenAI(
        api_key=ds["api_key"],
        base_url=ds["base_url"],
        max_retries=ds.get("max_retries", 3),
    )


def compute_cost(
    model: str,
    cache_hit_tokens: int,
    cache_miss_tokens: int,
    output_tokens: int,
    cost_rates: dict,
) -> float:
    """Compute USD cost using three-tier pricing (cache-hit, cache-miss, output).

    Listed rates are peak rates. Off-peak (outside 01:00-04:00 and 06:00-10:00
    UTC Mon-Fri) is 50% cheaper; WS-11 uses peak rates as conservative estimate.
    """
    rates = cost_rates.get(model, {})
    if not rates:
        logger.warning("No cost_rates for model %s, cost will be 0", model)
        return 0.0
    input_rate = rates.get("input_per_1m", 0)
    cache_rate = rates.get("cache_hit_per_1m", 0)
    output_rate = rates.get("output_per_1m", 0)
    cost = (
        cache_miss_tokens * input_rate
        + cache_hit_tokens * cache_rate
        + output_tokens * output_rate
    ) / 1_000_000
    return round(cost, 6)


def _extract_token_counts(usage: object | None) -> tuple[int, int, int, int]:
    """Pull token counts from the API usage object, defaulting missing fields to 0."""
    if usage is None:
        return 0, 0, 0, 0
    input_tokens = usage.prompt_tokens or 0
    output_tokens = usage.completion_tokens or 0
    cached_tokens = getattr(usage, "prompt_cache_hit_tokens", 0) or 0
    reasoning_tokens = 0
    details = getattr(usage, "completion_tokens_details", None)
    if details is not None:
        reasoning_tokens = getattr(details, "reasoning_tokens", 0) or 0
    return input_tokens, output_tokens, cached_tokens, reasoning_tokens


def call_deepseek(
    client: OpenAI,
    model: str,
    system_prompt: str,
    user_message: str,
    temperature: float | None = None,
    response_format: dict | None = None,
    timeout: int | None = None,
    thinking: dict | None = None,
    max_tokens: int | None = None,
    cost_rates: dict | None = None,
) -> tuple[str, Telemetry]:
    """Call DeepSeek chat API and return (content, telemetry).

    When thinking is disabled, temperature is applied. When thinking is enabled,
    temperature must be None (API rejects it).
    """
    kwargs = _build_request_kwargs(
        model, system_prompt, user_message,
        temperature, response_format, timeout, thinking, max_tokens,
    )

    start = time.monotonic()
    response = _execute_request(client, kwargs)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    content = response.choices[0].message.content or ""
    finish_reason = response.choices[0].finish_reason or "unknown"
    input_tokens, output_tokens, cached_tokens, reasoning_tokens = (
        _extract_token_counts(response.usage)
    )

    cache_miss_tokens = max(0, input_tokens - cached_tokens)
    cost = compute_cost(
        model, cached_tokens, cache_miss_tokens, output_tokens,
        cost_rates or {},
    )

    telemetry = Telemetry(
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached_tokens,
        reasoning_tokens=reasoning_tokens,
        finish_reason=finish_reason,
        latency_ms=elapsed_ms,
        cost_usd=cost,
    )

    if finish_reason == "length":
        logger.warning(
            "Response truncated (finish_reason=length, max_tokens=%s)",
            max_tokens,
        )

    if not content:
        logger.warning("DeepSeek returned empty content (known JSON mode issue)")

    return content, telemetry


def _build_request_kwargs(
    model: str,
    system_prompt: str,
    user_message: str,
    temperature: float | None,
    response_format: dict | None,
    timeout: int | None,
    thinking: dict | None,
    max_tokens: int | None,
) -> dict:
    """Assemble kwargs dict for chat.completions.create."""
    kwargs: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
    }
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens
    if response_format is not None:
        kwargs["response_format"] = response_format
    if timeout is not None:
        kwargs["timeout"] = timeout
    if thinking is not None:
        kwargs["extra_body"] = {"thinking": thinking}
    # V4 models reject temperature when thinking is enabled
    if temperature is not None and (
        thinking is None or thinking.get("type") == "disabled"
    ):
        kwargs["temperature"] = temperature
    return kwargs


def _execute_request(client: OpenAI, kwargs: dict) -> object:
    """Execute the API call, translating DeepSeek-specific errors."""
    model = kwargs.get("model", "unknown")
    try:
        return client.chat.completions.create(**kwargs)
    except openai.RateLimitError as exc:
        logger.error("DeepSeek rate limit exceeded (model=%s): %s", model, exc)
        raise
    except openai.APIStatusError as exc:
        if exc.status_code == 402:
            logger.error("DeepSeek API insufficient balance -- halting extraction")
            raise InsufficientBalanceError(str(exc)) from exc
        logger.error("DeepSeek API error (model=%s, status=%d): %s", model, exc.status_code, exc)
        raise
    except openai.APITimeoutError as exc:
        logger.error("DeepSeek request timed out (model=%s): %s", model, exc)
        raise
    except openai.APIError as exc:
        logger.error("DeepSeek API error (model=%s): %s", model, exc)
        raise
