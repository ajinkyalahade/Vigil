"""
Anthropic API client for AI resolution generation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from anthropic import Anthropic, AnthropicError

from .models import ResolutionResponse
from .prompts import SYSTEM_PROMPT, get_prompt_for_category

logger = logging.getLogger(__name__)


class AnthropicClient:
    """
    Wrapper around Anthropic API for generating security resolutions.

    Handles:
    - API communication
    - Structured output parsing
    - Error handling and retries
    - Token tracking
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-5-20250929",
        max_tokens: int = 4096,
        timeout: int = 30,
    ):
        """
        Initialize Anthropic client.

        Args:
            api_key: Anthropic API key
            model: Model identifier
            max_tokens: Maximum tokens in response
            timeout: Request timeout in seconds
        """
        if not api_key:
            raise ValueError("Anthropic API key is required")

        self.client = Anthropic(api_key=api_key, timeout=timeout)
        self.model = model
        self.max_tokens = max_tokens

    async def generate_resolution(
        self,
        finding: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> tuple[ResolutionResponse, int, int]:
        """
        Generate a resolution for a security finding.

        Args:
            finding: Finding details (must include category)
            context: Additional context (os_version, username, etc.)

        Returns:
            Tuple of (ResolutionResponse, tokens_used, latency_ms)

        Raises:
            AnthropicError: If API call fails
            ValueError: If response can't be parsed
        """
        import time

        start_time = time.time()

        # Get category-specific prompt
        category = finding.get("category", "other")
        user_prompt = get_prompt_for_category(category, finding, context)

        logger.info(
            f"Generating resolution for finding category={category} "
            f"severity={finding.get('severity')}"
        )

        try:
            # Call Anthropic API
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

            latency_ms = int((time.time() - start_time) * 1000)
            tokens_used = response.usage.input_tokens + response.usage.output_tokens

            # Extract text content
            if not response.content or len(response.content) == 0:
                raise ValueError("Empty response from Anthropic API")

            text_content = response.content[0].text

            # Parse JSON response
            resolution_data = self._parse_json_response(text_content)

            # Validate with Pydantic
            resolution = ResolutionResponse(**resolution_data)

            logger.info(
                f"Generated resolution: tokens={tokens_used}, latency={latency_ms}ms, "
                f"confidence={resolution.confidence}"
            )

            return resolution, tokens_used, latency_ms

        except AnthropicError as e:
            logger.error(f"Anthropic API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error generating resolution: {e}")
            raise ValueError(f"Failed to generate resolution: {e}")

    def _parse_json_response(self, text: str) -> dict[str, Any]:
        """
        Parse JSON from AI response, handling potential markdown code blocks.

        Args:
            text: Response text from AI

        Returns:
            Parsed JSON dict

        Raises:
            ValueError: If JSON can't be parsed
        """
        # Try direct JSON parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting from markdown code block
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            if end != -1:
                json_text = text[start:end].strip()
                try:
                    return json.loads(json_text)
                except json.JSONDecodeError:
                    pass

        # Try extracting from generic code block
        if "```" in text:
            start = text.find("```") + 3
            end = text.find("```", start)
            if end != -1:
                json_text = text[start:end].strip()
                try:
                    return json.loads(json_text)
                except json.JSONDecodeError:
                    pass

        # Last attempt: find first { and last }
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            json_text = text[start : end + 1]
            try:
                return json.loads(json_text)
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Could not parse JSON from response: {text[:200]}...")
