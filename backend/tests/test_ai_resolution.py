"""
Tests for AI resolution generation.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_check.ai_resolution.client import AnthropicClient
from security_check.ai_resolution.models import ResolutionResponse, ResolutionStep


class TestAnthropicClient:
    """Tests for AnthropicClient."""

    def test_init_without_api_key_raises(self):
        """Should raise ValueError if API key is not provided."""
        with pytest.raises(ValueError, match="API key is required"):
            AnthropicClient(api_key="")

    def test_init_with_valid_key(self):
        """Should initialize successfully with valid API key."""
        client = AnthropicClient(api_key="sk-ant-test123")
        assert client.model == "claude-sonnet-4-5-20250929"
        assert client.max_tokens == 4096

    def test_parse_json_response_direct(self):
        """Should parse direct JSON response."""
        client = AnthropicClient(api_key="sk-ant-test")
        response = '{"analysis": "test", "steps": [], "confidence": "high"}'
        result = client._parse_json_response(response)
        assert result["analysis"] == "test"
        assert result["confidence"] == "high"

    def test_parse_json_response_with_markdown(self):
        """Should extract JSON from markdown code block."""
        client = AnthropicClient(api_key="sk-ant-test")
        response = '''Here's the resolution:
```json
{
  "analysis": "test",
  "steps": [],
  "confidence": "high"
}
```
'''
        result = client._parse_json_response(response)
        assert result["analysis"] == "test"

    def test_parse_json_response_with_generic_code_block(self):
        """Should extract JSON from generic code block."""
        client = AnthropicClient(api_key="sk-ant-test")
        response = '''```
{"analysis": "test", "steps": [], "confidence": "high"}
```'''
        result = client._parse_json_response(response)
        assert result["analysis"] == "test"

    def test_parse_json_response_fallback_to_braces(self):
        """Should fall back to extracting between first { and last }."""
        client = AnthropicClient(api_key="sk-ant-test")
        response = 'Some text before {"analysis": "test", "steps": [], "confidence": "high"} and after'
        result = client._parse_json_response(response)
        assert result["analysis"] == "test"

    def test_parse_json_response_invalid_raises(self):
        """Should raise ValueError if JSON can't be parsed."""
        client = AnthropicClient(api_key="sk-ant-test")
        with pytest.raises(ValueError, match="Could not parse JSON"):
            client._parse_json_response("This is not JSON at all")

    @pytest.mark.asyncio
    async def test_generate_resolution_success(self):
        """Should generate resolution successfully with mocked API."""
        client = AnthropicClient(api_key="sk-ant-test")

        # Mock the Anthropic API response
        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(
                text=json.dumps(
                    {
                        "analysis": "The SSH key has incorrect permissions",
                        "steps": [
                            {
                                "order": 1,
                                "description": "Check current permissions",
                                "command": "ls -la ~/.ssh/id_rsa",
                                "expected_output": "-rw-r--r--",
                                "is_safe": True,
                                "requires_confirmation": False,
                            },
                            {
                                "order": 2,
                                "description": "Fix permissions",
                                "command": "chmod 600 ~/.ssh/id_rsa",
                                "expected_output": "",
                                "is_safe": True,
                                "requires_confirmation": True,
                            },
                        ],
                        "safety_notes": ["This modifies file permissions"],
                        "verification": {
                            "command": "ls -la ~/.ssh/id_rsa",
                            "expected_output": "-rw-------",
                        },
                        "references": ["https://www.ssh.com/academy/ssh/config"],
                        "confidence": "high",
                    }
                )
            )
        ]
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=200)

        with patch.object(client.client.messages, "create", return_value=mock_response):
            finding = {
                "category": "config",
                "title": "SSH key world-readable",
                "description": "Private key has incorrect permissions",
                "severity": "high",
                "evidence": {"path": "~/.ssh/id_rsa", "permissions": "-rw-r--r--"},
            }

            resolution, tokens, latency = await client.generate_resolution(finding)

            assert isinstance(resolution, ResolutionResponse)
            assert resolution.analysis == "The SSH key has incorrect permissions"
            assert len(resolution.steps) == 2
            assert resolution.steps[0].order == 1
            assert resolution.confidence == "high"
            assert tokens == 300
            assert latency >= 0  # May be 0 for mocked calls

    @pytest.mark.asyncio
    async def test_generate_resolution_empty_response_raises(self):
        """Should raise ValueError if API returns empty response."""
        client = AnthropicClient(api_key="sk-ant-test")

        mock_response = MagicMock()
        mock_response.content = []

        with patch.object(client.client.messages, "create", return_value=mock_response):
            finding = {"category": "config", "title": "Test"}

            with pytest.raises(ValueError, match="Empty response"):
                await client.generate_resolution(finding)


class TestPrompts:
    """Tests for prompt generation."""

    def test_config_prompt_generation(self):
        """Should generate config-specific prompt."""
        from security_check.ai_resolution.prompts import build_config_prompt

        finding = {
            "title": "SSH key world-readable",
            "description": "Private key has incorrect permissions",
            "category": "config",
            "severity": "high",
            "evidence": {"path": "~/.ssh/id_rsa"},
        }

        context = {"os_version": "macOS 14.2", "username": "testuser"}

        prompt = build_config_prompt(finding, context)

        assert "SSH key world-readable" in prompt
        assert "macOS 14.2" in prompt
        assert "testuser" in prompt
        assert "chmod" in prompt.lower()

    def test_vuln_prompt_generation(self):
        """Should generate vulnerability-specific prompt."""
        from security_check.ai_resolution.prompts import build_vuln_prompt

        finding = {
            "title": "Vulnerable package",
            "description": "CVE-2024-1234",
            "category": "vuln",
            "severity": "high",
            "evidence": {"package": {"name": "curl", "version": "7.0.0"}},
        }

        prompt = build_vuln_prompt(finding)

        assert "curl" in prompt
        assert "7.0.0" in prompt
        assert "brew upgrade" in prompt.lower() or "package update" in prompt.lower()

    def test_secrets_prompt_generation(self):
        """Should generate secrets-specific prompt."""
        from security_check.ai_resolution.prompts import build_secrets_prompt

        finding = {
            "title": "API key in environment",
            "description": "Found token in .zshrc",
            "category": "secrets",
            "severity": "high",
            "evidence": {"file": "~/.zshrc", "variable": "API_TOKEN"},
        }

        prompt = build_secrets_prompt(finding)

        assert "API key" in prompt or "token" in prompt.lower()
        assert "rotate" in prompt.lower() or "invalidat" in prompt.lower()
        assert "NEVER include actual secret values" in prompt


class TestResolutionModels:
    """Tests for resolution data models."""

    def test_resolution_step_model(self):
        """Should create valid ResolutionStep."""
        step = ResolutionStep(
            order=1,
            description="Test step",
            command="ls -la",
            expected_output="files",
            is_safe=True,
            requires_confirmation=False,
        )

        assert step.order == 1
        assert step.description == "Test step"
        assert step.is_safe is True

    def test_resolution_response_model(self):
        """Should create valid ResolutionResponse."""
        response = ResolutionResponse(
            analysis="Test analysis",
            steps=[
                ResolutionStep(
                    order=1,
                    description="Test",
                    command="echo test",
                    is_safe=True,
                )
            ],
            confidence="high",
        )

        assert response.analysis == "Test analysis"
        assert len(response.steps) == 1
        assert response.confidence == "high"
