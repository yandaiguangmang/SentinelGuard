"""
LLM Client Wrapper
Supports: OpenAI (GPT-4o, GPT-4o-mini), Google Gemini, any OpenAI-compatible endpoint.
"""

import os
import json
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class LLMClient:
    """
    Unified LLM client. Selects backend based on `model` prefix or explicit `provider`.

    Supported providers:
      - "openai"  : GPT-4o, GPT-4o-mini, etc.  Requires OPENAI_API_KEY.
      - "gemini"  : Gemini-2.0-flash, etc.      Requires GOOGLE_API_KEY.
      - "openai_compatible": Any OpenAI-compatible endpoint (e.g. Together, Ollama).
                              Requires OPENAI_COMPATIBLE_BASE_URL + OPENAI_COMPATIBLE_API_KEY.
    """

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        provider: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        max_retries: int = 3,
        retry_delay: float = 2.0,
    ):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # Auto-detect provider
        if provider:
            self.provider = provider
        elif model.startswith("gemini"):
            self.provider = "gemini"
        elif "gpt" in model or "o1" in model or "o3" in model:
            self.provider = "openai"
        else:
            self.provider = "openai_compatible"

        self._setup_client()

    def _setup_client(self):
        if self.provider == "openai":
            try:
                from openai import OpenAI
                api_key = os.getenv("OPENAI_API_KEY")
                if not api_key:
                    raise ValueError("OPENAI_API_KEY environment variable not set.")
                self.client = OpenAI(api_key=api_key)
            except ImportError:
                raise ImportError("Install openai: pip install openai")

        elif self.provider == "gemini":
            try:
                import google.generativeai as genai
                api_key = os.getenv("GOOGLE_API_KEY")
                if not api_key:
                    raise ValueError("GOOGLE_API_KEY environment variable not set.")
                genai.configure(api_key=api_key)
                self.client = genai.GenerativeModel(self.model)
            except ImportError:
                raise ImportError("Install google-generativeai: pip install google-generativeai")

        elif self.provider == "openai_compatible":
            try:
                from openai import OpenAI
                base_url = os.getenv(
                    "OPENAI_COMPATIBLE_BASE_URL", "http://localhost:11434/v1"
                )
                api_key = os.getenv("OPENAI_COMPATIBLE_API_KEY", "ollama")
                self.client = OpenAI(base_url=base_url, api_key=api_key)
            except ImportError:
                raise ImportError("Install openai: pip install openai")

    def chat(self, system: str, user: str) -> str:
        """Send a chat completion request and return the response text."""
        for attempt in range(self.max_retries):
            try:
                return self._do_chat(system, user)
            except Exception as e:
                if attempt < self.max_retries - 1:
                    wait = self.retry_delay * (2 ** attempt)
                    logger.warning(f"LLM call failed (attempt {attempt+1}): {e}. Retrying in {wait}s…")
                    time.sleep(wait)
                else:
                    logger.error(f"LLM call failed after {self.max_retries} attempts: {e}")
                    raise

    def _do_chat(self, system: str, user: str) -> str:
        if self.provider in ("openai", "openai_compatible"):
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return resp.choices[0].message.content.strip()

        elif self.provider == "gemini":
            combined = f"System: {system}\n\nUser: {user}"
            resp = self.client.generate_content(
                combined,
                generation_config={
                    "temperature": self.temperature,
                    "max_output_tokens": self.max_tokens,
                },
            )
            return resp.text.strip()

        raise ValueError(f"Unknown provider: {self.provider}")

    def parse_json(self, text: str) -> dict:
        """Parse JSON from LLM output, stripping markdown fences if present."""
        # Strip ```json ... ``` fences
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON object
            import re
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                return json.loads(match.group())
            logger.warning(f"Failed to parse JSON from: {text[:200]}")
            return {}
