"""
Zero-dependency, offline-first LLM completions client using Python standard library.
Supports Ollama, LM Studio, llama.cpp, OpenAI, and Gemini APIs.
"""
import json
import urllib.request
import urllib.error
import hashlib
import threading
from pathlib import Path
import config
from utils.logger import get_logger

logger = get_logger("LLMClient")

# Persistent cache configuration
CACHE_FILE = Path(__file__).resolve().parent / "llm_cache.json"
_cache = {}
try:
    if CACHE_FILE.exists():
        _cache = json.loads(CACHE_FILE.read_text(encoding="utf-8-sig"))
except Exception as e:
    logger.warning(f"Failed to load LLM cache: {e}")


class LLMClient:
    def __init__(self):
        self.provider = getattr(config, "LLM_PROVIDER", "ollama").lower()
        self.model = getattr(config, "LLM_MODEL", "qwen2.5-coder:1.5b")
        self.api_key = getattr(config, "LLM_API_KEY", "")
        self.custom_url = getattr(config, "LLM_API_URL", "")
        self._request_lock = threading.Lock()
        self._disabled_reason = ""
        
        # Determine target API Endpoint
        self.api_url = self._get_endpoint()
        logger.info(f"Initialized LLMClient (Provider: {self.provider.upper()}, Model: {self.model})")

    def reset_scan_state(self) -> None:
        """Allow a fresh availability check at the beginning of each scan."""
        with self._request_lock:
            self._disabled_reason = ""

    def _get_endpoint(self) -> str:
        """Resolve API completions endpoint based on provider config."""
        if self.custom_url:
            if self.provider == "ollama":
                url = self.custom_url.rstrip("/")
                # Accept an Ollama host/root URL or its explicit chat endpoint.
                # Posting to the server root produces a misleading HTTP 404.
                if not url.endswith("/api/chat"):
                    return f"{url}/api/chat"
            return self.custom_url
            
        if self.provider == "ollama":
            return "http://localhost:11434/api/chat"
        elif self.provider == "lmstudio":
            return "http://localhost:1234/v1/chat/completions"
        elif self.provider == "openai":
            return "https://api.openai.com/v1/chat/completions"
        elif self.provider == "nvidia":
            return "https://integrate.api.nvidia.com/v1/chat/completions"
        elif self.provider == "gemini":
            return "https://generativelanguage.googleapis.com/v1beta/openai/v1/chat/completions"
        return ""

    def clear_cache(self) -> int:
        """Clear in-memory and persistent LLM response cache."""
        global _cache
        with self._request_lock:
            count = len(_cache)
            _cache = {}
            try:
                CACHE_FILE.write_text("{}", encoding="utf-8")
            except Exception as e:
                logger.warning(f"Failed to reset cache file: {e}")
            logger.info(f"Cleared {count} entries from LLM cache")
            return count

    def generate_completion(self, system_prompt: str, user_prompt: str, temperature: float = 0.2, context_key: str = "") -> str:
        """
        Request chat completions from the LLM provider.
        Returns the generated assistant text response, or an empty string if failed.
        """
        if self.provider == "none" or not self.api_url:
            logger.debug("LLM provider is set to 'none' or URL is empty. Skipping generative pass.")
            return ""

        # The RAG stage can request several enrichments concurrently.  Once a
        # local service is known to be unavailable, do not issue identical
        # failing requests for every finding in the same scan.
        if self._disabled_reason:
            import time
            if hasattr(self, '_disabled_time') and time.time() - self._disabled_time > 300:
                self.reset_scan_state()
            else:
                logger.debug(f"LLM disabled for this scan: {self._disabled_reason}")
                return ""

        # Check Cache (isolated per app context if provided)
        key_str = f"{self.provider}:{self.model}:{context_key}:{system_prompt}:{user_prompt}"
        cache_key = hashlib.md5(key_str.encode("utf-8")).hexdigest()
        
        with self._request_lock:
            if cache_key in _cache:
                logger.info(f"LLM cache hit [OK] (Context: {context_key or 'global'})")
                return _cache[cache_key]

        # Formulate payload based on provider
        if self.provider == "ollama":
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "options": {
                    "temperature": temperature,
                    "num_predict": 256,
                    # Auto-offload to NVIDIA GPU when available
                    "num_gpu": 0 if getattr(config, "LLM_FORCE_CPU", False) else -1,
                },
                "stream": False,
                "keep_alive": "30m"
            }
        elif self.provider == "gemini":
            # Determine the actual URL first — this affects payload format
            api_url_gemini = self.api_url
            if self.api_key:
                # Use native Gemini generateContent endpoint when API key is available
                api_url_gemini = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

            if "generateContent" in api_url_gemini:
                # Native Gemini API structure for generateContent endpoint
                payload = {
                    "contents": [{
                        "parts": [{"text": f"System Instructions:\n{system_prompt}\n\nTask:\n{user_prompt}"}]
                    }],
                    "generationConfig": {
                        "temperature": temperature,
                        "maxOutputTokens": 1000
                    }
                }
            else:
                # OpenAI-compatible format for /openai/v1/chat/completions endpoint
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": temperature,
                    "max_tokens": 1000
                }
        else:
            # Standard OpenAI-compatible payload (LM Studio, OpenAI, NVIDIA, etc.)
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": temperature,
                "max_tokens": 1000
            }

        # Build request headers and URL
        headers = {"Content-Type": "application/json"}
        api_url = api_url_gemini if self.provider == "gemini" else self.api_url
        if self.provider in ("openai", "nvidia") and self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        data = json.dumps(payload).encode("utf-8")

        # Determine timeout and retry strategy
        # Ollama on CPU: ~3.7 tok/s, 400 tokens ≈ 108s + cold-start loading
        timeout_val = 300 if self.provider == "ollama" else 60
        max_attempts = 3  # Multiple attempts to allow recovery on rate limits

        # Serialize local-model requests; this also makes the circuit breaker
        # deterministic when the enrichment stage uses a thread pool.
        with self._request_lock:
            if self._disabled_reason:
                return ""
            # Double-check cache under lock to avoid duplicate API calls
            if cache_key in _cache:
                return _cache[cache_key]
            for attempt in range(max_attempts):
                try:
                    # Resolve request
                    req = urllib.request.Request(api_url, data=data, headers=headers, method="POST")

                    # Free-tier rate limiting for Gemini (15 RPM limits)
                    if self.provider == "gemini":
                        import time
                        time.sleep(3)

                    with urllib.request.urlopen(req, timeout=timeout_val) as response:
                        res_data = response.read().decode("utf-8")
                        res_json = json.loads(res_data)

                        content = ""
                        # Parse response based on provider format
                        if self.provider == "ollama":
                            msg = res_json.get("message", {})
                            content = msg.get("content", "")
                            # Fallback: if thinking mode consumed all tokens and
                            # content is empty, extract from the thinking field
                            if not content.strip() and msg.get("thinking"):
                                thinking_text = msg["thinking"]
                                logger.info("Content empty, extracting from thinking field")
                                content = thinking_text
                        elif self.provider == "gemini":
                            if "generateContent" in api_url:
                                # Native Gemini response format
                                candidates = res_json.get("candidates", [])
                                if candidates:
                                    parts = candidates[0].get("content", {}).get("parts", [])
                                    if parts:
                                        content = parts[0].get("text", "")
                            else:
                                # OpenAI-compatible response format
                                choices = res_json.get("choices", [])
                                if choices:
                                    content = choices[0].get("message", {}).get("content", "")
                        else:
                            # Parse standard chat completions content
                            choices = res_json.get("choices", [])
                            if choices:
                                content = choices[0].get("message", {}).get("content", "")

                        if content:
                            clean_content = content.strip()
                            # Save to cache
                            _cache[cache_key] = clean_content
                            try:
                                CACHE_FILE.write_text(json.dumps(_cache, indent=2, ensure_ascii=False), encoding="utf-8")
                            except Exception as e:
                                logger.warning(f"Failed to save LLM cache to disk: {e}")
                            return clean_content

                        logger.warning(f"Malformed LLM API response: {res_data[:200]}")
                        return ""
                except urllib.error.HTTPError as e:
                    # Ollama uses 404 for both an invalid route and a model
                    # that is not installed. Preserve its response for an
                    # actionable log message instead of hiding the cause.
                    response_text = ""
                    try:
                        response_text = e.read().decode("utf-8", errors="replace")[:300]
                    except Exception:
                        pass
                    if e.code in (429, 503) and attempt < (max_attempts - 1):
                        import time
                        wait_time = 3 * (attempt + 1)
                        logger.warning(f"LLM rate limited ({e.code}). Retrying in {wait_time}s... (Attempt {attempt+1}/{max_attempts})")
                        time.sleep(wait_time)
                        continue
                    detail = response_text or e.reason or "No error details returned"
                    self._disabled_reason = f"HTTP {e.code} from {self.api_url}: {detail}"
                    self._disabled_time = time.time()
                    logger.warning(f"LLM unavailable ({self.provider.upper()}): {self._disabled_reason}. Using IR templates for the rest of this scan.")
                    break
                except urllib.error.URLError as e:
                    self._disabled_reason = str(e.reason)
                    self._disabled_time = time.time()
                    logger.warning(f"LLM unavailable ({self.provider.upper()}): {self._disabled_reason}. Using IR templates for the rest of this scan.")
                    break
                except Exception as e:
                    self._disabled_reason = str(e)
                    self._disabled_time = time.time()
                    logger.error(f"Unexpected LLM error; disabling it for this scan: {e}")
                    break

        return ""
