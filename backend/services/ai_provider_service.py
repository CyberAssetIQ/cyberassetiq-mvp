import os, time, logging
logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY      = os.getenv("GROQ_API_KEY", "")
AI_PROVIDER       = os.getenv("AI_PROVIDER", "groq").lower()
AI_MODEL          = os.getenv("AI_MODEL", "claude-sonnet-4-6")
AI_MODEL_FALLBACK = os.getenv("AI_MODEL_FALLBACK", "gpt-4o")
AI_GEMINI_MODEL   = os.getenv("AI_GEMINI_MODEL", "gemini-2.0-flash")
GROQ_MODEL        = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
AI_MAX_TOKENS     = int(os.getenv("AI_MAX_TOKENS", "2048"))

# Fallback chain — Groq first (free, 14,400 req/day)
# Groq > Gemini > Anthropic > OpenAI
FALLBACK_CHAIN = []
if GROQ_API_KEY:      FALLBACK_CHAIN.append("groq")
if GEMINI_API_KEY:    FALLBACK_CHAIN.append("gemini")
if ANTHROPIC_API_KEY: FALLBACK_CHAIN.append("anthropic")
if OPENAI_API_KEY:    FALLBACK_CHAIN.append("openai")


class LLMResponse:
    def __init__(self, content, model, prompt_tokens, completion_tokens, latency_ms):
        self.content = content
        self.model = model
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = prompt_tokens + completion_tokens
        self.latency_ms = latency_ms


class AIProviderService:

    def call(self, system_prompt: str, user_message: str,
             max_tokens: int = AI_MAX_TOKENS, prefer: str = None) -> LLMResponse:
        preferred = (prefer or AI_PROVIDER).lower()
        chain = [preferred] + [p for p in FALLBACK_CHAIN if p != preferred]
        last_error = None
        for provider in chain:
            try:
                if provider == "groq" and GROQ_API_KEY:
                    return self._call_groq(system_prompt, user_message, max_tokens)
                elif provider == "gemini" and GEMINI_API_KEY:
                    return self._call_gemini(system_prompt, user_message, max_tokens)
                elif provider == "anthropic" and ANTHROPIC_API_KEY:
                    return self._call_anthropic(system_prompt, user_message, max_tokens)
                elif provider == "openai" and OPENAI_API_KEY:
                    return self._call_openai(system_prompt, user_message, max_tokens)
            except Exception as e:
                last_error = e
                logger.warning("Provider %s failed: %s — trying next",
                               provider, str(e)[:120])
                continue
        raise RuntimeError(
            f"All AI providers failed or not configured. Last error: {last_error}. "
            f"Add at least one of: GROQ_API_KEY, GEMINI_API_KEY, "
            f"ANTHROPIC_API_KEY, or OPENAI_API_KEY to your .env file."
        )

    def _call_groq(self, system_prompt, user_message, max_tokens):
        import openai as _o
        client = _o.OpenAI(
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1",
        )
        t0 = time.time()
        r = client.chat.completions.create(
            model=GROQ_MODEL, max_tokens=max_tokens,
            messages=[{"role":"system","content":system_prompt},
                      {"role":"user","content":user_message}],
        )
        c = r.choices[0]
        return LLMResponse(c.message.content or "", r.model,
                           r.usage.prompt_tokens, r.usage.completion_tokens,
                           int((time.time()-t0)*1000))

    def _call_gemini(self, system_prompt, user_message, max_tokens):
        from google import genai
        from google.genai import types
        client = genai.Client(api_key=GEMINI_API_KEY)
        t0 = time.time()
        r = client.models.generate_content(
            model=AI_GEMINI_MODEL,
            contents=user_message,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                max_output_tokens=max_tokens,
            ),
        )
        content = r.text if hasattr(r, "text") else ""
        pt = getattr(r.usage_metadata, "prompt_token_count", 0) or 0
        ct = getattr(r.usage_metadata, "candidates_token_count", 0) or 0
        return LLMResponse(content, AI_GEMINI_MODEL, pt, ct,
                           int((time.time()-t0)*1000))

    def _call_anthropic(self, system_prompt, user_message, max_tokens):
        import anthropic as _a
        client = _a.Anthropic(api_key=ANTHROPIC_API_KEY)
        t0 = time.time()
        r = client.messages.create(
            model=AI_MODEL if "claude" in AI_MODEL else "claude-sonnet-4-6",
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        content = "".join(b.text for b in r.content if hasattr(b, "text"))
        return LLMResponse(content, r.model,
                           r.usage.input_tokens, r.usage.output_tokens,
                           int((time.time()-t0)*1000))

    def _call_openai(self, system_prompt, user_message, max_tokens):
        import openai as _o
        client = _o.OpenAI(api_key=OPENAI_API_KEY)
        model = AI_MODEL_FALLBACK if "claude" in AI_MODEL else AI_MODEL
        t0 = time.time()
        r = client.chat.completions.create(
            model=model, max_tokens=max_tokens,
            messages=[{"role":"system","content":system_prompt},
                      {"role":"user","content":user_message}],
        )
        c = r.choices[0]
        return LLMResponse(c.message.content or "", r.model,
                           r.usage.prompt_tokens, r.usage.completion_tokens,
                           int((time.time()-t0)*1000))

    @staticmethod
    def is_configured() -> bool:
        return any([GROQ_API_KEY, GEMINI_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY])

    @staticmethod
    def groq_available() -> bool: return bool(GROQ_API_KEY)

    @staticmethod
    def gemini_available() -> bool: return bool(GEMINI_API_KEY)

    @staticmethod
    def anthropic_available() -> bool: return bool(ANTHROPIC_API_KEY)

    @staticmethod
    def openai_available() -> bool: return bool(OPENAI_API_KEY)

    @staticmethod
    def provider_name() -> str:
        if GROQ_API_KEY:      return "groq"
        if GEMINI_API_KEY:    return "gemini"
        if ANTHROPIC_API_KEY: return "anthropic"
        if OPENAI_API_KEY:    return "openai"
        return "none"

    @staticmethod
    def model_name() -> str: return GROQ_MODEL if GROQ_API_KEY else AI_MODEL

    def available_providers(self) -> list:
        providers = []
        if GROQ_API_KEY:      providers.append("groq")
        if GEMINI_API_KEY:    providers.append("gemini")
        if ANTHROPIC_API_KEY: providers.append("anthropic")
        if OPENAI_API_KEY:    providers.append("openai")
        return providers
