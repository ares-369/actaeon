"""Google Gemini provider: one provider, every common way to connect.

``auth`` (default ``auto``):

  api_key         Google AI Studio key in ``GEMINI_API_KEY`` (or ``GOOGLE_API_KEY``)
  vertex          Vertex AI with Google application default credentials. That covers:
                  a service-account key file or a workload identity federation config
                  (``credentials_file`` or ``GOOGLE_APPLICATION_CREDENTIALS``), the identity
                  of the cloud VM or container it runs on, and ``gcloud auth
                  application-default login``. Needs ``project`` (or ``GOOGLE_CLOUD_PROJECT``).
  vertex_api_key  Vertex AI express mode with an API key in ``GEMINI_API_KEY``
  auto            api_key if a key is set and no project is set; vertex if a project is set

Other settings: ``location`` (default ``global``), ``base_url`` (send requests through an AI
gateway or proxy), ``headers`` (extra headers for that gateway, values may use ``${VAR}``),
``min_output_tokens`` (default 8192, since thinking models spend tokens before answering).
The SDK (``google-genai``) is only imported when this provider is used.
"""

from __future__ import annotations

import os
from typing import Any

from .base import ACTION_TOOLS, LLMProvider, LLMResult, Message, action_json, is_tool_loop_system

AUTH_MODES = ("auto", "api_key", "vertex", "vertex_api_key")


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self, cfg: dict[str, Any], secret: str = ""):
        super().__init__(cfg, secret)
        self.default_model = cfg.get("default_model") or "gemini-2.5-flash"
        self.secret = secret or os.getenv("GOOGLE_API_KEY", "")
        self.auth = str(cfg.get("auth", "auto"))
        self.project = str(cfg.get("project") or os.getenv("GOOGLE_CLOUD_PROJECT", "")).strip()
        self.location = str(cfg.get("location") or os.getenv("GOOGLE_CLOUD_LOCATION", "") or "global")
        self._client = None

    def mode(self) -> str:
        if self.auth != "auto":
            return self.auth
        return "vertex" if self.project else "api_key"

    def _make_client(self):
        from google import genai  # lazy
        from google.genai import types
        kw: dict[str, Any] = {}
        opts: dict[str, Any] = {}
        if self.cfg.get("base_url"):
            opts["base_url"] = str(self.cfg["base_url"])
        if self.cfg.get("headers"):
            from ..connectors.spec import expand_env
            opts["headers"] = {str(k): expand_env(str(v)) for k, v in self.cfg["headers"].items()}
        if self.cfg.get("timeout_sec"):
            opts["timeout"] = int(float(self.cfg["timeout_sec"]) * 1000)
        if opts:
            kw["http_options"] = types.HttpOptions(**opts)
        mode = self.mode()
        if mode not in AUTH_MODES:
            raise ValueError(f"gemini auth must be one of {AUTH_MODES}")
        if mode == "api_key":
            if not self.secret:
                raise ValueError("GEMINI_API_KEY is not set (auth: api_key)")
            return genai.Client(api_key=self.secret, **kw)
        if mode == "vertex_api_key":
            if not self.secret:
                raise ValueError("GEMINI_API_KEY is not set (auth: vertex_api_key)")
            return genai.Client(vertexai=True, api_key=self.secret, **kw)
        if not self.project:
            raise ValueError("Vertex AI needs a project: set llm.providers.gemini.project or GOOGLE_CLOUD_PROJECT")
        creds = None
        if self.cfg.get("credentials_file"):
            import google.auth
            creds, _ = google.auth.load_credentials_from_file(
                os.path.expanduser(str(self.cfg["credentials_file"])),
                scopes=["https://www.googleapis.com/auth/cloud-platform"])
        return genai.Client(vertexai=True, project=self.project, location=self.location, credentials=creds, **kw)

    def chat(self, messages: list[Message], *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        use_model = model or self.default_model
        try:
            from google.genai import types
            if self._client is None:
                self._client = self._make_client()
            system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
            contents = [types.Content(role="model" if m["role"] == "assistant" else "user",
                                      parts=[types.Part(text=m["content"])])
                        for m in messages if m["role"] != "system"]
            cfg_kw: dict[str, Any] = {
                "system_instruction": system or None, "temperature": temperature,
                "max_output_tokens": max(int(max_tokens), int(self.cfg.get("min_output_tokens", 8192))),
            }
            if hasattr(types, "SafetySetting"):
                default_thresh = "OFF" if self.mode() in ("vertex", "vertex_api_key") else "BLOCK_NONE"
                thresh = str(self.cfg.get("safety_threshold", default_thresh))
                cfg_kw["safety_settings"] = [
                    types.SafetySetting(category=c, threshold=thresh)
                    for c in ("HARM_CATEGORY_HATE_SPEECH", "HARM_CATEGORY_DANGEROUS_CONTENT",
                              "HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_SEXUALLY_EXPLICIT")
                ]
            native = is_tool_loop_system(system) and self.cfg.get("native_tools", True)
            if native:
                cfg_kw["tools"] = [types.Tool(function_declarations=[
                    types.FunctionDeclaration(**t) for t in ACTION_TOOLS
                ])]
            try:
                resp = self._client.models.generate_content(
                    model=use_model, contents=contents, config=types.GenerateContentConfig(**cfg_kw))
            except Exception:
                if not native:
                    raise
                cfg_kw.pop("tools", None)  # model without function calling: fall back to the JSON protocol
                resp = self._client.models.generate_content(
                    model=use_model, contents=contents, config=types.GenerateContentConfig(**cfg_kw))
            if native and "MALFORMED_FUNCTION_CALL" in str(_finish_reason(resp)):
                # The model produced a broken tool call: ask again without tools (JSON action protocol).
                cfg_kw.pop("tools", None)
                resp = self._client.models.generate_content(
                    model=use_model, contents=contents, config=types.GenerateContentConfig(**cfg_kw))
            fcs = getattr(resp, "function_calls", None) or []
            if fcs:
                fc = fcs[0]
                return LLMResult(
                    text=action_json(getattr(fc, "name", ""), dict(getattr(fc, "args", None) or {})),
                    model=use_model,
                )
            text = (resp.text or "").strip()
            if not text:
                fb = getattr(getattr(resp, "prompt_feedback", None), "block_reason", None)
                cands = getattr(resp, "candidates", None) or []
                fr = getattr(cands[0], "finish_reason", None) if cands else None
                why = f"block_reason={fb}" if fb else f"finish_reason={fr}" if fr else "empty response"
                return LLMResult(text="", model=use_model,
                                 error=f"Gemini returned no text ({why}); raise min_output_tokens if MAX_TOKENS")
            return LLMResult(text=text, model=use_model)
        except ImportError:
            return LLMResult(text="", model=use_model, error="the gemini extra is not installed: "
                                                             "pip install 'actaeon[gemini]'")
        except Exception as exc:
            return LLMResult(text="", model=use_model, error=f"Gemini error ({self.mode()}): {exc}")

    def health(self) -> bool:
        return bool(self.secret) or bool(self.project)


def _finish_reason(resp) -> object:
    cands = getattr(resp, "candidates", None) or []
    return getattr(cands[0], "finish_reason", None) if cands else None
