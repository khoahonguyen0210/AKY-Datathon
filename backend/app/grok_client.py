"""Optional narrative rewrite through the xAI Grok API.

The evidence ledger is never taken from the model. Grok may only rewrite
the summary, and the rewrite is kept when it cites real event ids and
avoids attack procedure.
"""

import os
import re

import httpx

class GrokUnavailable(Exception):
    """No API key is configured."""


class GrokError(Exception):
    """The API call failed or returned something unusable."""


_BANNED = (
    "mimikatz",
    "meterpreter",
    "shellcode",
    "pass-the-hash",
    "psexec",
    "powershell -enc",
    "invoke-expression",
    "cmd.exe /c",
    "proof of concept",
    "step-by-step",
    "reproduce the attack",
    "to exploit",
)

_SYSTEM = """You rewrite incident summaries for SENTINEL, a defensive investigation tool.
Use only the facts in the user message.
Cite event ids exactly as given, in the form they already appear.
Do not add event ids that were not provided.
Do not describe commands, malware, exploit procedures, or how to repeat activity.
Do not invent vulnerabilities or a root cause beyond the supplied root-cause sentence.
Keep two short paragraphs of plain prose. No headings and no bullet list.
"""


def rewrite_summary(local_summary: str, allowed_ids: set[str]) -> str:
    key = os.environ.get("XAI_API_KEY", "").strip()
    if not key:
        raise GrokUnavailable()
    model = os.environ.get("SENTINEL_GROK_MODEL", "grok-4.7").strip() or "grok-4.7"
    cited = ", ".join(sorted(allowed_ids))
    user = (
        "Rewrite this summary. You must mention at least one of these event ids verbatim: "
        f"{cited}.\n\n{local_summary}"
    )
    try:
        response = httpx.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "temperature": 0.2,
                "max_tokens": 500,
                "messages": [
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": user},
                ],
            },
            timeout=30.0,
        )
    except httpx.HTTPError as exc:
        raise GrokError("Grok request failed") from exc
    if response.status_code >= 400:
        raise GrokError(f"Grok returned HTTP {response.status_code}")
    try:
        payload = response.json()
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise GrokError("Grok returned an unexpected body") from exc
    text = _flatten(content)
    if not summary_is_usable(text, allowed_ids):
        raise GrokError("Grok summary failed the evidence check")
    return text


def summary_is_usable(text: str, allowed_ids: set[str]) -> bool:
    cleaned = _strip_fence(text).strip()
    if len(cleaned) < 40 or len(cleaned) > 3500:
        return False
    lowered = cleaned.lower()
    if any(term in lowered for term in _BANNED):
        return False
    known = {event_id.lower() for event_id in allowed_ids}
    for token in re.findall(r"\be\d+\b", cleaned, flags=re.IGNORECASE):
        if token.lower() not in known:
            return False
    return any(event_id in cleaned for event_id in allowed_ids)


def _flatten(content: object) -> str:
    if isinstance(content, str):
        return _strip_fence(content)
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return _strip_fence("\n".join(parts))
    return ""


def _strip_fence(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned)
    return cleaned.strip()
