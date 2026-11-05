#!/usr/bin/env python3
"""
Diagnose the Gemini connection.

    python check_gemini.py

1. Lists the models your GEMINI_API_KEY can use.
2. Sends a tiny test request to each "flash" model and shows the result,
   including Google's own error message if one fails.
"""

import json
import urllib.error
import urllib.request

from threat_intel import load_keys

BASE = "https://generativelanguage.googleapis.com/v1beta"


def call(url, key, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json", "x-goog-api-key": key})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def error_text(e: urllib.error.HTTPError) -> str:
    try:
        return json.loads(e.read().decode()).get("error", {}).get("message", "")[:200]
    except Exception:
        return ""


def main():
    key = load_keys().get("GEMINI_API_KEY")
    if not key:
        raise SystemExit("No GEMINI_API_KEY found in .env")

    try:
        models = call(f"{BASE}/models?pageSize=200", key).get("models", [])
    except urllib.error.HTTPError as e:
        raise SystemExit(f"Could not list models: HTTP {e.code} {error_text(e)}")

    usable = [m["name"].removeprefix("models/") for m in models
              if "generateContent" in m.get("supportedGenerationMethods", [])]
    print(f"Your key can use {len(usable)} models. Flash models:")
    flash = [m for m in usable if "flash" in m]
    for m in flash:
        print("  ", m)

    print("\nTesting each flash model with a tiny request...")
    body = {"contents": [{"parts": [{"text": "Reply with the single word: OK"}]}]}
    for m in flash[:8]:
        try:
            r = call(f"{BASE}/models/{m}:generateContent", key, body)
            text = r["candidates"][0]["content"]["parts"][0]["text"].strip()
            print(f"  WORKS  {m}  -> {text[:20]}")
        except urllib.error.HTTPError as e:
            print(f"  HTTP {e.code}  {m}  {error_text(e)}")
        except Exception as e:
            print(f"  ERROR  {m}  {type(e).__name__}")

    print("\nPick a model marked WORKS and add it to .env, e.g.:\n  GEMINI_MODEL=<model name>")


if __name__ == "__main__":
    main()
