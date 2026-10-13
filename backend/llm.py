"""One place for calls to the AkashML model, so every caller gets the same safeguards.

The model reasons before it answers, and that reasoning is billed against
max_tokens. With a small budget the reasoning can use all of it and leave an empty
or cut-off reply, so the budget here is generous, and a reply that still comes back
unusable is retried once with reasoning switched off.
"""
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(base_url=os.getenv("AKASHML_BASE_URL"), api_key=os.getenv("AKASHML_API_KEY"),
                timeout=60, max_retries=1)
MODEL = os.getenv("AKASHML_MODEL")

MAX_TOKENS = 4000
NO_REASONING = {"chat_template_kwargs": {"enable_thinking": False}}


def first_json(text: str):
    """The first JSON object in the text, or None."""
    start = (text or "").find("{")
    if start == -1:
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def _complete(messages, extra_body=None):
    r = client.chat.completions.create(model=MODEL, messages=messages, temperature=0,
                                       max_tokens=MAX_TOKENS, extra_body=extra_body)
    choice = r.choices[0]
    return choice.message.content or "", choice.finish_reason


def ask_json(messages, tag: str, required=()):
    """Return the model's reply as a dict, or None if two attempts both failed.

    `required` lists keys the reply must contain to count as usable.
    """
    for attempt, extra_body in enumerate((None, NO_REASONING), 1):
        try:
            text, finish = _complete(messages, extra_body)
        except Exception as e:
            print(f"[{tag}] WARNING: model call failed (attempt {attempt}): {e!r}", flush=True)
            continue
        data = first_json(text)
        if data is not None and all(key in data for key in required):
            return data
        print(f"[{tag}] WARNING: unusable reply (attempt {attempt}, finish_reason={finish}, "
              f"{len(text)} chars)", flush=True)
    return None
