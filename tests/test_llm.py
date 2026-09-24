from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from llm import _VISION_CAPABLE, complete


def _resp(status: int, *, text: str = "", json_data=None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.reason = "Bad Request" if status >= 400 else "OK"
    r.text = text
    if json_data is not None:
        r.json.return_value = json_data
    else:
        r.json.side_effect = ValueError("no json")
    return r


def test_complete_retries_without_images_when_vision_model_returns_400():
    _VISION_CAPABLE["qwen3.6:27b"] = True
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "compare OCR", "images": ["ZmFrZQ=="]},
    ]
    vision_fail = _resp(400, text='{"error":"image payload too large"}')
    text_ok = _resp(200, json_data={"message": {"content": "compared via OCR"}})

    with patch("llm.OLLAMA_MODEL", "qwen3.6:27b"), patch(
        "llm.requests.post", side_effect=[vision_fail, text_ok]
    ) as post:
        out = complete(messages)

    assert out == "compared via OCR"
    assert post.call_count == 2
    first = post.call_args_list[0].kwargs["json"]["messages"][-1]
    second = post.call_args_list[1].kwargs["json"]["messages"][-1]
    assert "images" in first
    assert "images" not in second


def test_complete_surfaces_ollama_body_on_plain_400():
    _VISION_CAPABLE.clear()
    bad = _resp(400, text='{"error":"model requires more VRAM"}')
    with patch("llm.OLLAMA_MODEL", "qwen3.6:27b"), patch("llm.requests.post", return_value=bad):
        try:
            complete([{"role": "user", "content": "hi"}])
            assert False, "expected HTTPError"
        except requests.HTTPError as exc:
            assert "400" in str(exc)
            assert "VRAM" in str(exc)


if __name__ == "__main__":
    test_complete_retries_without_images_when_vision_model_returns_400()
    test_complete_surfaces_ollama_body_on_plain_400()
    print("LLM TESTS OK")
