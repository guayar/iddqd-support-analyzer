from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from PIL import Image

from chats import assistant_chat, normalize_user_message, web_chat
from vision import SCOPE_ASSISTANT, SCOPE_GENERAL_CHAT, VisionError, attach_images, clear_vision_cache, inspect_image


def _png(path: Path, size=(24, 16), color=(255, 255, 255)) -> Path:
    Image.new("RGB", size, color).save(path, format="PNG")
    return path


def test_normalize_string_and_multimodal_dict():
    assert normalize_user_message("hello") == ("hello", [])
    text, paths = normalize_user_message({"text": "read this", "files": [{"path": "/tmp/x.png"}]})
    assert text == "read this"
    assert paths == ["/tmp/x.png"]


def test_rejects_non_image(tmp_path):
    bogus = tmp_path / "notes.txt"
    bogus.write_text("not an image", encoding="utf-8")
    try:
        inspect_image(str(bogus))
        assert False, "expected VisionError"
    except VisionError as exc:
        assert "readable" in str(exc) or "unsupported" in str(exc)


def test_rejects_remote_urls():
    try:
        inspect_image("https://example.com/shot.png")
        assert False, "expected VisionError"
    except VisionError as exc:
        assert "Remote" in str(exc)


def test_accepts_png_and_caps_count(tmp_path):
    clear_vision_cache()
    files = [_png(tmp_path / f"{i}.png") for i in range(4)]
    with patch("vision.ocr_image", side_effect=lambda p, scope=None: {**inspect_image(p), "text": "ERROR 500", "error": None}):
        attachments, notes = attach_images([str(p) for p in files])
    assert len(attachments) == 3
    assert attachments[0]["ocr_text"] == "ERROR 500"
    assert any("3" in n for n in notes)


def test_ocr_failure_still_attaches(tmp_path):
    clear_vision_cache()
    path = str(_png(tmp_path / "ok.png"))
    with patch("vision.ocr_image", side_effect=lambda p, scope=None: {**inspect_image(p), "text": "", "error": "Tesseract is not installed locally."}):
        attachments, notes = attach_images([path])
    assert len(attachments) == 1
    assert attachments[0]["ocr_error"]


def test_assistant_sends_image_and_ocr_and_keeps_web_chat_isolated(tmp_path):
    clear_vision_cache()
    path = str(_png(tmp_path / "term.png"))
    captured: list[list[dict]] = []

    def fake_complete(messages, temperature=0.2):
        captured.append(messages)
        return "seen"

    with patch("chats.complete", fake_complete), patch(
        "vision.ocr_image",
        side_effect=lambda p, scope=SCOPE_ASSISTANT: {**inspect_image(p), "text": "INVALID_ISSUER", "error": None},
    ), patch("vision.encode_image_png_base64", return_value="ZmFrZQ=="):
        out = assistant_chat({"text": "What failed?", "files": [{"path": path}]}, [], {"kind": "saml"})
    assert out == "seen"
    user = captured[0][-1]
    assert user["role"] == "user"
    assert "INVALID_ISSUER" in user["content"]
    assert "LOCAL OCR EXTRACT" in user["content"]
    assert user["images"] == ["ZmFrZQ=="]
    assert "ANALYZER OUTPUT" in captured[0][0]["content"]

    product = str(_png(tmp_path / "product.png", color=(10, 20, 30)))
    search_plans: list[tuple[str, bool]] = []
    executed: list[list[str]] = []
    web_captured: list = []

    def fake_plan(message, history, has_images=False):
        search_plans.append((message, has_images))
        return ["Pearl Export current price"]

    def fake_execute(queries):
        executed.append(queries)
        return ([], queries, "auto")

    def fake_web_complete(messages, temperature=0.2):
        web_captured.append(messages)
        return "web-ok"

    with patch("chats.complete", fake_web_complete), patch(
        "websearch.plan_web_search",
        fake_plan,
    ), patch(
        "websearch.execute_web_search",
        fake_execute,
    ), patch(
        "vision.ocr_image",
        side_effect=lambda p, scope=SCOPE_GENERAL_CHAT: {**inspect_image(p), "text": "INVALID_ISSUER customer123", "error": None},
    ), patch("vision.encode_image_png_base64", return_value="cHJvZA=="):
        web_chat({"text": "ile to kosztuje?", "files": [{"path": product}]}, [])
    assert search_plans == [("ile to kosztuje?", True)]
    assert executed == [["Pearl Export current price"]]
    assert all("INVALID_ISSUER" not in p[0] for p in search_plans)
    sent = web_captured[0]
    assert all("ANALYZER OUTPUT" not in str(m.get("content")) for m in sent)
    user = [m for m in sent if m.get("role") == "user"][-1]
    assert user["images"] == ["cHJvZA=="]
    assert "INVALID_ISSUER" in user["content"]


def test_general_chat_skips_search_for_what_is_this_photo(tmp_path):
    path = str(_png(tmp_path / "drums.png"))
    planned = []
    executed = []

    def fake_plan(message, history, has_images=False):
        planned.append((message, has_images))
        return []

    def fake_execute(queries):
        executed.append(queries)
        return ([], queries, "auto")

    with patch("chats.complete", return_value="perkusja"), patch(
        "websearch.plan_web_search",
        fake_plan,
    ), patch(
        "websearch.execute_web_search",
        fake_execute,
    ), patch(
        "vision.ocr_image",
        side_effect=lambda p, scope=SCOPE_GENERAL_CHAT: {
            **inspect_image(p),
            "text": "OS ZA h WA AA OTSA LT RPA",
            "error": None,
        },
    ), patch("vision.encode_image_png_base64", return_value="ZHJ1bQ=="):
        out = web_chat({"text": "co to jest?", "files": [{"path": path}]}, [])
    assert out == "perkusja"
    assert planned == [("co to jest?", True)]
    assert executed == []
    assert "Web sources used by this chat" not in out


def test_attach_scopes_are_separate(tmp_path):
    path = str(_png(tmp_path / "shared.png"))
    scopes: list[str] = []

    def fake_ocr(p, scope=SCOPE_ASSISTANT):
        scopes.append(scope)
        return {**inspect_image(p), "text": scope, "error": None}

    with patch("vision.ocr_image", fake_ocr):
        a, _ = attach_images([path], scope=SCOPE_ASSISTANT)
        g, _ = attach_images([path], scope=SCOPE_GENERAL_CHAT)
    assert scopes == [SCOPE_ASSISTANT, SCOPE_GENERAL_CHAT]
    assert a[0]["ocr_text"] == SCOPE_ASSISTANT
    assert g[0]["ocr_text"] == SCOPE_GENERAL_CHAT


def test_follow_up_resends_previous_screenshot(tmp_path):
    path = str(_png(tmp_path / "prev.png"))
    captured: list = []

    def fake_complete(messages, temperature=0.2):
        captured.append(messages)
        return "follow"

    history = [{"role": "user", "content": [{"path": path}, "What caused this?"]}, {"role": "assistant", "content": "A timeout."}]
    with patch("chats.complete", fake_complete), patch(
        "vision.ocr_image",
        side_effect=lambda p, scope=None: {**inspect_image(p), "text": "ORA-12514", "error": None},
    ), patch("vision.encode_image_png_base64", return_value="cHJldg=="):
        assistant_chat("Look at the third line again.", history)
    user = captured[0][-1]
    assert user["images"] == ["cHJldg=="]
    assert "ORA-12514" in user["content"]


if __name__ == "__main__":
    from pathlib import Path as P
    import tempfile

    test_normalize_string_and_multimodal_dict()
    test_rejects_remote_urls()
    with tempfile.TemporaryDirectory() as d:
        td = P(d)
        test_rejects_non_image(td)
        test_accepts_png_and_caps_count(td)
        test_ocr_failure_still_attaches(td)
        test_assistant_sends_image_and_ocr_and_keeps_web_chat_isolated(td)
        test_general_chat_skips_search_for_what_is_this_photo(td)
        test_follow_up_resends_previous_screenshot(td)
        test_attach_scopes_are_separate(td)
    print("VISION TESTS OK")
