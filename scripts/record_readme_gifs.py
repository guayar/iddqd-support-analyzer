#!/usr/bin/env python3
"""Record README Analyze demo GIFs from a live Gradio UI. Writes PNGs + GIFs; does not print image bytes."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PORT = int(os.environ.get("DEMO_PORT", "7870"))
BASE = f"http://127.0.0.1:{PORT}"
OUT = Path(os.environ.get("DEMO_OUT", "/tmp/iddqd-demo"))
ASSETS = Path(os.environ.get("DEMO_ASSETS", str(ROOT / "docs" / "assets")))
WIDTH = 1280
HEIGHT = 900
GIF_WIDTH = 1100

SAML_PASTE = (
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" '
    'IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.example/sso" '
    'AssertionConsumerServiceURL="https://sp.example/acs" '
    'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
    "<saml:Issuer>https://sp.example/entity</saml:Issuer></samlp:AuthnRequest>\n\n"
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
    'InResponseTo="_req1" Destination="https://sp.example/wrong-acs" '
    'IssueInstant="2026-09-07T08:00:01Z">'
    "<saml:Issuer>https://idp.example/entity</saml:Issuer>"
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">'
    "<saml:Issuer>https://idp.example/entity</saml:Issuer>"
    "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">alice@example.com</saml:NameID>"
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
    '<saml:SubjectConfirmationData Recipient="https://sp.example/wrong-recipient" InResponseTo="_req1" '
    'NotOnOrAfter="2099-09-07T08:05:00Z"/></saml:SubjectConfirmation></saml:Subject>'
    '<saml:Conditions NotBefore="2026-09-07T07:59:00Z" NotOnOrAfter="2099-09-07T08:05:00Z">'
    "<saml:AudienceRestriction><saml:Audience>https://wrong.example/entity</saml:Audience></saml:AudienceRestriction>"
    "</saml:Conditions></saml:Assertion></samlp:Response>\n"
)

SP_METADATA = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example/entity">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="false">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example/acs" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""

IDP_METADATA = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""

SSH_PASTE = """Dec 24 06:55:46 box sshd[3321]: reverse mapping checking getaddrinfo for ns.example.com [198.51.100.44] failed - POSSIBLE BREAK-IN ATTEMPT!
Dec 24 06:55:48 box sshd[3321]: Failed password for invalid user webmaster from 198.51.100.44 port 38926 ssh2
Dec 24 07:13:50 box sshd[4401]: Failed password for root from 198.51.100.44 port 22 ssh2
Dec 24 07:13:51 box sshd[4402]: Failed password for root from 198.51.100.44 port 22 ssh2
Dec 24 07:13:52 box sshd[4403]: Failed password for root from 198.51.100.44 port 22 ssh2
Dec 24 07:13:53 box sshd[4404]: Failed password for root from 198.51.100.44 port 22 ssh2
Dec 24 07:13:54 box sshd[4405]: Failed password for root from 198.51.100.44 port 22 ssh2
Dec 24 07:13:56 box sshd[3321]: fatal: Too many authentication failures for root [preauth]
"""


def wait_app():
    import urllib.request

    deadline = time.time() + 40
    while time.time() < deadline:
        try:
            urllib.request.urlopen(BASE, timeout=1)
            return
        except Exception:
            time.sleep(0.3)
    raise SystemExit(f"app not up on {BASE}")


def encode_gif(frames: list[tuple[Path, float]], dest: Path) -> None:
    images: list[Image.Image] = []
    durations: list[int] = []
    for path, dur in frames:
        im = Image.open(path).convert("RGBA")
        w, h = im.size
        if w != GIF_WIDTH:
            im = im.resize((GIF_WIDTH, max(1, round(h * GIF_WIDTH / w))), Image.Resampling.LANCZOS)
        images.append(im.convert("P", palette=Image.Palette.ADAPTIVE, colors=128))
        durations.append(int(dur * 1000))
    images[0].save(
        dest,
        save_all=True,
        append_images=images[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )


def paste_box(page):
    loc = page.locator("#paste-input textarea").first
    if loc.count() == 0:
        loc = page.locator("#paste-input").locator("textarea").first
    if loc.count() == 0:
        loc = page.get_by_label("or paste SAML / log text")
    return loc


def analyze_button(page):
    return page.get_by_role("button", name="Analyze", exact=True)


def file_input_near(page, label_substr: str):
    block = page.locator("div.block").filter(has_text=label_substr).first
    inp = block.locator("input[type=file]")
    inp.wait_for(state="attached", timeout=10000)
    return inp


def shot(page, name: str) -> Path:
    path = OUT / name
    page.screenshot(path=str(path), full_page=False)
    return path


def scroll_report_heading(page, text: str):
    page.locator("#analysis").get_by_text(text, exact=False).first.wait_for(timeout=30000)
    page.evaluate(
        """(needle) => {
          const root = document.querySelector('#analysis');
          if (!root) return;
          const nodes = root.querySelectorAll('h1,h2,h3,p,li,strong');
          for (const node of nodes) {
            if ((node.textContent || '').includes(needle)) {
              node.scrollIntoView({block: 'start'});
              return;
            }
          }
          root.scrollIntoView({block: 'start'});
        }""",
        text,
    )
    time.sleep(0.5)


def show_report(page, text: str):
    scroll_report_heading(page, text)


def scroll_in_report(page, text: str):
    scroll_report_heading(page, text)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    ASSETS.mkdir(parents=True, exist_ok=True)
    wait_app()
    idp = OUT / "idp-metadata.xml"
    sp = OUT / "sp-metadata.xml"
    idp.write_text(IDP_METADATA)
    sp.write_text(SP_METADATA)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--hide-scrollbars"])
        context = browser.new_context(
            viewport={"width": WIDTH, "height": HEIGHT},
            color_scheme="light",
            device_scale_factor=1,
        )
        page = context.new_page()
        page.goto(BASE, wait_until="domcontentloaded")
        page.get_by_role("tab", name="Analyze").click()
        paste_box(page).wait_for(timeout=15000)

        f0 = shot(page, "saml-00-empty.png")
        paste_box(page).fill(SAML_PASTE)
        time.sleep(0.4)
        f1 = shot(page, "saml-01-pasted.png")
        file_input_near(page, "IdP metadata XML").set_input_files(str(idp))
        file_input_near(page, "SP metadata XML").set_input_files(str(sp))
        time.sleep(0.6)
        f2 = shot(page, "saml-02-metadata.png")
        analyze_button(page).click()
        show_report(page, "Documents detected")
        f3 = shot(page, "saml-03-report.png")
        scroll_in_report(page, "Mapping / consistency checks")
        f4 = shot(page, "saml-04-checks.png")
        encode_gif(
            [(f0, 1.5), (f1, 2.2), (f2, 2.2), (f3, 2.6), (f4, 3.4)],
            ASSETS / "analyze-saml-demo.gif",
        )

        page.reload(wait_until="domcontentloaded")
        page.get_by_role("tab", name="Analyze").click()
        paste_box(page).wait_for(timeout=15000)

        g0 = shot(page, "ssh-00-empty.png")
        paste_box(page).fill(SSH_PASTE)
        time.sleep(0.4)
        g1 = shot(page, "ssh-01-pasted.png")
        analyze_button(page).click()
        show_report(page, "Detected line severities")
        g2 = shot(page, "ssh-02-report.png")
        scroll_in_report(page, "Correlated incidents")
        g3 = shot(page, "ssh-03-incidents.png")
        encode_gif(
            [(g0, 1.5), (g1, 2.2), (g2, 2.6), (g3, 3.4)],
            ASSETS / "analyze-demo.gif",
        )

        browser.close()

    for name in ("analyze-saml-demo.gif", "analyze-demo.gif"):
        pth = ASSETS / name
        print(f"{name} bytes={pth.stat().st_size}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
