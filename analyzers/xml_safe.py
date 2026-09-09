from __future__ import annotations

import zlib

from lxml import etree

from config import MAX_FILE_MB

# Same budget as uploads: a tiny compressed blob must not expand past the file cap.
MAX_INFLATE_BYTES = MAX_FILE_MB * 1024 * 1024


def lxml_parser() -> etree.XMLParser:
    """lxml parser for untrusted SAML/metadata (SignXML needs lxml, not defusedxml)."""
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        remove_blank_text=False,
        recover=False,
        huge_tree=False,
    )


def lxml_fromstring(xml: str | bytes):
    raw = xml.encode("utf-8") if isinstance(xml, str) else xml
    return etree.fromstring(raw, parser=lxml_parser())


def decompress_limited(data: bytes, wbits: int, max_length: int | None = None) -> bytes:
    """Inflate zlib/raw-DEFLATE/gzip and reject output larger than max_length."""
    limit = MAX_INFLATE_BYTES if max_length is None else max_length
    if limit <= 0:
        raise ValueError("decompressed payload exceeds size limit")
    decoder = zlib.decompressobj(wbits)
    out = decoder.decompress(data, max_length=limit)
    if decoder.unconsumed_tail:
        raise ValueError("decompressed payload exceeds size limit")
    out += decoder.flush()
    if len(out) > limit:
        raise ValueError("decompressed payload exceeds size limit")
    return out
