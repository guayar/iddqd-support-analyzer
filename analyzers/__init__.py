from .saml import analyze_saml_input as _analyze_saml_input
from .saml_signature import enhance_saml_signature_validation
from .saml_supplied_cert import extract_pem_certificates_from_text, verify_with_supplied_certificate
from .logs import analyze_log_text
from .anonymizer import anonymize_text


def analyze_saml_input(text: str, signing_cert: bytes | str | None = None):
    result = _analyze_saml_input(text)
    result = enhance_saml_signature_validation(text, result)

    # PEM certificate files dropped into the existing multi-file Analyze input
    # are included in `text`; discover them automatically. A dedicated upload
    # field can also pass PEM or DER bytes explicitly.
    cert_data = signing_cert if signing_cert is not None else extract_pem_certificates_from_text(text)
    if cert_data is not None:
        result = verify_with_supplied_certificate(text, result, cert_data)
    return result
