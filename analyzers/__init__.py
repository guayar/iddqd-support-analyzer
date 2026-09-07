from .saml import analyze_saml_input as _analyze_saml_input
from .saml_signature import enhance_saml_signature_validation
from .logs import analyze_log_text
from .anonymizer import anonymize_text


def analyze_saml_input(text: str):
    result = _analyze_saml_input(text)
    return enhance_saml_signature_validation(text, result)
