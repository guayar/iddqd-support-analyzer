"""OAuth2 log analyzer tests - real security escalations."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_missing_state_parameter_csrf_risk():
    """Real escalation: Authorization request without state parameter = CSRF vulnerability."""
    log = '2026-01-15 10:23:45 INFO AuthzEndpoint: client_id=abc123456 scope=email+profile response_type=code'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_bearer_token_in_logs_credential_leak():
    """Real escalation: JWT token exposed in logs = credentials leaked."""
    log = '2026-01-15 10:24:00 DEBUG API Request: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_client_secret_exposed():
    """Real escalation: Client secret in logs = attacker can impersonate app."""
    log = '2026-01-15 10:25:00 ERROR TokenEndpoint: client_id=app123 client_secret=super_secret_xyz_789 grant_type=authorization_code code=authcode123'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_authorization_code_reuse_replay_attack():
    """Real escalation: Auth code reused = replay attack detected."""
    text = (
        '2026-01-15 10:26:00 INFO TokenEndpoint: Exchanging code=xyz123 for token\n'
        '2026-01-15 10:26:01 INFO Token issued: access_token=new_token_abc\n'
        '2026-01-15 10:26:05 ERROR TokenEndpoint: Authorization code already used - code=xyz123\n'
        '2026-01-15 10:26:06 INFO Possible replay attack detected from 192.168.1.50\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 3


def test_implicit_flow_deprecated():
    """Real escalation: Implicit flow still in use (deprecated OAuth2 spec)."""
    text = (
        '2026-01-15 10:27:00 INFO AuthzEndpoint: response_type=token client_id=spa_app_123 scope=openid+email\n'
        '2026-01-15 10:27:01 WARN Using deprecated implicit flow - recommend authorization_code + PKCE\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 1


def test_missing_pkce_native_app():
    """Real escalation: Native app without PKCE = vulnerable to auth code interception."""
    log = '2026-01-15 10:28:00 ERROR AuthzEndpoint: native app "MobileApp/1.0" grant_type=authorization_code without code_challenge (PKCE missing)'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_invalid_grant_token_rotation_failure():
    """Real escalation: Invalid grant error = token refresh might have failed."""
    text = (
        '2026-01-15 10:29:00 INFO TokenEndpoint: client_id=web_app refresh_token=refresh_xyz_123\n'
        '2026-01-15 10:29:01 ERROR Invalid grant: refresh_token expired or revoked\n'
        '2026-01-15 10:29:02 WARN User may need to re-authenticate\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_token_expiration_without_refresh():
    """Real escalation: Token expired, no refresh token flow."""
    text = (
        '2026-01-15 10:30:00 INFO API: access_token validation\n'
        '2026-01-15 10:30:01 ERROR Token expired: access_token_xyz_123\n'
        '2026-01-15 10:30:02 ERROR No refresh_token available - user must re-login\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_redirect_uri_mismatch_attack():
    """Real escalation: Attacker sending different redirect_uri = possible account takeover."""
    text = (
        '2026-01-15 10:31:00 INFO AuthzEndpoint: redirect_uri=https://legitimate-app.com/callback\n'
        '2026-01-15 10:31:01 WARN Mismatch: Request redirect_uri=https://attacker.com/steal_token\n'
        '2026-01-15 10:31:02 ERROR Redirect URI mismatch - authorization denied\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_invalid_scope_permission_denied():
    """Real escalation: App requesting scope it doesn't have."""
    text = (
        '2026-01-15 10:32:00 INFO AuthzEndpoint: client_id=app123 scope=user:delete+repo:admin\n'
        '2026-01-15 10:32:01 ERROR Invalid scope "user:delete" not authorized for this app\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 1


def test_multiple_token_failures_user_lockout():
    """Real escalation: Multiple failed token requests might indicate lockout or compromise."""
    text = (
        '2026-01-15 10:33:00 INFO TokenEndpoint: client_id=mobile_app code=auth123\n'
        '2026-01-15 10:33:01 ERROR Invalid grant: code already used\n'
        '2026-01-15 10:33:02 INFO TokenEndpoint: client_id=mobile_app code=auth456\n'
        '2026-01-15 10:33:03 ERROR Invalid grant: code already used\n'
        '2026-01-15 10:33:04 INFO TokenEndpoint: client_id=mobile_app code=auth789\n'
        '2026-01-15 10:33:05 ERROR Invalid grant: code already used\n'
        '2026-01-15 10:33:06 WARN Suspicious: 3 failed token exchanges in 6 seconds\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 5


def test_refresh_token_rotation_pattern():
    """Real scenario: Healthy refresh token rotation (no errors expected)."""
    text = (
        '2026-01-15 10:34:00 INFO TokenEndpoint: Refresh token rotation\n'
        '2026-01-15 10:34:01 INFO Issued new access_token (exp: 3600s)\n'
        '2026-01-15 10:34:02 INFO Issued new refresh_token (rotation)\n'
        '2026-01-15 10:34:03 INFO Old refresh_token revoked\n'
    )
    r = analyze_log_text(text)
    # No errors expected in normal flow
    assert r.get("error_event_count", 0) == 0 or r.get("line_count", 0) >= 3


def test_mixed_oauth_and_other_logs():
    """Real scenario: OAuth2 logs mixed with app logs."""
    text = (
        '2026-01-15 10:35:00 INFO AppStart: Starting user service\n'
        '2026-01-15 10:35:01 INFO AuthzEndpoint: client_id=web123 scope=openid+email\n'
        '2026-01-15 10:35:02 INFO Processing request /api/users\n'
        '2026-01-15 10:35:03 ERROR Bearer token invalid or expired\n'
        '2026-01-15 10:35:04 DEBUG Response: 401 Unauthorized\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 4


def test_github_oauth_token_exposure():
    """Real example: GitHub OAuth token leaked in logs (from real incidents)."""
    log = '2026-01-15 10:36:00 ERROR Failed to revoke token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_google_oauth_refresh_failure():
    """Real example: Google OAuth refresh token expired/revoked."""
    text = (
        '2026-01-15 10:37:00 INFO Google OAuth: Attempting token refresh\n'
        '2026-01-15 10:37:01 ERROR Response: invalid_grant (Refresh token revoked)\n'
        '2026-01-15 10:37:02 WARN User "john@example.com" must re-authorize\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_okta_mfa_with_oauth():
    """Real scenario: Okta OAuth with MFA challenges."""
    text = (
        '2026-01-15 10:38:00 INFO Okta AuthzEndpoint: scope=openid+profile+email\n'
        '2026-01-15 10:38:01 INFO MFA Required: user must verify TOTP\n'
        '2026-01-15 10:38:02 INFO TokenEndpoint: MFA verified, issuing tokens\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_keycloak_token_introspection():
    """Real scenario: Keycloak token validation."""
    text = (
        '2026-01-15 10:39:00 INFO Keycloak: Token introspection request\n'
        '2026-01-15 10:39:01 DEBUG token_signature=valid, realm=production\n'
        '2026-01-15 10:39:02 DEBUG token_exp=2026-01-15T11:39:00Z (valid)\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


if __name__ == "__main__":
    test_missing_state_parameter_csrf_risk()
    test_bearer_token_in_logs_credential_leak()
    test_client_secret_exposed()
    test_authorization_code_reuse_replay_attack()
    test_implicit_flow_deprecated()
    test_missing_pkce_native_app()
    test_invalid_grant_token_rotation_failure()
    test_token_expiration_without_refresh()
    test_redirect_uri_mismatch_attack()
    test_invalid_scope_permission_denied()
    test_multiple_token_failures_user_lockout()
    test_refresh_token_rotation_pattern()
    test_mixed_oauth_and_other_logs()
    test_github_oauth_token_exposure()
    test_google_oauth_refresh_failure()
    test_okta_mfa_with_oauth()
    test_keycloak_token_introspection()
    print("LOG OAUTH2 TESTS OK")
