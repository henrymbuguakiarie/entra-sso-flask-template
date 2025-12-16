import pathlib
import pathlib
import sys

import pytest


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from entra_sso_app import create_app
from entra_sso_app.config import TestingConfig
from entra_sso_app.token_store import token_store


@pytest.fixture()
def app():
    app = create_app(config_class=TestingConfig)
    app.config.update({"TESTING": True})
    return app
@pytest.fixture()
def client(app):
    return app.test_client()


def test_index_shows_login_when_anonymous(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Sign in with Microsoft" in response.data


def test_profile_redirects_when_not_authenticated(client):
    response = client.get("/profile", follow_redirects=False)
    # Unauthenticated users should be redirected to the login route
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_profile_fetches_graph_with_token_store(monkeypatch, app, client):
    """Happy-path profile call uses the token store and Graph.

    This test avoids real network calls by mocking requests and ensures
    that a user in the session with an oid gets a profile rendered.
    """

    # Seed a logged-in user in the session.
    with client.session_transaction() as sess:
        sess["user"] = {"oid": "user-123", "name": "Test User"}

    # Store a token for that subject in the in-memory token store.
    token_store.save_access_token("user-123", "fake-access-token")

    # Mock the Graph call made from entra_sso_app.main.
    import entra_sso_app.main as main_module

    class DummyResponse:
        status_code = 200
        text = ""

        def json(self):
            return {"displayName": "Test User", "mail": "test@example.com"}

    def fake_get(url, headers=None, timeout=5):  # noqa: ARG001
        return DummyResponse()

    monkeypatch.setattr(main_module, "requests", type("R", (), {"get": staticmethod(fake_get)}))

    response = client.get("/profile")
    assert response.status_code == 200
    assert b"Test User" in response.data
    assert b"test@example.com" in response.data


def test_profile_handles_graph_error(monkeypatch, app, client):
    """Profile route returns 500 and friendly message on Graph error."""

    with client.session_transaction() as sess:
        sess["user"] = {"oid": "user-456", "name": "Error User"}

    token_store.save_access_token("user-456", "fake-access-token")

    import entra_sso_app.main as main_module

    class ErrorResponse:
        status_code = 500
        text = "Graph error"

        def json(self):  # pragma: no cover - should not be called on error
            return {}

    def fake_get(url, headers=None, timeout=5):  # noqa: ARG001
        return ErrorResponse()

    monkeypatch.setattr(main_module, "requests", type("R", (), {"get": staticmethod(fake_get)}))

    response = client.get("/profile")
    assert response.status_code == 500
    assert b"Could not load profile information from Microsoft Graph." in response.data


def test_auth_redirect_missing_flow_returns_session_expired(client):
    """Redirect without an auth_flow in session should return a 400 error."""

    response = client.get("/auth/redirect")
    assert response.status_code == 400
    assert b"Session expired. Please sign in again." in response.data


def test_auth_redirect_value_error_treated_as_csrf(monkeypatch, client):
    """ValueError from MSAL auth_code_flow should surface as CSRF/state error."""

    import entra_sso_app.auth as auth_module

    class FakeMsalApp:
        def acquire_token_by_auth_code_flow(self, flow, auth_response, scopes=None, **kwargs):  # noqa: ARG002
            raise ValueError("invalid state")

    def fake_build_msal_app():
        return FakeMsalApp()

    monkeypatch.setattr(auth_module, "_build_msal_app", fake_build_msal_app)

    # Seed a dummy auth_flow in the session so the view does not short-circuit.
    with client.session_transaction() as sess:
        sess["auth_flow"] = {"state": "abc"}

    response = client.get("/auth/redirect?code=some-code&state=abc")
    assert response.status_code == 400
    assert b"State mismatch. Possible CSRF attack." in response.data


def test_profile_can_show_id_token_claims(monkeypatch, app, client):
    """When enabled, profile page includes a debug dump of ID token claims."""

    app.config["SHOW_ID_TOKEN_CLAIMS"] = True

    with client.session_transaction() as sess:
        sess["user"] = {"oid": "user-789", "name": "Claims User"}
        sess["id_token_claims"] = {
            "aud": "my-client-id",
            "tid": "tenant-id",
        }

    token_store.save_access_token("user-789", "fake-access-token")

    import entra_sso_app.main as main_module

    class DummyResponse:
        status_code = 200
        text = ""

        def json(self):
            return {"displayName": "Claims User", "mail": "claims@example.com"}

    def fake_get(url, headers=None, timeout=5):  # noqa: ARG001
        return DummyResponse()

    monkeypatch.setattr(main_module, "requests", type("R", (), {"get": staticmethod(fake_get)}))

    response = client.get("/profile")
    assert response.status_code == 200
    # Debug section should contain the JSON-encoded claims.
    assert b"claims@example.com" in response.data
    assert b"my-client-id" in response.data


def test_build_client_credential_uses_secret_when_no_cert(monkeypatch):
    """When no certificate is configured, the client secret is used."""

    import entra_sso_app.auth as auth_module

    class DummyConfig:
        CLIENT_SECRET = "secret-value"
        CLIENT_CERT_PATH = None
        CLIENT_CERT_THUMBPRINT = None
        CLIENT_CERT_PASSWORD = None

    monkeypatch.setattr(auth_module, "Config", DummyConfig)

    credential = auth_module._build_client_credential()
    assert credential == "secret-value"


def test_build_client_credential_prefers_certificate_when_available(tmp_path, monkeypatch, app):
    """When a certificate is configured, it is preferred over the secret."""

    import entra_sso_app.auth as auth_module

    cert_file = tmp_path / "client-cert.pem"
    cert_file.write_bytes(b"dummy-private-key")

    class DummyConfig:
        CLIENT_SECRET = "secret-value"
        CLIENT_CERT_PATH = str(cert_file)
        CLIENT_CERT_THUMBPRINT = "CERT-THUMBPRINT"
        CLIENT_CERT_PASSWORD = ""

    monkeypatch.setattr(auth_module, "Config", DummyConfig)

    with app.app_context():
        credential = auth_module._build_client_credential()

    assert isinstance(credential, dict)
    assert credential["thumbprint"] == "CERT-THUMBPRINT"
    assert credential["private_key"] == b"dummy-private-key"


def test_build_client_credential_falls_back_to_secret_if_cert_unreadable(tmp_path, monkeypatch, app):
    """If the certificate cannot be read, fall back to the secret."""

    import entra_sso_app.auth as auth_module

    # Point to a non-existent file to trigger the fallback path.
    missing_file = tmp_path / "missing-cert.pem"

    class DummyConfig:
        CLIENT_SECRET = "secret-value"
        CLIENT_CERT_PATH = str(missing_file)
        CLIENT_CERT_THUMBPRINT = "CERT-THUMBPRINT"
        CLIENT_CERT_PASSWORD = ""

    monkeypatch.setattr(auth_module, "Config", DummyConfig)

    with app.app_context():
        credential = auth_module._build_client_credential()

    assert credential == "secret-value"
