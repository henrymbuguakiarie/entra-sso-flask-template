import os
from typing import Mapping

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class BaseConfig:
    """Base configuration shared by all environments."""

    # --- Flask Configuration ---
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
    PREFERRED_URL_SCHEME = "https"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = True

    # --- Microsoft Entra ID (Azure AD) Configuration ---
    TENANT_ID = os.environ.get("TENANT_ID")
    CLIENT_ID = os.environ.get("CLIENT_ID")
    CLIENT_SECRET = os.environ.get("CLIENT_SECRET")

    # Optional: certificate-based credentials. When configured, the app will
    # prefer this certificate over the client secret for MSAL auth.
    CLIENT_CERT_PATH = os.environ.get("ENTRA_CLIENT_CERT_PATH")
    CLIENT_CERT_THUMBPRINT = os.environ.get("ENTRA_CLIENT_CERT_THUMBPRINT")
    CLIENT_CERT_PASSWORD = os.environ.get("ENTRA_CLIENT_CERT_PASSWORD")

    # Base URL for the Microsoft identity platform
    AUTHORITY_BASE_URL = os.environ.get("AUTHORITY_BASE_URL")

    # Construct the full authority URL for the specific tenant
    AUTHORITY = (
        f"{AUTHORITY_BASE_URL}{TENANT_ID}" if AUTHORITY_BASE_URL and TENANT_ID else None
    )

    # The required scope (permissions) for the delegated flow.
    # Accepts a space-separated list in SCOPE, e.g. "User.Read offline_access".
    _raw_scope = os.environ.get("SCOPE", "")
    SCOPE = [s for s in _raw_scope.split(" ") if s] or ["User.Read"]

    # The application's redirect path (matches the App Registration setup)
    REDIRECT_PATH = "/auth/redirect"

    # Microsoft Graph API endpoint for reading user profile
    ENDPOINT = "https://graph.microsoft.com/v1.0/me"

    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

    # When true, expose raw ID token claims to the profile page for
    # developer debugging. This should normally remain false in production.
    SHOW_ID_TOKEN_CLAIMS = os.environ.get("SHOW_ID_TOKEN_CLAIMS", "false").lower() == "true"

    @classmethod
    def validate(cls, config: Mapping[str, object] | None = None) -> None:
        """Validate that critical configuration values are present.

        In production this should run at startup to fail fast when
        required environment variables are missing.
        """

        required_attrs = [
            "SECRET_KEY",
            "TENANT_ID",
            "CLIENT_ID",
            "AUTHORITY_BASE_URL",
            "AUTHORITY",
            "SCOPE",
        ]
        missing = [name for name in required_attrs if not getattr(cls, name, None)]
        if missing:
            raise RuntimeError(
                f"Missing required configuration values: {', '.join(missing)}. "
                "Check your environment variables or .env file."
            )

        # Ensure we have at least one form of client credential.
        has_secret = bool(cls.CLIENT_SECRET)
        has_cert = bool(cls.CLIENT_CERT_PATH and cls.CLIENT_CERT_THUMBPRINT)

        if not (has_secret or has_cert):
            raise RuntimeError(
                "You must configure either CLIENT_SECRET or "
                "ENTRA_CLIENT_CERT_PATH and ENTRA_CLIENT_CERT_THUMBPRINT."
            )

        # If a certificate is configured, ensure the file exists so startup
        # fails fast rather than at the first login attempt.
        if has_cert and not os.path.exists(cls.CLIENT_CERT_PATH):
            raise RuntimeError(
                f"Client certificate file not found at {cls.CLIENT_CERT_PATH}. "
                "Check ENTRA_CLIENT_CERT_PATH or use CLIENT_SECRET instead."
            )


class DevelopmentConfig(BaseConfig):
    """Configuration for local development."""

    DEBUG = True
    # For local HTTPS with self-signed cert this can remain True.
    SESSION_COOKIE_SECURE = True


class ProductionConfig(BaseConfig):
    """Configuration for production deployments."""

    DEBUG = False
    # Ensure cookies are secure and HTTP-only in production.
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


class TestingConfig(BaseConfig):
    """Configuration used in unit tests.

    Provides dummy but syntactically valid values so tests do not
    require real secrets or network calls.
    """

    TESTING = True
    SECRET_KEY = "test-secret-key"
    TENANT_ID = "test-tenant"
    CLIENT_ID = "test-client-id"
    CLIENT_SECRET = "test-client-secret"
    AUTHORITY_BASE_URL = "https://login.microsoftonline.com/"
    AUTHORITY = AUTHORITY_BASE_URL + TENANT_ID
    SCOPE = ["User.Read"]
    # Disable CSRF in tests to simplify client interactions.
    WTF_CSRF_ENABLED = False

    @classmethod
    def validate(cls, config: Mapping[str, object] | None = None) -> None:  # type: ignore[override]
        """Skip strict validation during tests."""
        return


def get_config_class() -> type[BaseConfig]:
    """Select the appropriate configuration class from APP_ENV.

    Defaults to ``DevelopmentConfig`` when ``APP_ENV`` is not set.
    """

    env = os.environ.get("APP_ENV", "development").lower()
    if env in {"prod", "production"}:
        return ProductionConfig
    if env in {"test", "testing"}:
        return TestingConfig
    return DevelopmentConfig


# Backwards-compatible name for code that still imports Config directly.
Config = BaseConfig