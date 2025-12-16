import msal
from flask import Blueprint, current_app, redirect, request, session, url_for

from .config import Config
from .token_store import token_store


auth_bp = Blueprint("auth", __name__)


def _build_client_credential():
    """Build the MSAL client credential.

    Prefer a certificate when configured; otherwise fall back to CLIENT_SECRET.
    """

    cert_path = Config.CLIENT_CERT_PATH
    thumbprint = Config.CLIENT_CERT_THUMBPRINT
    password = Config.CLIENT_CERT_PASSWORD

    if cert_path and thumbprint:
        try:
            with open(cert_path, "rb") as cert_file:
                private_key = cert_file.read()

            current_app.logger.info(
                "Using client certificate for MSAL authentication (thumbprint=%s)",
                thumbprint,
            )

            credential: dict[str, object] = {
                "private_key": private_key,
                "thumbprint": thumbprint,
            }
            if password:
                credential["passphrase"] = password.encode("utf-8")

            return credential
        except OSError as exc:  # pragma: no cover - error path exercised in tests
            current_app.logger.warning(
                "Failed to load client certificate from %s: %s. Falling back to CLIENT_SECRET.",
                cert_path,
                exc,
            )

    return Config.CLIENT_SECRET


def _build_msal_app() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        Config.CLIENT_ID,
        authority=Config.AUTHORITY,
        client_credential=_build_client_credential(),
    )


@auth_bp.route("/login")
def login():
    """Initiate the Authorization Code Flow with Microsoft Entra ID."""
    msal_app = _build_msal_app()
    flow = msal_app.initiate_auth_code_flow(
        scopes=Config.SCOPE,
        redirect_uri=url_for("auth.auth_redirect", _external=True, _scheme="https"),
    )

    # Store the flow in the session so MSAL can validate state, nonce, and PKCE.
    session["auth_flow"] = flow
    current_app.logger.info("Starting login flow, state=%s", flow.get("state"))

    return redirect(flow["auth_uri"])


@auth_bp.route(Config.REDIRECT_PATH)
def auth_redirect():
    """Handle the redirect from Microsoft Entra ID with an auth code."""

    if request.args.get("error"):
        error = request.args.get("error")
        error_description = request.args.get("error_description")
        current_app.logger.error(
            "Authentication error on redirect: %s - %s", error, error_description
        )
        return f"Authentication error: {error} - {error_description}", 400

    flow = session.get("auth_flow")
    if not flow:
        current_app.logger.error("Auth code flow not found in session on redirect")
        return "Session expired. Please sign in again.", 400

    msal_app = _build_msal_app()
    try:
        result = msal_app.acquire_token_by_auth_code_flow(
            flow,
            request.args,
            scopes=Config.SCOPE,
        )
    except ValueError:
        current_app.logger.warning(
            "State mismatch or invalid auth response in acquire_token_by_auth_code_flow"
        )
        return "State mismatch. Possible CSRF attack.", 400
    finally:
        # Flow is one-time-use; remove it regardless of outcome.
        session.pop("auth_flow", None)

    if "error" in result:
        current_app.logger.error(
            "Token acquisition error: %s - %s",
            result.get("error"),
            result.get("error_description"),
        )
        return (
            f"Token acquisition error: {result.get('error')} - {result.get('error_description')}",
            400,
        )

    id_token_claims = result.get("id_token_claims", {})
    if current_app.config.get("SHOW_ID_TOKEN_CLAIMS"):
        # Store raw claims for developer inspection on the profile page.
        session["id_token_claims"] = id_token_claims
    user_context = {
        "name": id_token_claims.get("name"),
        "preferred_username": id_token_claims.get("preferred_username"),
        "oid": id_token_claims.get("oid"),
    }
    session["user"] = user_context

    access_token = result.get("access_token")
    refresh_token = result.get("refresh_token")
    subject = user_context.get("oid")
    if access_token and subject:
        token_store.save_tokens(subject, access_token, refresh_token)
        current_app.logger.info(
            "Stored tokens for subject=%s (has_refresh=%s)",
            subject,
            bool(refresh_token),
        )

    return redirect(url_for("main.profile"))


@auth_bp.route("/logout")
def logout():
    """Sign the user out locally and at Microsoft Entra ID."""

    user = session.get("user") or {}
    subject = user.get("oid")
    if subject:
        token_store.revoke_tokens(subject)
        current_app.logger.info("Revoked tokens for subject=%s", subject)

    session.clear()

    tenant_id = Config.TENANT_ID
    post_logout_redirect_uri = url_for("main.index", _external=True, _scheme="https")
    logout_url = (
        f"{Config.AUTHORITY_BASE_URL}{tenant_id}/oauth2/v2.0/logout"
        f"?post_logout_redirect_uri={post_logout_redirect_uri}"
    )

    return redirect(logout_url)
