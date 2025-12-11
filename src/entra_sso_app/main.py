import requests
from flask import Blueprint, current_app, redirect, render_template, session, url_for

from .auth import _build_msal_app
from .config import Config
from .token_store import token_store


main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Public landing page.

    Shows a sign-in button for anonymous users and a greeting
    for signed-in users.
    """

    user = session.get("user")
    return render_template("index.html", user=user)


@main_bp.route("/profile")
def profile():
    """Protected profile page backed by Microsoft Graph."""

    user = session.get("user")
    if not user:
        return redirect(url_for("auth.login"))

    subject = user.get("oid")
    if not subject:
        current_app.logger.warning("User in session missing oid; redirecting to login")
        return redirect(url_for("auth.login"))

    access_token = token_store.get_access_token(subject)
    if not access_token:
        current_app.logger.info(
            "No access token found for subject=%s; redirecting to login", subject
        )
        return redirect(url_for("auth.login"))

    def call_graph(token: str):
        headers = {"Authorization": f"Bearer {token}"}
        return requests.get(Config.ENDPOINT, headers=headers, timeout=5)

    # First attempt with the current access token.
    graph_response = call_graph(access_token)

    # If the token is expired or invalid, attempt a refresh using the
    # stored refresh token and retry once.
    if graph_response.status_code in {401, 403}:
        refresh_token = token_store.get_refresh_token(subject)
        if refresh_token:
            current_app.logger.info(
                "Access token rejected for subject=%s (status=%s); attempting refresh",
                subject,
                graph_response.status_code,
            )
            msal_app = _build_msal_app()
            result = msal_app.acquire_token_by_refresh_token(
                refresh_token,
                scopes=Config.SCOPE,
            )
            if "error" not in result:
                new_access_token = result.get("access_token")
                new_refresh_token = result.get("refresh_token") or refresh_token
                if new_access_token:
                    token_store.save_tokens(subject, new_access_token, new_refresh_token)
                    access_token = new_access_token
                    graph_response = call_graph(access_token)
            else:
                current_app.logger.error(
                    "Failed to refresh token for subject=%s: %s - %s",
                    subject,
                    result.get("error"),
                    result.get("error_description"),
                )

    if graph_response.status_code != 200:
        current_app.logger.error(
            "Failed to fetch profile from Microsoft Graph: %s - %s",
            graph_response.status_code,
            graph_response.text,
        )
        return "Could not load profile information from Microsoft Graph.", 500

    profile_data = graph_response.json()
    claims = (
        session.get("id_token_claims")
        if current_app.config.get("SHOW_ID_TOKEN_CLAIMS")
        else None
    )
    return render_template("profile.html", user=user, profile=profile_data, claims=claims)
