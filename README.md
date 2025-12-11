# Entra SSO Flask Template

This project is a minimal but production-oriented Flask application that shows how to integrate Microsoft Entra ID (Azure AD) Single Sign-On using the OAuth 2.0 Authorization Code Flow with MSAL for Python and Microsoft Graph.

You can use it as a starting point for any Flask app that needs secure SSO with Entra ID and basic access to the signed-in user’s profile.

## What the template implements (and why you care)

- **Clean Flask architecture**: App factory (`create_app` in `entra_sso_app.__init__`) and blueprints (`main` and `auth`) so you can extend routes and tests without rewiring everything.
- **Entra ID Authorization Code Flow**: `/login` and `/auth/redirect` in `entra_sso_app.auth` implement the standard web sign-in flow via MSAL, including state validation for CSRF protection.
- **Microsoft Graph integration**: `/profile` in `entra_sso_app.main` calls `https://graph.microsoft.com/v1.0/me` to show the signed-in user’s basic profile (name, email, job title, id).
- **Secure token handling**: Access tokens are stored server-side via a token store (`entra_sso_app.token_store`) instead of being placed directly in the browser cookie, reducing leakage risk.
- **Environment-aware configuration**: `entra_sso_app.config` defines `DevelopmentConfig`, `ProductionConfig`, and `TestingConfig` with secure cookie flags and validation of required Entra settings.
- **Logging and error handling**: Centralized logging and simple 400/500 error handlers help you diagnose issues in a consistent way.
- **PKCE + hardened state**: The Authorization Code Flow uses a high-entropy state value for CSRF protection and implements PKCE by sending a SHA256-based `code_challenge` on the authorize request and redeeming the code with the original `code_verifier` in the token request body.

This means you don’t just get a demo that “works on localhost” – you get patterns you can safely grow into a real application.

## Entra app registration setup

1. **Create an app registration** in the Azure portal under **Microsoft Entra ID → App registrations**.

2. **Platform configuration**
   - Add a **Web** platform.
   - Set the redirect URI to match what the app uses, for example:
     - `https://127.0.0.1:5000/auth/redirect`
   - Ensure the scheme (`https`), host, port, and path exactly match.

3. **API permissions (Microsoft Graph)**
   - Under **API permissions**, add **Microsoft Graph → Delegated** permission:
     - `User.Read`
   - Click **Grant admin consent** if your tenant requires it.

4. **Expose values for the app**
   - From the app registration blade, collect:
     - **Directory (tenant) ID** → `TENANT_ID`
     - **Application (client) ID** → `CLIENT_ID`
   - Create a **client secret** under **Certificates & secrets**, and use the value as `CLIENT_SECRET`.

5. **Match redirect URI in `.env`**
   - The app uses `Config.REDIRECT_PATH = "/auth/redirect"` and `PREFERRED_URL_SCHEME = "https"`.
   - When running locally with the included runner, the full redirect URI is typically:
     - `https://127.0.0.1:5000/auth/redirect`
   - Make sure this value is registered in Entra exactly.

## Getting started (clone and run)

1. **Clone the repository**

   ```bash
   git clone https://github.com/henrymbuguakiarie/entra-sso-flask-template.git
   cd entra-sso-flask-template
   ```

2. **Create and configure `.env`**

   - Copy the example env file and edit it:

     ```bash
     cp .env.example .env
     ```

   - Fill in the values from your Entra app registration (see the _Entra app registration setup_ section above for details). At minimum set:

     ```env
     FLASK_SECRET_KEY=super-secret-key
     TENANT_ID=<your-tenant-id>
     CLIENT_ID=<your-client-id>
     CLIENT_SECRET=<your-client-secret>
     AUTHORITY_BASE_URL=https://login.microsoftonline.com/
     SCOPE=User.Read offline_access
     APP_ENV=development
     LOG_LEVEL=INFO
     ```

3. **Install dependencies with Poetry**

   ```bash
   poetry install
   ```

4. **(Optional) Install dev dependencies and run tests**

   ```bash
   poetry install --with dev
   poetry run pytest
   ```

5. **Run the application**

   ```bash
   poetry run python -m src.entra_sso_app.app
   ```

6. **Open the app in your browser**

   - Navigate to `https://127.0.0.1:5000`.
   - Accept the self-signed certificate warning.
   - Click **Sign in with Microsoft** and complete the Entra sign-in.

## Configuration: APP_ENV and config classes

Configuration lives in `entra_sso_app.config` and is environment-driven.

- **BaseConfig**: Common settings loaded from environment variables (`.env` via `python-dotenv`):
  - `FLASK_SECRET_KEY`, `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `AUTHORITY_BASE_URL`, `SCOPE`, etc.
  - Defines `ENDPOINT = "https://graph.microsoft.com/v1.0/me"` and secure cookie defaults.
  - `BaseConfig.validate(...)` checks that required values are present and fails fast if they are not.

- **DevelopmentConfig**: Used when `APP_ENV` is unset or set to `development`.
  - Enables `DEBUG` and keeps secure cookie flags on for local HTTPS with self-signed certs.

- **ProductionConfig**: Used when `APP_ENV` is `prod`/`production`.
  - Disables `DEBUG` and keeps cookies secure.

- **TestingConfig**: Used when `APP_ENV` is `test`/`testing` or when passed explicitly in tests.
  - Provides dummy but valid values for Entra settings.
  - Overrides `validate` to skip strict checks so tests don’t need real secrets.

The app factory (`create_app`) in `entra_sso_app.__init__` will:

1. Choose the appropriate config class via `APP_ENV` (or use the one you pass in).
2. Load it into the Flask app.
3. Configure logging based on `LOG_LEVEL`.
4. Validate that required settings are present (except for `TestingConfig`).

### Required environment variables (`.env`)

Create a `.env` file in the project root with at least:

```env
FLASK_SECRET_KEY=super-secret-key
TENANT_ID=<your-tenant-id>
CLIENT_ID=<your-client-id>
CLIENT_SECRET=<your-client-secret>
AUTHORITY_BASE_URL=https://login.microsoftonline.com/
SCOPE=User.Read offline_access
APP_ENV=development
LOG_LEVEL=INFO
```

## Token store: how tokens are stored and why

The template uses a small abstraction in `entra_sso_app.token_store`:

- `TokenStore`: an interface for saving/getting/revoking access tokens.
- `InMemoryTokenStore`: a simple in-memory implementation used by default.

How it works in the flow:

- After a successful sign-in in `auth.auth_redirect`, MSAL returns an access token and ID token claims.
- The app stores only minimal user info (name, preferred username, object id) in the Flask session cookie.
- The access token is stored **server-side** in the token store keyed by the user’s object id (`oid`).
- When `/profile` is called, it reads the user from the session, derives the `oid`, and fetches the access token from the token store before calling Microsoft Graph.

Why this matters:

- Access tokens can grant powerful access to APIs; keeping them out of browser cookies reduces the blast radius if a cookie leaks.
- The abstraction makes it easy to later swap in a more robust backend (e.g. Redis) without changing your route logic.

### Refresh tokens and `offline_access`

When you include `offline_access` in `SCOPE`, Entra ID can issue a **refresh token** alongside the access token. This template:

- Stores refresh tokens server-side in the same token store (never in cookies).
- On Graph calls from `/profile`, if the access token is rejected (e.g., expires and returns 401/403), it:
   - Uses MSAL and the stored refresh token to acquire a new access token.
   - Saves the new access and refresh tokens in the token store.
   - Retries the Graph call once transparently.

This gives you a smoother user experience (fewer forced re-logins) while still keeping tokens off the client and under server control.

For production, you would typically:

- Replace `InMemoryTokenStore` with a Redis or database-backed store.
- Keep the same interface so your view functions do not change.

## Debugging ID token claims during development

Sometimes it is useful to see the raw ID token claims that Entra ID is issuing (for example, to understand which `tid`, `oid`, or custom claims are present). This template includes an **opt-in** developer feature for that.

When the configuration flag `SHOW_ID_TOKEN_CLAIMS` is enabled:

- `auth.auth_redirect` stores the full `id_token_claims` from MSAL into the Flask session.
- The `/profile` route reads those claims and passes them into the `profile.html` template.
- The profile page renders a debug section showing the claims as pretty-printed JSON.

To enable this in local development, set the flag in your `.env`:

```env
SHOW_ID_TOKEN_CLAIMS=true
```

Then restart the app, sign in, and visit `/profile`. You’ll see a **"Debug: ID token claims"** section under the standard profile fields. This is intended for developers only; keep `SHOW_ID_TOKEN_CLAIMS=false` (or unset) in production so raw token contents are not exposed.

## Local development

1. **Install dependencies** with Poetry:

   ```bash
   poetry install
   ```

2. **Run the application** (HTTPS with self-signed cert for local dev):

   ```bash
   poetry run python -m src.entra_sso_app.app
   ```

3. **Browse the app**:

   - Open `https://127.0.0.1:5000` (or `https://localhost:5000`).
   - Accept the self-signed certificate warning.
   - Click the sign-in button to start the Entra ID login flow.
   - After successful login and consent to Graph (`User.Read`), you’ll be redirected back and can view your profile.

## Running tests

The project includes a small but meaningful test suite using `pytest`.

1. Install dev dependencies (including `pytest`):

   ```bash
   poetry install --with dev
   ```

2. Run the tests:

   ```bash
   poetry run pytest
   ```

What the tests cover:

- The home page renders and shows the sign-in button for anonymous users.
- `/profile` redirects to `/login` when the user is not authenticated.
- A happy-path `/profile` call that uses the token store and a mocked Microsoft Graph response.
- An error-path `/profile` call where Graph returns an error, and the route responds with a 500 and a friendly message.

These tests ensure the most important behaviors (auth gating, token store wiring, and Graph integration) stay stable as you evolve the app.

## How to extend this template

Here are a few common extension points and how to approach them.

### Add a new protected route

1. Define a new route in `entra_sso_app.main` (or another blueprint) that:
   - Checks `session["user"]` and redirects to `auth.login` if missing.
   - Uses the user’s `oid` to fetch the access token from the token store.
2. Optionally call another Microsoft Graph endpoint (or your own API) using that token.

Example sketch:

```python
@main_bp.route("/groups")
def groups():
   user = session.get("user")
   if not user:
      return redirect(url_for("auth.login"))

   subject = user.get("oid")
   token = token_store.get_access_token(subject)
   if not token:
      return redirect(url_for("auth.login"))

   headers = {"Authorization": f"Bearer {token}"}
   response = requests.get("https://graph.microsoft.com/v1.0/me/memberOf", headers=headers, timeout=5)
   # handle response, then render a template
```

### Call additional Microsoft Graph APIs

1. Add the required delegated permissions in the Entra app (e.g. `Calendars.Read`).
2. Update your `SCOPE` env var to include them (space-separated list as required by MSAL).
3. Update your views to call the relevant Graph endpoints using the stored access token.

### Swap the token store implementation

1. Create a new class that implements the `TokenStore` interface (e.g. `RedisTokenStore`).
2. Replace the module-level `token_store` instance in `entra_sso_app.token_store` with your implementation, or choose it based on an environment variable.
3. No changes are needed in your views as long as the interface stays the same.

This design keeps your auth, Graph access, and persistence concerns separated so you can evolve each independently as your application grows.
