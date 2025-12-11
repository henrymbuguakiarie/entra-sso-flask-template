## 📄 ARCHITECTURE PROPOSAL: Microsoft Entra ID SSO Integration

### 1. Introduction and Objectives

This document proposes the architectural blueprint for integrating **Single Sign-On (SSO)** into a Python web application using the **Microsoft Entra Identity Platform** (formerly Azure AD). The primary objective is to establish a secure, standardized, and reusable foundation for authenticating internal users accessing web services.

#### **Key Objectives:**

* **Security:** Implement the highly secure **OAuth 2.0 Authorization Code Flow** to protect the client secret and tokens.
* **Standardization:** Utilize the **MSAL (Microsoft Authentication Library for Python)** to abstract protocol complexity and adhere to Microsoft's recommended security practices.
* **Reusability:** Develop a clean, modular **Flask** template (`entra-sso-flask-template`) for rapid deployment across future internal services.
* **Compliance:** Align the authentication pattern with the organization's **Zero Trust** security model.

---

### 2. Architectural Components and Flow Analysis

#### **2.1. Component Roles**

| Component | Role in Project | Engineering Consideration |
| :--- | :--- | :--- |
| **Microsoft Entra ID** | **Authorization Server / Identity Provider (IdP)** | Handles user authentication, token issuance, and maintains centralized identity policy. |
| **Flask Application** | **Client / Relying Party** | Initiates the authentication request and securely exchanges the Authorization Code for tokens. |
| **Microsoft Graph API** | **Resource Server** | Used post-authentication to retrieve essential user profile claims (`User.Read`). |
| **MSAL Python** | **Protocol Handler** | Manages the cryptographic aspects of the OAuth 2.0 flow (e.g., PKCE integration, token validation, caching). |

#### **2.2. The Authorization Code Flow (Grant)**

The architecture relies on the Authorization Code flow, which is mandatory for web applications running on a server. 

1.  **Authorization Request:** The Flask app redirects the user to the Entra ID authorization endpoint, requesting permissions (`scope: User.Read`).
2.  **Authorization Code:** Entra ID returns a short-lived **Authorization Code** to the configured **Redirect URI** (`/auth/redirect`).
3.  **Token Exchange (Server-Side):** The Flask app, using the MSAL client, sends the **Code** along with its **Client ID** and **Client Secret** (kept secret on the server) to the token endpoint.
4.  **Token Issuance:** Entra ID validates the secret and issues an **Access Token** (for accessing the Graph API) and an **ID Token** (containing user identity claims).
5.  **Session Establishment:** The application uses the claims from the ID Token to establish a user session (`flask.session`).

---

### 3. Implementation and Engineering Practices

#### **3.1. Project Structure and Management**

* **Dependency Management:** The project uses **Poetry** for isolated environments, clean dependency resolution, and predictable builds. This minimizes the risk of dependency conflicts and facilitates reproducible CI/CD pipelines.
* **Configuration:** All secrets and configuration parameters are loaded via `python-dotenv` into a central `Config` class, promoting **12-Factor App** principles. The `.gitignore` file explicitly excludes the `.env` file, enforcing secret separation.

#### **3.2. Security Considerations**

* **Client Secret Protection:** The application is configured as a `ConfidentialClientApplication` in MSAL, ensuring the crucial `CLIENT_SECRET` is never exposed to the user's browser, satisfying a core security requirement.
* **State Management:** The MSAL library automatically generates and validates a unique `state` parameter during the flow to prevent **Cross-Site Request Forgery (CSRF)** attacks.
* **Token Validation:** Tokens received are automatically validated by MSAL (checking signature, expiration, issuer, and audience) before being accepted, protecting against forged tokens.

#### **3.3. Scalability and Extensibility**

The current implementation uses the Flask session for token caching. For production scalability, this will be modified to use an external persistent cache (e.g., Redis or Memcached), ensuring:

* **Horizontal Scaling:** User state is not tied to a single application instance.
* **Token Refresh:** Tokens can be securely refreshed using the stored refresh token when the access token expires, providing a seamless user experience.

---

### 4. Conclusion

The proposed architecture delivers a secure, professional, and maintainable SSO solution for internal applications. By leveraging Python, Flask, and the robust MSAL library, this project serves as a definitive security template, significantly reducing the engineering overhead and risk associated with securing future enterprise services.