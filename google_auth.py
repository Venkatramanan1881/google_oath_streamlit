import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import requests
import json

# === CONFIGURATION ===
CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email"
]
COOKIE_ENCRYPTION_PASSWORD = "your-strong-16+char-password"  # Replace with strong password
REDIRECT_URI = "http://localhost:8501"

# === Initialize and load cookies ===
cookies = EncryptedCookieManager(password=COOKIE_ENCRYPTION_PASSWORD)
if not cookies.ready():
    st.warning("Cookies are not ready. Please refresh the page.")
    st.stop()


# === Save credentials to cookies ===
def save_credentials_to_cookie(creds):
    creds_data = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }
    cookies["google_creds"] = json.dumps(creds_data)
    cookies.save()

# === Load credentials from cookies ===
def load_credentials_from_cookie():
    if "google_creds" not in cookies:
        return None
    try:
        creds_data = json.loads(cookies["google_creds"])
        return Credentials(
            token=creds_data["token"],
            refresh_token=creds_data["refresh_token"],
            token_uri=creds_data["token_uri"],
            client_id=creds_data["client_id"],
            client_secret=creds_data["client_secret"],
            scopes=creds_data["scopes"],
        )
    except Exception:
        return None

# === Clear credentials from cookies ===
def clear_creds_cookie():
    if "google_creds" in cookies:
        del cookies["google_creds"]
        cookies.save()

# === Exchange authorization code for token ===
def authenticate_user():
    query_params = st.experimental_get_query_params()
    code = query_params.get("code", [None])[0]

    if code:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        try:
            flow.fetch_token(code=code)
            creds = flow.credentials
            save_credentials_to_cookie(creds)
            st.success("Login successful. Reloading...")
            st.experimental_set_query_params()
            st.rerun()
        except Exception as e:
            st.error(f"OAuth2 token fetch failed: {e}")
            return

# === Get user profile using token ===
def fetch_user_info(creds):
    try:
        resp = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {creds.token}"}
        )

        if resp.status_code == 401:  # Possibly expired
            creds.refresh(Request())
            save_credentials_to_cookie(creds)
            resp = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {creds.token}"}
            )

        if resp.status_code == 200:
            return resp.json()
        else:
            st.warning(f"Failed to fetch user info. Status: {resp.status_code}")
            return None
    except Exception as e:
        st.error(f"Error fetching user info: {e}")
        return None

# === MAIN APP ===
def main():
    st.title("🔐 Google Login with Encrypted Cookies")

    # Step 1: Handle OAuth callback
    if "code" in st.experimental_get_query_params():
        authenticate_user()
        return

    # Step 2: Load credentials from cookie
    creds = load_credentials_from_cookie()

    if creds and creds.valid:
        user_info = fetch_user_info(creds)
        if user_info:
            st.success(f"👋 Welcome {user_info.get('name')} ({user_info.get('email')})")
            st.image(user_info.get("picture"), width=100)

            if st.button("Logout"):
                clear_creds_cookie()
                st.success("Logged out successfully.")
                st.rerun()
        else:
            st.warning("Session expired or invalid. Logging out...")
            clear_creds_cookie()
            st.rerun()
    else:
        st.info("You are not logged in.")
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline')
        st.markdown(f"""<a href="{auth_url}"><button>Login with Google</button></a>""", unsafe_allow_html=True)

# Run the app
if __name__ == "__main__":
    main()
