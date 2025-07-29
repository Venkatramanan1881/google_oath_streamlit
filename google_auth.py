import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import requests
import json

# === CONFIGURATION ===
CLIENT_SECRETS_FILE = "credentials.json"  # Path to your Google OAuth client secrets
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email"
]
COOKIE_ENCRYPTION_PASSWORD = "your-strong-16+char-password"  # 🔒 Keep this secret
REDIRECT_URI = "http://localhost:8501"  # Must match credentials.json

# === Initialize Encrypted Cookie Manager ===
cookies = EncryptedCookieManager(password=COOKIE_ENCRYPTION_PASSWORD)

if not cookies.ready():
    st.stop()  # Wait until cookies are fully loaded

# === Save Google Credentials to Cookie ===
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

# === Load Google Credentials from Cookie ===
def load_credentials_from_cookie():
    if "google_creds" not in cookies:
        return None
    creds_data = json.loads(cookies["google_creds"])
    return Credentials(
        token=creds_data["token"],
        refresh_token=creds_data["refresh_token"],
        token_uri=creds_data["token_uri"],
        client_id=creds_data["client_id"],
        client_secret=creds_data["client_secret"],
        scopes=creds_data["scopes"],
    )

# === Clear Cookie ===
def clear_creds_cookie():
    if "google_creds" in cookies:
        del cookies["google_creds"]
        cookies.save()

# === Authenticate User using OAuth2 ===
def authenticate_user():
    code = st.experimental_get_query_params().get("code", [None])[0]
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

    if code:
        try:
            flow.fetch_token(code=code)
            creds = flow.credentials
            save_credentials_to_cookie(creds)
            st.success("Authentication successful! Reloading...")
            st.experimental_set_query_params()  # Clear URL params
            st.rerun()
        except Exception as e:
            st.error(f"Failed to fetch token: {e}")
        return None
    else:
        auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline')
        st.markdown(f"""<meta http-equiv="refresh" content="0;URL='{auth_url}'" />""", unsafe_allow_html=True)
        st.stop()
    

# === Fetch User Profile Info ===
def fetch_user_info(creds):
    try:
        resp = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {creds.token}"}
        )

        if resp.status_code == 401:  # Token expired
            creds.refresh(requests.Request())
            save_credentials_to_cookie(creds)
            resp = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {creds.token}"}
            )

        if resp.status_code == 200:
            return resp.json()
        else:
            st.warning(f"Failed to fetch user info: {resp.status_code}")
            return None
    except Exception as e:
        st.error(f"Error during user info fetch: {e}")
        return None

# === MAIN APP ===
def main():
    st.title("🔐 Google Login with Encrypted Cookies")

    creds = load_credentials_from_cookie()

    if creds and creds.valid:
        user_info = fetch_user_info(creds)
        if user_info:
            st.success(f"Welcome {user_info.get('name')} ({user_info.get('email')})")
            st.image(user_info.get("picture"))
            if st.button("Logout"):
                clear_creds_cookie()
                st.success("Logged out successfully!")
                st.rerun()
        else:
            st.warning("Session expired or user info fetch failed.")
            clear_creds_cookie()
            st.rerun()
    else:
        
        st.info("You are not logged in.")
        if st.button("Login with Google"):
            authenticate_user()
            

if __name__ == "__main__":
    main()
