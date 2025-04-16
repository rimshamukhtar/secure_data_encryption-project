import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# -------------------------------
# ✅ Fixed Fernet key for encryption (Only for development)
# -------------------------------
KEY = b'X7ydmLPuopIbdcMm5GJpkIs8chIzKVKBLFqiJm5ow1Q='  # 32-byte key
cipher = Fernet(KEY)

# -------------------------------
# ✅ Session state for persistent storage during reruns
# -------------------------------
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

stored_data = st.session_state.stored_data

# 🔐 Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# 🔐 Encrypt user data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# 🔓 Decrypt if passkey is correct
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    if encrypted_text in stored_data:
        if stored_data[encrypted_text]["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
        else:
            st.session_state.failed_attempts += 1
            return None
    else:
        return None

# 🔑 Login handler
def handle_login():
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")

# -------------------------------
# Streamlit App UI Starts Here
# -------------------------------

st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📌 Navigation", menu)

# 🏠 Home Page
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Store and retrieve your data securely using passkeys and encryption.")

# 📝 Store Data Page
elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)
            stored_data[encrypted_text] = {"passkey": hashed_passkey}
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Both fields are required!")

# 🔍 Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decrypted Data:")
                st.code(result)
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Redirecting to Login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please fill both fields!")

# 🔐 Login Page
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    handle_login()
