import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
import pandas as pd

def hash_passkey(passkey):
    """Hash the passkey using SHA-256."""
    return hashlib.sha256(passkey.encode()).hexdigest()

def get_fernet_key(passkey):
    """Derive a Fernet key from the passkey."""
    # Hash the passkey and take first 32 bytes, then base64 encode
    passkey_hash = hashlib.sha256(passkey.encode()).digest()
    key = base64.urlsafe_b64encode(passkey_hash[:32])
    return key

def encrypt_data(data, passkey):
    """Encrypt data using Fernet with a key derived from the passkey."""
    key = get_fernet_key(passkey)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

def decrypt_data(encrypted_data, passkey):
    """Decrypt data using Fernet with a key derived from the passkey."""
    key = get_fernet_key(passkey)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted_data).decode()
        return decrypted, True
    except InvalidToken:
        return "Incorrect passkey!", False

def initialize_session_state():
    """Initialize session state variables."""
    if "stored_data" not in st.session_state:
        st.session_state.stored_data = {}
    if "page" not in st.session_state:
        st.session_state.page = "home"
    if "failed_attempts" not in st.session_state:
        st.session_state.failed_attempts = 0
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = True

def home_page():
    """Render the Home page."""
    st.title("Secure Data Encryption System")
    st.write("Store and retrieve sensitive data securely using a passkey.")
    
    if st.button("Store New Data"):
        st.session_state.page = "insert"
        st.rerun()
    if st.button("Retrieve Data"):
        st.session_state.page = "retrieve"
        st.rerun()

    
    # Display stored data IDs
    if st.session_state.stored_data:
        st.header("Stored Data IDs")
        data_ids = list(st.session_state.stored_data.keys())
        st.write(data_ids)

def insert_page():
    """Render the Insert Data page."""
    st.title("Store New Data")
    data_id = st.text_input("Enter a unique data ID (e.g., user1_data):")
    data = st.text_area("Enter the data to encrypt:")
    passkey = st.text_input("Enter a passkey:", type="password")
    
    if st.button("Store Data"):
        if not data_id or not data or not passkey:
            st.error("Please fill in all fields.")
        elif data_id in st.session_state.stored_data:
            st.error("Data ID already exists. Choose a different ID.")
        else:
            # Encrypt data and store
            encrypted_data = encrypt_data(data, passkey)
            hashed_passkey = hash_passkey(passkey)
            st.session_state.stored_data[data_id] = {
                "encrypted_text": encrypted_data,
                "passkey": hashed_passkey
            }
            st.success("Data stored successfully!")
            st.session_state.page = "home"
            st.rerun()

    
    if st.button("Back to Home"):
        st.session_state.page = "home"
        st.rerun()


def retrieve_page():
    """Render the Retrieve Data page."""
    st.title("Retrieve Data")
    data_id = st.text_input("Enter the data ID:")
    passkey = st.text_input("Enter the passkey:", type="password")
    
    st.write(f"Failed attempts: {st.session_state.failed_attempts}/3")
    
    if st.button("Retrieve Data"):
        if not data_id or not passkey:
            st.error("Please fill in all fields.")
        elif data_id not in st.session_state.stored_data:
            st.error("Data ID not found.")
        else:
            # Verify passkey
            stored = st.session_state.stored_data[data_id]
            if hash_passkey(passkey) == stored["passkey"]:
                # Decrypt data
                decrypted_data, success = decrypt_data(stored["encrypted_text"], passkey)
                if success:
                    st.success("Data retrieved successfully!")
                    st.write("Decrypted Data:")
                    st.write(decrypted_data)
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    st.error(decrypted_data)
            else:
                st.session_state.failed_attempts += 1
                st.error("Incorrect passkey!")
            
            # Check for too many failed attempts
            if st.session_state.failed_attempts >= 3:
                st.session_state.authenticated = False
                st.session_state.page = "login"
                st.rerun()

    
    if st.button("Back to Home"):
        st.session_state.page = "home"
        st.rerun()


def login_page():
    """Render the Login page for reauthorization."""
    st.title("Login Required")
    st.write("Too many failed attempts. Please reauthorize.")
    
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")
    
    if st.button("Login"):
        # Simple hardcoded credentials for demo
        if username == "admin" and password == "password123":
            st.success("Login successful!")
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.session_state.page = "retrieve"
            st.experimental_rerun()
        else:
            st.error("Invalid username or password.")
    
    if st.button("Back to Home"):
        st.session_state.page = "home"
        st.experimental_rerun()

def main():
    """Main function to initialize and render the app."""
    # Initialize session state
    initialize_session_state()
    
    # Set page config
    st.set_page_config(page_title="Secure Data System", page_icon="🔒")
    
    # Render pages based on session state
    if not st.session_state.authenticated:
        login_page()
    elif st.session_state.page == "home":
        home_page()
    elif st.session_state.page == "insert":
        insert_page()
    elif st.session_state.page == "retrieve":
        retrieve_page()
    elif st.session_state.page == "login":
        login_page()

if __name__ == "__main__":
    main()