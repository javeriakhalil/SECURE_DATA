import streamlit as st
 from cryptography.fernet import Fernet, InvalidToken
 import base64
 import hashlib
 
 # ----------------------------- Helper Functions -----------------------------
 
 def generate_key(passkey: str) -> bytes:
     """Generate a Fernet-compatible key from a passkey"""
     key = hashlib.sha256(passkey.encode()).digest()
     return base64.urlsafe_b64encode(key)
 
 def encrypt_message(message: str, passkey: str) -> str:
     """Encrypt the message and return it as a string"""
     key = generate_key(passkey)
     fernet = Fernet(key)
     return fernet.encrypt(message.encode()).decode()
 
 def decrypt_message(token: str, passkey: str) -> str:
     """Decrypt the encrypted string"""
     key = generate_key(passkey)
     fernet = Fernet(key)
     return fernet.decrypt(token.encode()).decode()
 
 # ----------------------------- Session Initialization -----------------------------
 
 if "storage" not in st.session_state:
     st.session_state.storage = {}  # Stores: {identifier: encrypted_data}
 
 if "attempts" not in st.session_state:
     st.session_state.attempts = 0
 
 if "authorized" not in st.session_state:
     st.session_state.authorized = True
 
 # ----------------------------- Reauthorization Page -----------------------------
 
 def login_page():
     st.error("🔒 Too many failed attempts. Please reauthorize to continue.")
     pwd = st.text_input("Re-enter Admin Passcode:", type="password")
     if pwd == "admin123":  # Change this to your preferred admin password
         st.session_state.attempts = 0
         st.session_state.authorized = True
         st.success("✅ Access Restored.")
     elif pwd:
         st.warning("❌ Incorrect passcode.")
 
 # ----------------------------- Main Interface -----------------------------
 
 def main_interface():
     st.title("🔐 Secure In-Memory Data Vault")
 
     option = st.radio("Choose Action", ["Store Data", "Retrieve Data"])
 
     if option == "Store Data":
         st.subheader("📝 Store Secret")
         name = st.text_input("Identifier (e.g., Note name)")
         data = st.text_area("Secret Data")
         passkey = st.text_input("Passkey to lock data", type="password")
 
         if st.button("Encrypt and Store"):
             if name and data and passkey:
                 encrypted = encrypt_message(data, passkey)
                 st.session_state.storage[name] = encrypted
                 st.success(f"✅ Data saved under '{name}'.")
             else:
                 st.warning("⚠️ All fields are required.")
 
     elif option == "Retrieve Data":
         st.subheader("🔍 Retrieve Secret")
         if not st.session_state.storage:
             st.info("ℹ️ No data stored yet.")
             return
 
         name = st.selectbox("Select Identifier", list(st.session_state.storage.keys()))
         passkey = st.text_input("Enter Passkey", type="password")
 
         if st.button("Decrypt and Show"):
             if name and passkey:
                 try:
                     encrypted_data = st.session_state.storage[name]
                     decrypted = decrypt_message(encrypted_data, passkey)
                     st.success("🔓 Decryption successful!")
                     st.code(decrypted)
                     st.session_state.attempts = 0  # Reset on success
                 except InvalidToken:
                     st.session_state.attempts += 1
                     st.error("❌ Invalid passkey.")
                     if st.session_state.attempts >= 3:
                         st.session_state.authorized = False
 
 # ----------------------------- Application Flow -----------------------------
 
 if not st.session_state.authorized:
     login_page()
 else:
     main_interface()