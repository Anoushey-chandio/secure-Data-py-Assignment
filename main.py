import streamlit as st
import hashlib, json, base64, time, os, uuid
from cryptography.fernet import Fernet

# --- File Path ---
FILE_PATH = "data_store.json"

# --- Utilities ---
def load_data():
    return json.load(open(FILE_PATH)) if os.path.exists(FILE_PATH) else {}

def save_data(data):
    json.dump(data, open(FILE_PATH, "w"))

def hash_key(p):
    return hashlib.sha256(p.encode()).hexdigest()

def get_fernet(p):
    key = base64.urlsafe_b64encode(hashlib.sha256(p.encode()).digest()[:32])
    return Fernet(key)

def encrypt(txt, p):
    return get_fernet(p).encrypt(txt.encode()).decode()

def decrypt(txt, p):
    try: return get_fernet(p).decrypt(txt.encode()).decode()
    except: return None

# --- Session Setup ---
ss = st.session_state
ss.page = ss.get("page", "Home")
ss.attempts = ss.get("attempts", 0)
ss.last_attempt = ss.get("last_attempt", 0)
ss.store = ss.get("store", load_data())

# --- Sidebar Nav ---
st.sidebar.title("🔐 Navigation")
ss.page = st.sidebar.radio("Go to", ["Home", "Login", "Store Data", "Retrieve Data", "Delete Data"], index=["Home", "Login", "Store Data", "Retrieve Data", "Delete Data"].index(ss.page))

# --- Header ---
st.title("🔐 Secure Data Manager")

# --- Home ---
if ss.page == "Home":
    st.header("🏠 Home")
    st.success(f"Total stored items: {len(ss.store)}")

# --- Login ---
elif ss.page == "Login":
    st.header("🔐 Login")
    if ss.attempts >= 3 and time.time() - ss.last_attempt < 10:
        st.warning(f"Wait {int(10 - (time.time() - ss.last_attempt))} seconds")
    else:
        pw = st.text_input("Enter Master Password", type="password")
        if st.button("Login"):
            if pw == "admin123":
                ss.attempts = 0
                st.success("Logged in!")
                ss.page = "Home"
                st.rerun()
            else:
                ss.attempts += 1
                ss.last_attempt = time.time()
                st.error("Wrong password")

# --- Store Data ---
elif ss.page == "Store Data":
    st.header("📦 Store Data")
    txt = st.text_area("Enter Data")
    pk1 = st.text_input("Create Passkey", type="password")
    pk2 = st.text_input("Confirm Passkey", type="password")
    if st.button("Encrypt & Save"):
        if not txt or not pk1 or not pk2:
            st.error("All fields required")
        elif pk1 != pk2:
            st.error("Passkeys don't match")
        else:
            enc = encrypt(txt, pk1)
            data_id = str(uuid.uuid4())
            ss.store[data_id] = {"encrypted": enc, "passkey": hash_key(pk1)}
            save_data(ss.store)
            st.success("Saved!")
            st.code(data_id)

# --- Retrieve Data ---
elif ss.page == "Retrieve Data":
    st.header("🔍 Retrieve Data")
    st.info(f"Attempts left: {3 - ss.attempts}")
    data_id = st.text_input("Enter Data ID")
    pk = st.text_input("Enter Passkey", type="password")
    if st.button("Decrypt"):
        entry = ss.store.get(data_id)
        if not data_id or not pk:
            st.warning("All fields required")
        elif entry and hash_key(pk) == entry["passkey"]:
            dec = decrypt(entry["encrypted"], pk)
            if dec:
                st.success("Decrypted!")
                st.code(dec)
                ss.attempts = 0
            else:
                ss.attempts += 1
                ss.last_attempt = time.time()
                st.error("Wrong Passkey")
        else:
            ss.attempts += 1
            ss.last_attempt = time.time()
            st.error("Invalid ID or Passkey")

# --- Delete Data ---
elif ss.page == "Delete Data":
    st.header("🗑️ Delete Data")
    pk = st.text_input("Enter Passkey to Delete Data", type="password")
    if st.button("Delete"):
        # Find and delete the data matching the passkey
        deleted = False
        for data_id, entry in ss.store.items():
            if entry["passkey"] == hash_key(pk):
                del ss.store[data_id]
                save_data(ss.store)
                st.success("Data deleted successfully!")
                deleted = True
                break
        if not deleted:
            st.error("No data found with the provided passkey.")

# --- Footer ---
st.markdown("---")
st.caption("🔐 Developed by Anoushey Chandio using Streamlit")




