# 🔐 Secure Data Manager

A secure, Streamlit-based web app for safely encrypting, storing, retrieving, and deleting sensitive information using custom passkeys. Designed with simplicity, security, and local privacy in mind.

---

## 🚀 Features

- ✅ **Master Login** authentication (`admin123`)
- 🔐 **Encrypt & Store Data** with your own passkey
- 🔎 **Retrieve Data** using a unique ID + correct passkey
- 🗑️ **Delete Data** securely by verifying the passkey
- 🛡️ **Brute-force protection** with timed lockout
- 💾 Stores data locally in `data_store.json`
- 🎯 Minimal, user-friendly UI with sidebar navigation
- 🔒 Built with modern encryption (`cryptography.fernet`)

---

## 📦 Tech Stack

- **Python 3**
- **Streamlit** for UI
- **Cryptography** for encryption
- Standard libraries: `json`, `os`, `uuid`, `hashlib`, `base64`, `time`

---





