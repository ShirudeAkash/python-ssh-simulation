# 🖥️ Mini SSH Simulator

A lightweight Python project that simulates the **core ideas of SSH**:  
- Client–server communication over TCP sockets  
- Username & password authentication  
- Secure channel established via **Diffie–Hellman (X25519)** key exchange  
- Encrypted command execution using **Fernet (AES)**  

⚠️ This is **for learning purposes only**. It is **not** a replacement for real SSH and should not be used in production.

---

## 🚀 Features
- 🔑 Encrypted client–server communication  
- 👤 Simple username/password authentication  
- 🖥 Remote command execution (like a minimal shell)  
- 🔒 Symmetric session key derived via **HKDF** from ECDH shared secret  
- ✨ Clean Python-only implementation (no external servers needed)  

---

## 📂 Project Structure
```
mini-ssh-simulator/
│── ssh_server_enc.py   # Encrypted server
│── ssh_client_enc.py   # Encrypted client
│── README.md           # Project docs
```

---

## ⚡ Requirements
- Python 3.8+  
- [cryptography](https://pypi.org/project/cryptography/)  

Install dependencies:
```bash
pip install cryptography
```

---

## ▶️ Usage

### 1. Start the server
```bash
python ssh_server_enc.py
```

### 2. Start the client in another terminal
```bash
python ssh_client_enc.py
```

### 3. Authenticate
- Username: `user`  
- Password: `pass123`  

(You can change these in the server code.)

### 4. Run commands
```bash
ssh> dir      # Windows
ssh> ls       # Linux/macOS (if server uses PowerShell or bash)
ssh> whoami
ssh> exit     # quit session
```

---

## 🔍 How It Works
1. Client and server exchange **X25519 public keys**.  
2. Both derive a shared secret → expanded into a **32-byte session key** using HKDF.  
3. A **Fernet cipher** (AES + HMAC) encrypts all communication.  
4. The server prompts for **username/password** (simulating SSH login).  
5. Once authenticated, the client can send commands → executed on server → results encrypted and sent back.  

---

## 📌 Limitations
- No host key verification (vulnerable to MITM).  
- No support for public-key authentication.  
- No terminal emulation or multiple sessions.  
- Encryption is **session-only** (no rekeying).  
- Educational toy project — **do not use for real security**.  

---

## 🛠 Future Improvements
- Add **server host keys** & client verification  
- Replace password login with **public/private key authentication**  
- Add replay protection with sequence numbers  
- Support file transfer (mini SFTP-like demo)  

