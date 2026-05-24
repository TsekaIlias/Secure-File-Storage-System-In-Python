# =========================================
# Secure File Storage System
# =========================================

A Python-based secure file storage application that demonstrates modern cybersecurity concepts such as:

- Password hashing with salt
- OTP-based user registration
- RSA public/private key cryptography
- AES-GCM file encryption
- Digital signatures
- Nonce-based replay attack prevention
- Secure file upload/download system
- Command Line Interface (CLI)

This project was developed as part of a cybersecurity / cryptography assignment.

---

# ========================
# Features
# ========================

## [ Authentication ]
- Secure password hashing using `PBKDF2-HMAC-SHA256`
- Random salt generation for each user
- Safe password verification using `secrets.compare_digest`

---

## [ OTP-Based Registration ]
- Admin generates One-Time Passwords (OTP)
- OTPs are:
  - Single-use
  - Stored securely
  - Time-tracked

---

## [ RSA Key Pair Generation ]
Each registered user automatically receives:
- RSA Private Key
- RSA Public Key

Keys are stored in the `keys/` directory.

---

## [ Secure File Encryption ]
Files are encrypted using:
- `AES-GCM (256-bit)` symmetric encryption

This provides:
- Confidentiality
- Integrity
- Authentication

---

## [ Digital Signatures ]
Uploaded files are digitally signed using:
- RSA-PSS
- SHA-256 hashing

This guarantees:
- File authenticity
- Data integrity
- Sender verification

---

## [ Replay Attack Protection ]
The system prevents replay attacks using:
- Unique cryptographic nonces
- Nonce validation database

---

## [ Secure File Storage ]
Uploaded files are stored as:
- Encrypted binary file (`.enc`)
- Metadata JSON file (`.json`)

Metadata includes:
- Encryption key
- AES nonce
- Digital signature
- Upload timestamp
- Uploader information

---

# ========================
# Technologies Used
# ========================

- Python 3
- Cryptography Library
- AES-GCM
- RSA
- SHA-256
- JSON
- pathlib

---

# ========================
# Project Structure
# ========================

```bash
project/
│
├── project2.py
├── users.json
├── nonces.json
├── otp_store.json
│
├── keys/
│   ├── user_private.pem
│   └── user_public.pem
│
└── secure_storage/
    ├── file.enc
    └── file.json
```

---

# ========================
# Installation
# ========================

## 1) Clone the repository

```bash
git clone https://github.com/yourusername/secure-file-storage.git
cd secure-file-storage
```

---

## 2) Install dependencies

```bash
pip install cryptography
```

---

# ========================
# Running the Program
# ========================

```bash
python project2.py
```

---

# ========================
# Menu Options
# ========================

```text
1. Register (OTP)
2. Login
3. Upload File
4. Download File
0. Exit
```

---

# ========================
# Example Workflow
# ========================

## Admin Issues OTP

```python
admin_issue_otp("john")
```

Example OTP:

```text
AB12CD34
```

---

## User Registration

```text
Username: john
OTP: AB12CD34
Password: mypassword
```

---

## Login

```text
Username: john
Password: mypassword
```

---

## Upload File

```text
Path: test.txt
```

The system will:
1. Sign the file
2. Generate a nonce
3. Encrypt the file
4. Store encrypted data securely

---

## Download File

```text
Filename: test.txt
```

The system will:
1. Decrypt the file
2. Verify the digital signature
3. Restore the original file

---

# ========================
# Security Concepts Implemented
# ========================

| Security Feature | Implementation |
|---|---|
| Password Hashing | PBKDF2-HMAC-SHA256 |
| Salt | Random 16-byte salt |
| Encryption | AES-GCM 256 |
| Public Key Crypto | RSA 2048 |
| Digital Signatures | RSA-PSS |
| Replay Protection | Nonce validation |
| Secure Comparison | `secrets.compare_digest()` |

---

# ========================
# Important Notes
# ========================

- This project is designed for educational purposes.
- Encryption keys are stored locally in metadata files.

In production systems:
- Keys should never be stored alongside encrypted data.
- Secure key management systems should be used.
- OTP expiration should be implemented.

---

# ========================
# Possible Improvements
# ========================

- Add OTP expiration time
- Add GUI interface
- Add database support
- Add user roles & permissions
- Add encrypted key storage
- Add file sharing system
- Add logging and monitoring
- Add JWT/session authentication

---

# ========================
# Learning Outcomes
# ========================

This project demonstrates practical usage of:
- Applied cryptography
- Authentication systems
- Secure file handling
- Digital signatures
- Secure software design
- Anti-replay protection mechanisms

---

# ========================
# Author
# ========================

Developed as a cybersecurity / cryptography assignment project.
