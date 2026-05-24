# 🔐 Secure File Storage System

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

# 📌 Features

## ✅ User Authentication
- Secure password hashing using `PBKDF2-HMAC-SHA256`
- Random salt generation for each user
- Safe password verification using `secrets.compare_digest`

---

## ✅ OTP-Based Registration
- Admin generates One-Time Passwords (OTP)
- OTPs are:
  - Single-use
  - Stored securely
  - Time-tracked

---

## ✅ RSA Key Pair Generation
Each registered user automatically receives:
- RSA Private Key
- RSA Public Key

Keys are stored in the `keys/` directory.

---

## ✅ Secure File Encryption
Files are encrypted using:
- `AES-GCM (256-bit)` symmetric encryption

This provides:
- Confidentiality
- Integrity
- Authentication

---

## ✅ Digital Signatures
Uploaded files are digitally signed using:
- RSA-PSS
- SHA-256 hashing

This guarantees:
- File authenticity
- Data integrity
- Sender verification

---

## ✅ Replay Attack Protection
The system prevents replay attacks using:
- Unique cryptographic nonces
- Nonce validation database

---

## ✅ Secure File Storage
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

# 🛠 Technologies Used

- Python 3
- Cryptography Library
- AES-GCM
- RSA
- SHA-256
- JSON
- pathlib

---

# 📂 Project Structure

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
