PROJECT REPORT: ADVANCED ENCRYPTION TOOL

Technology: Python 3, Tkinter, AES-256 (pycryptodome)

DESCRIPTION:
------------
This project implements a secure file encryption and decryption tool using AES-256 encryption. It features a GUI for user interaction and ensures the encrypted files are secure and unreadable without the correct key.

FEATURES:
---------
- AES-256 Encryption (CBC Mode)
- Secure Padding and IV
- File Encryption and Decryption
- GUI with Tkinter
- Password protected

REQUIREMENTS:
-------------
- Python 3.x
- pycryptodome

HOW TO RUN:
-----------
1. Run `main.py`
2. Browse and select the file
3. Enter a 32-character password
4. Click "Encrypt" or "Decrypt"


## 📸 Screenshot

![Screenshot](https://i.postimg.cc/zXHT9Ktn/Screenshot.png)


OUTPUT:
-------
Encrypted file: `yourfile.txt.enc`
Decrypted file: `yourfile.txt.dec`





SECURITY NOTES:
---------------
- Password must be exactly 32 characters (AES-256 key length)
- Encrypted file uses a random IV
- Files are unreadable without correct password



