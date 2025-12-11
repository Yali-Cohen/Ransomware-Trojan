# Ransomware-Trojan
# Educational Ransomware Trojan (Python)

> ⚠️ **Educational / Lab Use Only**  
> This project implements a *simulated* ransomware-style Trojan for learning and research purposes only.  
> **Do not** use, deploy or modify this code against any system you do not fully own and control.  
> Misuse of this code may be illegal and unethical.

---

## 📌 Project Overview

This project was built as a cryptography and cyber–security learning exercise.

It simulates the core flow of a ransomware attack in a **controlled lab environment**:

1. A **client** connects securely to a **server** over TLS.
2. The server sends a **base password** to the client.
3. The client derives a **strong symmetric key** from that password using a KDF and encrypts all files in a local `test_folder`.
4. The client sends the derived key back to the server.
5. The server **re-encrypts** and stores the key securely in a database.
6. After a simulated “payment” step, the server returns the decryption key and a **decryptor tool** to the client.
7. The victim can then use the decryptor GUI to recover the files in `test_folder`.

The goal of the project is to understand:

- How real-world ransomware might structure its **key management**.
- How **crypto**, **networking** and **GUI** components work together.
- What defenders should look for and protect against.

---

## 🧩 Components

### 1. Server (`server.py`)

The server:

- Listens on `HOST:PORT` and accepts a TLS-secured TCP connection.
- Uses a self-signed certificate (`cert.pem` / `key.pem`) loaded via `ssl.SSLContext`.
- Sends a hard-coded **base password** to the client:
  ```python
  password_text = "YaliTheSigmaBoy123"
Receives the derived encryption key from the client.

Protects that key using a master key stored in an environment variable:

bash
Copy code
MASTER_KEY=...
Uses cryptography.fernet.Fernet to:

Encrypt the client’s encryption key with the MASTER_KEY.

Store the encrypted key in a local SQLite database (encryption_key.db).

Later:

Reads the encrypted key back from the DB.

Decrypts it with the MASTER_KEY.

Sends the decrypted key length (4 bytes, big-endian) + the key itself to the client.

Streams a compiled decrypt_folders.exe binary to the client over the same TLS connection.

This models a simple key hierarchy:

MASTER_KEY – long-term key (never stored in the database).

Client key – per-"victim" key, stored only in encrypted form.

2. Client (client.py)
The client simulates the Trojan running on the victim machine.

Main responsibilities:

Establishes a TLS client connection to the server using:

python
Copy code
ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
with cert.pem pinned for server verification.

Receives a password from the server and derives a strong symmetric key with PBKDF2:

python
Copy code
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA1(),
    length=32,
    salt=salt,
    iterations=480000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
This key is then used with Fernet to encrypt files.

Encrypts all files under a local test_folder:

Uses Fernet for symmetric file encryption.

Recursively walks the directory and overwrites files with ciphertext.

Sends the derived encryption key back to the server.

Shows a simple ransom note using tkinter.messagebox.

Waits for the server to:

Send the length of the decryption key (4 bytes, struct.pack("!I", len(key))).

Send the raw decryption key bytes.

Stream the decrypt_folders.exe binary.

Copies the received decryption key to the clipboard automatically for convenience:

python
Copy code
root = tk.Tk()
root.withdraw()

def copy_to_clipboard(text: str):
    root.clipboard_clear()
    root.clipboard_append(text.strip())
    root.update()
Saves the received decryptor executable into test_folder/decrypt_folders.exe and runs it via subprocess.run.

To support both .py and compiled .exe (PyInstaller), the client uses:

python
Copy code
def get_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
This ensures test_folder is resolved correctly when running as a standalone executable.

3. Decryptor GUI (decrypt_folders.py)
The decryptor is a standalone GUI tool built with PySide6.

Features:

Simple window titled “Folder Decryptor”.

User inputs the decryption key.

On button click, it:

Resolves the same test_folder directory using the same get_base_dir logic.

Creates a Fernet instance with the user-provided key.

Recursively walks through test_folder and tries to decrypt each file.

If a file was not encrypted with that key, it prints a clear error and skips it.

This tool is what the “victim” uses to get files back after the key is released.

🔐 Security & Design Concepts Demonstrated
This project intentionally focuses on defensive learning and crypto hygiene:

Key derivation with PBKDF2 + salt
– Shows why using raw passwords as keys is unsafe.

Symmetric encryption with Fernet
– Authenticated encryption (integrity + confidentiality).

Transport security with TLS (SSL)
– Even if someone sniffs the network, they cannot see the keys.

Key management & storage
– Separating a master key (env var) from per-“victim” keys (DB, encrypted).

Protocol framing over TCP
– Using struct.pack("!I", key_len) and recv_exact() to build a robust, length-prefixed protocol over a stream-oriented socket.

EXE vs. script path handling
– Handling sys.executable vs. __file__ for PyInstaller-built binaries.

From a defender’s perspective, this project helps think about:

How to detect unusual outbound connections from “innocent” executables.

Why file-system and process monitoring (EDR) is important.

Why key material should never be left lying around in plaintext.

⚙️ Technologies Used
Python 3

cryptography (Fernet, PBKDF2HMAC)

sqlite3 (local key storage)

ssl / socket / struct (network & TLS)

Tkinter (simple messageboxes & clipboard)

PySide6 (Qt-based GUI for decryptor)

PyInstaller (to package client & decryptor as Windows executables)

🚀 How to Run (Lab Setup)
⚠️ Only use a test folder with non-important files.

Generate or prepare cert.pem and key.pem for TLS.

Set the MASTER_KEY environment variable on the server machine:

bash
Copy code
set MASTER_KEY=your-32-byte-secret-here
Start the server:

bash
Copy code
python server.py
On the “victim” machine:

Make sure there is a test_folder next to the client executable / script.

Run the client.py (or compiled GTA VI.exe).

After encryption:

The client shows a ransom message.

The server waits for manual “payment” confirmation in the console.

Once confirmed, the server sends back the decryption key and the decrypt_folders.exe file.

The client:

Copies the decryption key to the clipboard.

Saves and runs decrypt_folders.exe inside test_folder.

The user pastes the key into the decryptor GUI and decrypts the files.

📚 What I Learned
Working on this project helped me:

Get hands-on experience with modern Python cryptography libraries (cryptography, Fernet, PBKDF2HMAC) and understand how to correctly derive and handle symmetric keys.

Understand the principles of key management, including using a long-term MASTER_KEY, encrypting per-victim keys, and storing only encrypted material in a database.

Practice building a small but complete application-level protocol on top of TLS, including length-prefix framing and reliable reads over a stream-oriented socket (TCP).

Learn how to package Python tools into standalone Windows executables with PyInstaller, and how to correctly handle paths with sys.executable vs. __file__.

Build simple GUI tools with Tkinter and PySide6 to simulate attacker and victim flows in a realistic way.

Deepen my understanding of the ransomware kill-chain from both an attacker’s implementation perspective and a defender’s point of view (what needs to be monitored and protected).

🚫 Legal & Ethical Notice
This repository is for:

Education

Research

Interview preparation

Understanding how to defend against ransomware-style attacks

It must:

Only be run on your own machines,

Only against test folders you create yourself,

Only in a controlled lab environment.

You are solely responsible for complying with all applicable laws and regulations.
The author(s) of this code do not take any responsibility for misuse.
