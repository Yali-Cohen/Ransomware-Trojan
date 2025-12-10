import os
import sys
from cryptography.fernet import Fernet
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QLineEdit, QPushButton, QLabel
)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Folder Decryptor")
        self.text_value = ""

        container = QWidget()
        layout = QVBoxLayout(container)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Enter Decryption Key")
        layout.addWidget(self.input)

        self.button = QPushButton("Decrypt Folders")
        self.button.clicked.connect(self.save_text)
        layout.addWidget(self.button)

        self.label = QLabel("Status: Waiting for input")
        layout.addWidget(self.label)

        self.setCentralWidget(container)

    def save_text(self):
        self.text_value = self.input.text().strip()
        path = os.path.join(os.getcwd(), "test_folder")
        self.label.setText(f"Status: Decrypting with key {self.text_value} on {path}")
        decryption_key = self.text_value.encode()
        print(f"Starting decryption in path: {path}")
        f = Fernet(decryption_key)
        decrypt_files_in_directory(path, f)


def read_file_data(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
    return data

def decrypt_data(ciphertext, f):
    plaintext = f.decrypt(ciphertext)
    return plaintext


def decrypt_file(file_path, f):
    encrypted_data = read_file_data(file_path)
    try:
        decrypted_data = decrypt_data(encrypted_data, f)
    except Exception as e:
        print(f"[-] Invalid token for file (probably not encrypted with this key): {file_path}")
        return 
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)
    print(f"[+] Decrypted file: {file_path}")
    return decrypted_data

def decrypt_files_in_directory(directory_path, f):
    all_filenames = os.listdir(directory_path)

    for filename in all_filenames:
        file_path = os.path.join(directory_path, filename)

        if os.path.isfile(file_path):
            decrypt_file(file_path, f)
            print(f"Decrypted file: {file_path}")
        else:
            decrypt_files_in_directory(file_path, f)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
