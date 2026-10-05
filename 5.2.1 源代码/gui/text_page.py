from PyQt6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.text_cipher import (
    bytes_to_binary,
    bytes_to_hex,
    decrypt_text_ascii,
    encrypt_text_ascii,
    hex_to_bytes,
)


class TextPage(QWidget):
    def __init__(self) -> None:
        super().__init__()

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("10 bits")

        self.plaintext = QTextEdit()
        self.plaintext.setPlaceholderText("ASCII plaintext")

        self.cipher_hex = QTextEdit()
        self.cipher_hex.setPlaceholderText("Ciphertext in hexadecimal form")

        self.cipher_binary = QTextEdit()
        self.cipher_binary.setReadOnly(True)

        self.recovered_text = QTextEdit()
        self.recovered_text.setReadOnly(True)

        encrypt_button = QPushButton("Encrypt Text")
        decrypt_button = QPushButton("Decrypt Hex")
        clear_button = QPushButton("Clear")

        encrypt_button.clicked.connect(self.encrypt)
        decrypt_button.clicked.connect(self.decrypt)
        clear_button.clicked.connect(self.clear)

        buttons = QHBoxLayout()
        buttons.addWidget(encrypt_button)
        buttons.addWidget(decrypt_button)
        buttons.addWidget(clear_button)

        form = QFormLayout()
        form.addRow("10-bit key:", self.key_input)

        layout = QVBoxLayout(self)
        title = QLabel("ASCII / Byte Encryption")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        layout.addLayout(form)
        layout.addWidget(QLabel("Plaintext (ASCII)"))
        layout.addWidget(self.plaintext)
        layout.addLayout(buttons)
        layout.addWidget(QLabel("Ciphertext (HEX)"))
        layout.addWidget(self.cipher_hex)
        layout.addWidget(QLabel("Ciphertext (Binary)"))
        layout.addWidget(self.cipher_binary)
        layout.addWidget(QLabel("Recovered plaintext"))
        layout.addWidget(self.recovered_text)

    def encrypt(self) -> None:
        self.cipher_hex.clear()
        self.cipher_binary.clear()
        self.recovered_text.clear()
        try:
            encrypted = encrypt_text_ascii(
                self.plaintext.toPlainText(),
                self.key_input.text(),
            )
        except ValueError as exc:
            QMessageBox.warning(self, "Unable to encrypt", str(exc))
            return

        self.cipher_hex.setPlainText(bytes_to_hex(encrypted))
        self.cipher_binary.setPlainText(bytes_to_binary(encrypted))
        self.recovered_text.clear()

    def decrypt(self) -> None:
        # Keep HEX as the user's input; discard only results from earlier runs.
        self.cipher_binary.clear()
        self.recovered_text.clear()
        try:
            ciphertext = hex_to_bytes(self.cipher_hex.toPlainText())
            recovered = decrypt_text_ascii(ciphertext, self.key_input.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Unable to decrypt", str(exc))
            return

        self.cipher_binary.setPlainText(bytes_to_binary(ciphertext))
        self.recovered_text.setPlainText(recovered)

    def clear(self) -> None:
        self.plaintext.clear()
        self.cipher_hex.clear()
        self.cipher_binary.clear()
        self.recovered_text.clear()
