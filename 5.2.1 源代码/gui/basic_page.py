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

from core.cipher import decrypt_block_with_trace, encrypt_block_with_trace


def _format_round(name: str, key_name: str, data: dict) -> list[str]:
    f = data["f"]
    return [
        f"{name} ({key_name})",
        f"  input       : {data['input']}",
        f"  L | R       : {data['left']} | {data['right']}",
        f"  EP(R)       : {f['ep']}",
        f"  EP(R) XOR K : {f['ep_xor_key']}",
        f"  S1 in/out   : {f['sbox1_input']} -> {f['sbox1_output']}",
        f"  S2 in/out   : {f['sbox2_input']} -> {f['sbox2_output']}",
        f"  S1||S2      : {f['sbox_combined']}",
        f"  SP          : {f['sp']}",
        f"  L XOR F     : {data['left_xor_f']}",
        f"  output      : {data['output']}",
    ]


def format_trace(trace: dict) -> str:
    ks = trace["key_schedule"]
    lines = [
        "=== Key Schedule ===",
        f"Key          : {ks['original_key']}",
        f"P10          : {ks['p10']}",
        f"P10 halves   : {ks['p10_left']} | {ks['p10_right']}",
        f"LeftShift^1  : {ks['left_shift_1']}",
        f"K1 = P8(...) : {ks['k1']}",
        f"LeftShift^2  : {ks['left_shift_2']}",
        f"K2 = P8(...) : {ks['k2']}",
        "",
        "=== Block Processing ===",
        f"Input        : {trace['input']}",
        f"IP           : {trace['ip']}",
        "",
    ]
    lines.extend(_format_round("Round 1", trace["round1_key"], trace["round1"]))
    lines.extend(["", f"SW           : {trace['sw']}", ""])
    lines.extend(_format_round("Round 2", trace["round2_key"], trace["round2"]))
    lines.extend(["", f"IP^-1 / Final: {trace['ip_inv']}"])
    return "\n".join(lines)


class BasicPage(QWidget):
    def __init__(self) -> None:
        super().__init__()

        self.block_input = QLineEdit()
        self.block_input.setPlaceholderText("8 bits, e.g. 10101010")

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("10 bits, e.g. 1010000010")

        self.output = QLineEdit()
        self.output.setReadOnly(True)

        encrypt_button = QPushButton("Encrypt")
        decrypt_button = QPushButton("Decrypt")
        encrypt_button.clicked.connect(self.encrypt)
        decrypt_button.clicked.connect(self.decrypt)

        button_row = QHBoxLayout()
        button_row.addWidget(encrypt_button)
        button_row.addWidget(decrypt_button)

        form = QFormLayout()
        form.addRow("8-bit input:", self.block_input)
        form.addRow("10-bit key:", self.key_input)
        form.addRow("Output:", self.output)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("The S-DES execution trace will appear here.")

        layout = QVBoxLayout(self)
        title = QLabel("Basic S-DES Encryption / Decryption")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        layout.addLayout(form)
        layout.addLayout(button_row)
        layout.addWidget(QLabel("Execution details"))
        layout.addWidget(self.details, 1)

    def _run(self, decrypt: bool) -> None:
        # A failed operation must not leave a previous successful result visible.
        self.output.clear()
        self.details.clear()
        try:
            if decrypt:
                result, trace = decrypt_block_with_trace(
                    self.block_input.text(),
                    self.key_input.text(),
                )
            else:
                result, trace = encrypt_block_with_trace(
                    self.block_input.text(),
                    self.key_input.text(),
                )
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid input", str(exc))
            return

        self.output.setText(result)
        self.details.setPlainText(format_trace(trace))

    def encrypt(self) -> None:
        self._run(decrypt=False)

    def decrypt(self) -> None:
        self._run(decrypt=True)
