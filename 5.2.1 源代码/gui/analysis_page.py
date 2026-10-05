from PyQt6.QtCore import QThreadPool
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.collision_analysis import (
    AllPlaintextsSummary,
    PlaintextCollisionResult,
    analyze_all_plaintexts,
    analyze_plaintext,
)
from gui.workers import FunctionWorker


class AnalysisPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.thread_pool = QThreadPool.globalInstance()

        self.plaintext_input = QLineEdit()
        self.plaintext_input.setPlaceholderText("8 bits, e.g. 00000000")

        self.single_button = QPushButton("Analyze This Plaintext")
        self.all_button = QPushButton("Analyze All 256 Plaintexts")

        self.single_button.clicked.connect(self.analyze_single)
        self.all_button.clicked.connect(self.analyze_all)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Plaintext:"))
        controls.addWidget(self.plaintext_input)
        controls.addWidget(self.single_button)
        controls.addWidget(self.all_button)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)

        self.result = QTextEdit()
        self.result.setReadOnly(True)
        self.result.setPlaceholderText(
            "Collision statistics and key groups will appear here."
        )

        layout = QVBoxLayout(self)
        title = QLabel("Key / Ciphertext Collision Analysis")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        layout.addLayout(controls)
        layout.addWidget(self.progress)
        layout.addWidget(self.result, 1)

    def analyze_single(self) -> None:
        self._set_busy(True)
        self.progress.setValue(0)
        self.result.clear()
        worker = FunctionWorker(analyze_plaintext, self.plaintext_input.text())
        worker.signals.finished.connect(self._show_single_result)
        worker.signals.error.connect(self._show_error)
        self.thread_pool.start(worker)

    def analyze_all(self) -> None:
        self._set_busy(True)
        self.progress.setValue(0)
        self.result.setPlainText("Analyzing 256 plaintexts × 1024 keys...")
        worker = FunctionWorker(analyze_all_plaintexts, supports_progress=True)
        worker.signals.progress.connect(self.progress.setValue)
        worker.signals.finished.connect(self._show_all_result)
        worker.signals.error.connect(self._show_error)
        self.thread_pool.start(worker)

    def _set_busy(self, busy: bool) -> None:
        self.single_button.setEnabled(not busy)
        self.all_button.setEnabled(not busy)

    def _show_single_result(self, result: PlaintextCollisionResult) -> None:
        self._set_busy(False)
        self.progress.setValue(100)

        lines = [
            f"Plaintext                    : {result.plaintext}",
            f"Keys checked                 : 1024",
            f"Distinct ciphertexts         : {result.distinct_ciphertexts}",
            f"Ciphertexts with >1 key      : {result.collision_ciphertexts}",
            f"Max keys for one ciphertext  : {result.max_keys_for_one_ciphertext}",
            "",
            "Ciphertext -> matching keys (collision groups only)",
            "----------------------------------------------------",
        ]

        for ciphertext, keys in result.ciphertext_to_keys.items():
            if len(keys) > 1:
                lines.append(f"{ciphertext} ({len(keys)} keys)")
                lines.append("  " + ", ".join(keys))

        self.result.setPlainText("\n".join(lines))

    def _show_all_result(self, result: AllPlaintextsSummary) -> None:
        self._set_busy(False)
        self.progress.setValue(100)

        lines = [
            "Complete plaintext-space analysis",
            "--------------------------------",
            f"Plaintexts analyzed               : {result.total_plaintexts}",
            f"Total encryptions                 : {result.total_encryptions}",
            f"Plaintexts with collisions        : {result.plaintexts_with_collisions}",
            f"Min distinct ciphertexts / P      : {result.min_distinct_ciphertexts}",
            f"Max distinct ciphertexts / P      : {result.max_distinct_ciphertexts}",
            f"Average distinct ciphertexts / P  : {result.average_distinct_ciphertexts:.2f}",
            f"Global max keys for one C         : {result.global_max_keys_for_one_ciphertext}",
            f"Elapsed                           : {result.elapsed_seconds:.6f} s",
            "",
            "Per-plaintext summary:",
            "P         distinct-C   collision-C   max-keys-for-one-C",
        ]

        for row in result.per_plaintext:
            lines.append(
                f"{row['plaintext']}   "
                f"{row['distinct_ciphertexts']:>10}   "
                f"{row['collision_ciphertexts']:>11}   "
                f"{row['max_keys_for_one_ciphertext']:>18}"
            )

        self.result.setPlainText("\n".join(lines))

    def _show_error(self, message: str) -> None:
        self._set_busy(False)
        self.progress.setValue(0)
        self.result.clear()
        QMessageBox.warning(self, "Analysis failed", message)
