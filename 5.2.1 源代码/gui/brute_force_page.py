from PyQt6.QtCore import QThreadPool
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.brute_force import BruteForceResult, brute_force
from gui.workers import FunctionWorker


class BruteForcePage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.thread_pool = QThreadPool.globalInstance()

        self.table = QTableWidget(1, 2)
        self.table.setHorizontalHeaderLabels(["Plaintext (8 bit)", "Ciphertext (8 bit)"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setItem(0, 0, QTableWidgetItem(""))
        self.table.setItem(0, 1, QTableWidgetItem(""))

        add_button = QPushButton("Add Pair")
        remove_button = QPushButton("Remove Selected")
        self.start_button = QPushButton("Start Brute Force")

        add_button.clicked.connect(self.add_pair)
        remove_button.clicked.connect(self.remove_selected)
        self.start_button.clicked.connect(self.start)

        row_buttons = QHBoxLayout()
        row_buttons.addWidget(add_button)
        row_buttons.addWidget(remove_button)
        row_buttons.addStretch(1)
        row_buttons.addWidget(self.start_button)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)

        self.result = QTextEdit()
        self.result.setReadOnly(True)
        self.result.setPlaceholderText(
            "All candidate keys and timing information will appear here."
        )

        layout = QVBoxLayout(self)
        title = QLabel("Brute-force Key Recovery")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        layout.addWidget(
            QLabel("Enter one or more known plaintext/ciphertext pairs.")
        )
        layout.addWidget(self.table)
        layout.addLayout(row_buttons)
        layout.addWidget(self.progress)
        layout.addWidget(self.result, 1)

    def add_pair(self) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(""))
        self.table.setItem(row, 1, QTableWidgetItem(""))

    def remove_selected(self) -> None:
        rows = sorted(
            {item.row() for item in self.table.selectedItems()},
            reverse=True,
        )
        for row in rows:
            self.table.removeRow(row)

        if self.table.rowCount() == 0:
            self.add_pair()

    def _read_pairs(self) -> list[tuple[str, str]]:
        pairs = []
        for row in range(self.table.rowCount()):
            p_item = self.table.item(row, 0)
            c_item = self.table.item(row, 1)
            plaintext = p_item.text().strip() if p_item else ""
            ciphertext = c_item.text().strip() if c_item else ""
            if plaintext or ciphertext:
                pairs.append((plaintext, ciphertext))
        if not pairs:
            raise ValueError("Enter at least one plaintext/ciphertext pair.")
        return pairs

    def start(self) -> None:
        self.result.clear()
        self.progress.setValue(0)
        try:
            pairs = self._read_pairs()
        except ValueError as exc:
            QMessageBox.warning(self, "Missing input", str(exc))
            return

        self.start_button.setEnabled(False)
        self.progress.setValue(0)
        self.result.setPlainText("Searching the complete 10-bit key space...")

        worker = FunctionWorker(brute_force, pairs, supports_progress=True)
        worker.signals.progress.connect(self.progress.setValue)
        worker.signals.finished.connect(self._show_result)
        worker.signals.error.connect(self._show_error)
        self.thread_pool.start(worker)

    def _show_result(self, result: BruteForceResult) -> None:
        self.start_button.setEnabled(True)
        keys = "\n".join(result.candidate_keys) if result.candidate_keys else "(none)"
        self.result.setPlainText(
            "\n".join(
                [
                    f"Started at     : {result.started_at}",
                    f"Finished at    : {result.finished_at}",
                    f"Elapsed        : {result.elapsed_seconds:.6f} s",
                    f"Keys tested    : {result.tested_keys}",
                    f"Candidate count: {len(result.candidate_keys)}",
                    "",
                    "Candidate keys:",
                    keys,
                ]
            )
        )

    def _show_error(self, message: str) -> None:
        self.start_button.setEnabled(True)
        self.progress.setValue(0)
        self.result.clear()
        QMessageBox.warning(self, "Brute-force failed", message)
