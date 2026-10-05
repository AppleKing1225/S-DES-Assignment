"""Offscreen Qt regression tests; no manual or external-group test is simulated."""
from pathlib import Path
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PyQt6.QtCore import QThreadPool, PYQT_VERSION_STR, qVersion
from PyQt6.QtWidgets import QApplication, QMessageBox
from gui.main_window import MainWindow
from verification_io import output_path, save_record, require


def main() -> None:
    destination = output_path("gui_results")
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.processEvents()
    tabs = window.centralWidget()
    basic, text, brute, analysis = [tabs.widget(index) for index in range(4)]
    warnings = []
    checks = []
    original_warning = QMessageBox.warning
    # Capture modal warnings so invalid-input cases cannot block the test run.
    QMessageBox.warning = lambda *args: warnings.append(str(args[2]))

    def check(label, condition):
        require(condition, label)
        checks.append(dict(case=label, passed=True))

    def expect_warning(label, operation, message):
        before = len(warnings)
        operation()
        check(label, len(warnings) == before + 1 and message in warnings[-1])

    def wait_done(button):
        deadline = time.monotonic() + 60
        while not button.isEnabled():
            app.processEvents()
            require(time.monotonic() < deadline, "Background task timeout")
            time.sleep(0.005)
        app.processEvents()

    try:
        basic.block_input.setText("10101010")
        basic.key_input.setText("1010000010")
        basic.encrypt()
        check("basic_encrypt", basic.output.text() == "00001001")
        basic.block_input.setText("00001001")
        basic.decrypt()
        check("basic_decrypt", basic.output.text() == "10101010")
        basic.block_input.setText("101010101")
        check("nine_bit_input_preserved", basic.block_input.text() == "101010101")
        expect_warning("nine_bit_input_rejected", basic.encrypt, "exactly 8 bits")
        check("basic_error_clears_output_and_trace", not basic.output.text() and not basic.details.toPlainText())
        basic.block_input.setText("10101010")
        basic.key_input.setText("10100000100")
        expect_warning("eleven_bit_key_rejected", basic.encrypt, "exactly 10 bits")
        basic.key_input.setText("1010000010")
        basic.block_input.setText("10102111")
        expect_warning("nonbinary_input_rejected", basic.encrypt, "only 0 and 1")

        text.key_input.setText("1010000010")
        text.plaintext.setPlainText("Hello SDES!")
        text.encrypt()
        check("text_encrypt", text.cipher_hex.toPlainText() == "E4 5C 89 89 AB C2 CB 9B 30 CB AD")
        text.decrypt()
        check("text_decrypt", text.recovered_text.toPlainText() == "Hello SDES!")
        text.cipher_hex.setPlainText("G4")
        expect_warning("bad_hex_rejected", text.decrypt, "hexadecimal")
        check("decrypt_error_clears_results_keeps_input", not text.recovered_text.toPlainText()
              and not text.cipher_binary.toPlainText() and text.cipher_hex.toPlainText() == "G4")
        text.encrypt()
        text.plaintext.setPlainText("你好")
        expect_warning("non_ascii_rejected", text.encrypt, "ASCII")
        check("encrypt_error_clears_results", not text.cipher_hex.toPlainText()
              and not text.cipher_binary.toPlainText() and not text.recovered_text.toPlainText())
        text.clear()
        text.key_input.setText("bad")
        expect_warning("empty_text_bad_key_rejected", text.encrypt, "exactly 10 bits")
        expect_warning("empty_hex_bad_key_rejected", text.decrypt, "exactly 10 bits")
        text.key_input.setText("10100000100")
        expect_warning("text_long_key_rejected", text.encrypt, "exactly 10 bits")
        text.key_input.setText("1010000010")
        before = len(warnings)
        text.encrypt()
        text.decrypt()
        check("empty_text_valid_key", len(warnings) == before and not text.recovered_text.toPlainText())

        brute.table.item(0, 0).setText("10101010")
        brute.table.item(0, 1).setText("00001001")
        brute.start()
        wait_done(brute.start_button)
        check("single_pair_worker", "Candidate count: 4" in brute.result.toPlainText())
        brute.add_pair()
        brute.table.item(1, 0).setText("11010111")
        brute.table.item(1, 1).setText("11101000")
        brute.start()
        wait_done(brute.start_button)
        check("two_pair_worker", "Candidate count: 2" in brute.result.toPlainText() and brute.progress.value() == 100)
        for row in range(2):
            brute.table.item(row, 0).setText("")
            brute.table.item(row, 1).setText("")
        expect_warning("empty_pairs_rejected", brute.start, "at least one")
        check("empty_pairs_clear_previous_result", not brute.result.toPlainText() and brute.progress.value() == 0)
        brute.table.item(0, 0).setText("101010101")
        brute.table.item(0, 1).setText("00001001")
        before = len(warnings)
        brute.start()
        wait_done(brute.start_button)
        check("worker_error_clears_search_text", len(warnings) == before + 1 and not brute.result.toPlainText())

        analysis.plaintext_input.setText("10101010")
        analysis.analyze_single()
        wait_done(analysis.single_button)
        check("single_analysis_worker", "254" in analysis.result.toPlainText())
        analysis.plaintext_input.setText("101010101")
        before = len(warnings)
        analysis.analyze_single()
        wait_done(analysis.single_button)
        check("analysis_long_input_rejected_and_cleared", len(warnings) == before + 1
              and "exactly 8 bits" in warnings[-1] and not analysis.result.toPlainText())
        analysis.analyze_all()
        wait_done(analysis.all_button)
        check("all_analysis_worker", "262144" in analysis.result.toPlainText() and analysis.progress.value() == 100)
        save_record(destination, dict(
            status="PASS", scope="Offscreen Qt widgets and signals; not manual or cross-group testing.",
            PyQt6=PYQT_VERSION_STR, Qt=qVersion(), checks=checks, warning_messages=warnings,
        ))
        print(f"PASS: {len(checks)} GUI regression checks.")
    finally:
        QThreadPool.globalInstance().waitForDone()
        QMessageBox.warning = original_warning
        window.close()
        app.processEvents()


if __name__ == "__main__":
    main()
