from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QMainWindow, QTabWidget

from .analysis_page import AnalysisPage
from .basic_page import BasicPage
from .brute_force_page import BruteForcePage
from .text_page import TextPage


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("S-DES Encryption System")
        self.resize(980, 720)

        tabs = QTabWidget()
        tabs.addTab(BasicPage(), "Basic")
        tabs.addTab(TextPage(), "Text")
        tabs.addTab(BruteForcePage(), "Brute Force")
        tabs.addTab(AnalysisPage(), "Analysis")
        self.setCentralWidget(tabs)

        app_font = QFont()
        app_font.setPointSize(10)
        self.setFont(app_font)

        self.setStyleSheet(
            '''
            QMainWindow {
                background: #f4f6f8;
            }
            QTabWidget::pane {
                border: 1px solid #c9d1d9;
                background: white;
            }
            QTabBar::tab {
                padding: 10px 18px;
            }
            QLabel#pageTitle {
                font-size: 20px;
                font-weight: 600;
                margin-bottom: 8px;
            }
            QPushButton {
                padding: 7px 14px;
            }
            QLineEdit, QTextEdit, QTableWidget {
                padding: 5px;
            }
            '''
        )
