from typing import Any, Callable

from PyQt6.QtCore import QObject, QRunnable, pyqtSignal


class WorkerSignals(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)


class FunctionWorker(QRunnable):
    def __init__(
        self,
        function: Callable[..., Any],
        *args: Any,
        supports_progress: bool = False,
    ) -> None:
        super().__init__()
        self.function = function
        self.args = args
        self.supports_progress = supports_progress
        self.signals = WorkerSignals()

    def run(self) -> None:
        try:
            if self.supports_progress:
                result = self.function(
                    *self.args,
                    progress_callback=self.signals.progress.emit,
                )
            else:
                result = self.function(*self.args)
        except Exception as exc:
            self.signals.error.emit(str(exc))
            return
        self.signals.finished.emit(result)
