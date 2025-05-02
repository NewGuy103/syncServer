from typing import Any
from collections.abc import Callable

from PySide6.QtCore import QObject, Signal

class WorkerThread(QObject):
    dataReady = Signal(object)
    excReceived = Signal(Exception)

    def __init__(self, func: Callable[[], Any]):
        super().__init__()
        self.func = func
    
    def run(self):
        try:
            result = self.func()
            self.dataReady.emit(result)
        except Exception as exc:
            self.excReceived.emit(exc)
