import typing
import traceback
import httpx
import keyring

from PySide6.QtWidgets import QMessageBox
from PySide6.QtCore import QObject, QThread, Slot
from ..interface import MainClient
from ..workers import WorkerThread
from .tabs.files import FilesTabController
from .tabs.api_keys import APIKeysTabController

if typing.TYPE_CHECKING:
    from ..main import MainWindow


class AppsController(QObject):
    def __init__(self, mw_parent: 'MainWindow'):
        super().__init__(mw_parent)

        self.mw_parent = mw_parent
        self.ui = mw_parent.ui

        self.ui.appTabWidget.setCurrentIndex(0)  # dashboard tab
        self.main_client = None
    
    @Slot(str, str)
    def setup(self, username: str, server_url: str):
        authorization = keyring.get_password('newguy103-syncserver', username)

        self.ui.mainStackedWidget.setCurrentIndex(1)  # app tabs
        self.main_client = MainClient(authorization, server_url)

        self.worker = WorkerThread(self.main_client.setup)
        self.thread = QThread(self)
        
        self.worker.moveToThread(self.thread)
        
        self.worker.dataReady.connect(self.setup_complete)
        self.worker.excReceived.connect(self.setup_fail)
        
        self.thread.started.connect(self.worker.run)
        self.worker.dataReady.connect(self.thread.quit)

        self.worker.excReceived.connect(self.thread.quit)
        self.thread.start()
    
    @Slot(bool)
    def setup_complete(self, success: bool):
        self.ui.statusbar.showMessage('Dashboard - Authorization complete', timeout=5000)

        self.files_ctrl = FilesTabController(self)
        self.apikeys_ctrl = APIKeysTabController(self)

        self.files_ctrl.setup()
        self.apikeys_ctrl.setup()
    
    @Slot(Exception)
    def setup_fail(self, exc: Exception):
        self.ui.statusbar.showMessage('Dashboard - Authorization failed', timeout=5000)
        tb: str = ''.join(traceback.format_exception(exc, limit=1))

        match exc:
            case httpx.HTTPStatusError() if exc.response.status_code == 401:
                QMessageBox.warning(
                    self.mw_parent,
                    "syncServer - Client",
                    f"Authorization header is not valid, please login again.\nDetails:\n\n{tb}",
                    buttons=QMessageBox.StandardButton.Ok,
                    defaultButton=QMessageBox.StandardButton.Ok,
                )
                self.ui.mainStackedWidget.setCurrentIndex(0)
            case httpx.HTTPError():
                QMessageBox.warning(
                    self.mw_parent,
                    "syncServer - Client",
                    f"Could not setup HTTP client.\nDetails:\n\n{tb}",
                    buttons=QMessageBox.StandardButton.Ok,
                    defaultButton=QMessageBox.StandardButton.Ok
                )
            case _:
                QMessageBox.critical(
                    self.mw_parent,
                    "syncServer - Client",
                    f"An unexpected error occured, check the log file for details.\nTraceback:\n\n{tb}"
                )

        return
