import sys
import traceback
import httpx
import keyring
import webbrowser

from typing import Callable
from functools import partial

from PySide6.QtWidgets import QMainWindow, QApplication, QMessageBox
from PySide6.QtCore import QObject, QThread, Signal
from .interface import MainClient
from .ui.main import Ui_MainWindow
from .models import AccessTokenResponse, AccessTokenError


class WorkerThread(QObject):
    dataReady = Signal(object)
    excReceived = Signal(Exception)

    def __init__(self, func: Callable):
        super().__init__()
        self.func = func
    
    def run(self):
        try:
            result = self.func()
            self.dataReady.emit(result)
        except Exception as exc:
            self.excReceived.emit(exc)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.mainStackedWidget.setCurrentIndex(0)
        self.login_ctrl = LoginController(self)

        self.apps_ctrl = AppsController(self)
        self.login_ctrl.login_done.connect(self.apps_ctrl.setup)

        # TODO: Make a dialog that shows copyright info and link to source code
        # not like this is proprietary or anything...
        self.ui.actionSource_Code.triggered.connect(
            lambda: webbrowser.open('https://github.com/newguy103/syncserver')
        )


class LoginController(QObject):
    login_done = Signal(str, str)
    
    def __init__(self, mw_parent: MainWindow):
        super().__init__(mw_parent)

        self.mw_parent = mw_parent
        self.ui = mw_parent.ui

        self.provided_username = None

        self.ui.loginButton.clicked.connect(self.login_start)
        self.ui.serverUrlLineEdit.setFocus()

    def login_start(self):
        server_url = self.ui.serverUrlLineEdit.text()
        if not server_url:
            QMessageBox.warning(
                self.mw_parent, 
                "syncServer - Client",
                "Enter the server hostname where syncServer is running.",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok
            )
            return
        
        username = self.ui.usernameLineEdit.text()
        password = self.ui.passwordLineEdit.text()

        if not username or not password:
            QMessageBox.warning(
                self.mw_parent,
                "syncServer - Client",
                "Enter a username and password.",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok,
            )
            return
        
        func = partial(
            MainClient.fetch_authorization_header, 
            username, password, server_url
        )
        
        self.login_worker = WorkerThread(func)
        self.login_thread = QThread()
        
        self.login_worker.moveToThread(self.login_thread)
        
        self.login_worker.dataReady.connect(self.on_worker_complete)
        self.login_worker.excReceived.connect(self.on_worker_exc)
        
        self.login_thread.started.connect(self.login_worker.run)
        self.login_worker.dataReady.connect(self.login_thread.quit)

        self.login_worker.excReceived.connect(self.login_thread.quit)
        self.login_thread.start()

        self.provided_username: str = username
        self.provided_server_url: str = server_url

        self.ui.statusbar.showMessage('Auth - Sent HTTP request for token', timeout=30000)
    
    def on_worker_complete(self, data: AccessTokenResponse | AccessTokenError):
        self.ui.statusbar.showMessage('Auth - HTTP response received', timeout=5000)
        if isinstance(data, AccessTokenError):
            QMessageBox.information(
                self.mw_parent,
                "syncServer - Client",
                f"Invalid credentials were passed:\n{data.error} - {data.error_description}",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok,
            )
            return
        
        # TODO: Make it also save the same URL in a config file or something
        keyring.set_password(
            'newguy103-syncserver', 
            self.provided_username, 
            data.access_token
        )
        self.login_done.emit(self.provided_username, self.provided_server_url)
        return
    
    def on_worker_exc(self, exc: Exception):
        self.ui.statusbar.showMessage('Auth - HTTP request failed', timeout=5000)
        tb: str = ''.join(traceback.format_exception(exc, limit=1))

        match exc:
            case httpx.InvalidURL() | httpx.UnsupportedProtocol():
                QMessageBox.warning(
                    self.mw_parent,
                    "syncServer - Client",
                    f"Invalid HTTP host passed. Details:\n\n{tb}",
                    buttons=QMessageBox.StandardButton.Ok,
                    defaultButton=QMessageBox.StandardButton.Ok
                )
            case httpx.HTTPError():
                QMessageBox.warning(
                    self.mw_parent,
                    "syncServer - Client",
                    f"An HTTP error occured.\nDetails:\n\n{tb}",
                    buttons=QMessageBox.StandardButton.Ok,
                    defaultButton=QMessageBox.StandardButton.Ok,
                )
            case _:
                QMessageBox.critical(
                    self.mw_parent,
                    "syncServer - Client",
                    f"An unexpected error occured, check the log file for details.\nTraceback:\n\n{tb}"
                )
        return

class AppsController(QObject):
    def __init__(self, mw_parent: MainWindow):
        super().__init__(mw_parent)

        self.mw_parent = mw_parent
        self.ui = mw_parent.ui
    
    def setup(self, username: str, server_url: str):
        authorization = keyring.get_password('newguy103-syncserver', username)
        self.ui.mainStackedWidget.setCurrentIndex(1)  # app tabs
        self.main_client = MainClient(authorization, server_url)

        self.worker = WorkerThread(self.main_client.setup)
        self.thread = QThread()
        
        self.worker.moveToThread(self.thread)
        
        self.worker.dataReady.connect(self.setup_complete)
        self.worker.excReceived.connect(self.setup_fail)
        
        self.thread.started.connect(self.worker.run)
        self.worker.dataReady.connect(self.thread.quit)

        self.worker.excReceived.connect(self.thread.quit)
        self.thread.start()

    def setup_complete(self, success: bool):
        self.ui.statusbar.showMessage('Dashboard - Authorization complete', timeout=5000)
    
    def setup_fail(self, exc: Exception):
        self.ui.statusbar.showMessage('Dashboard - Authorization failed', timeout=5000)
        tb: str = ''.join(traceback.format_exception(exc, limit=1))

        match exc:
            case httpx.HTTPError():
                QMessageBox.warning(
                    self.mw_parent,
                    "syncServer - Client",
                    f"Could not setup HTTP client.\nDetails:\n\n{tb}",
                    buttons=QMessageBox.StandardButton.Ok,
                    defaultButton=QMessageBox.StandardButton.Ok,
                )
            case _:
                QMessageBox.critical(
                    self.mw_parent,
                    "syncServer - Client",
                    f"An unexpected error occured, check the log file for details.\nTraceback:\n\n{tb}"
                )

        return


def main():
    app = QApplication(sys.argv)

    mw = MainWindow()  # type: ignore
    mw.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
