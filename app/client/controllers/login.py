import typing
import traceback
import httpx
import keyring

from functools import partial

from PySide6.QtWidgets import QMessageBox
from PySide6.QtCore import QObject, QThread, Signal, Slot
from ..interface import MainClient
from ..models import AccessTokenResponse, AccessTokenError
from ..workers import WorkerThread


if typing.TYPE_CHECKING:
    from ..main import MainWindow


class LoginController(QObject):
    login_done = Signal(str, str)
    
    def __init__(self, mw_parent: 'MainWindow'):
        super().__init__(mw_parent)

        self.mw_parent = mw_parent
        self.ui = mw_parent.ui

        self.provided_username = None

        self.ui.loginButton.clicked.connect(self.login_start)
        self.ui.serverUrlLineEdit.setFocus()

    def check_saved_credentials(self):
        """Only check for saved keyring credentials, not verify, leave that to the dashboard"""
        
        auth_header = keyring.get_password(
            'newguy103-syncserver',
            self.mw_parent.app_settings.username
        )

        if auth_header:
            self.login_done.emit(
                self.mw_parent.app_settings.username, 
                str(self.mw_parent.app_settings.server_url)
            )

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
    
    @Slot(AccessTokenResponse, AccessTokenError)
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
        
        keyring.set_password(
            'newguy103-syncserver', 
            self.provided_username, 
            data.access_token
        )
        self.mw_parent.app_settings.server_url = self.provided_server_url
        self.mw_parent.app_settings.username = self.provided_username

        self.mw_parent.app_settings.save_settings()
        self.login_done.emit(self.provided_username, self.provided_server_url)

        return
    
    @Slot(Exception)
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
