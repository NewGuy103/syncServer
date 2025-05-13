from functools import partial
import traceback
import httpx
import keyring
import typing
import logging

from pathlib import Path

from PySide6.QtWidgets import (
    QMessageBox, QListWidgetItem, QMenu,
    QDialog
)
from PySide6.QtCore import QObject, Slot, Qt, Signal, QThread
from PySide6.QtGui import QAction, QIcon
from ....version import __version__
from ...workers import WorkerThread
from ...config import AvailableLogins, LogLevels, logger, dirs
from ...models import AccessTokenResponse, AccessTokenError
from ...interface import MainClient
from ...ui.add_account_dialog import Ui_AddAccountDialog


if typing.TYPE_CHECKING:
    from ..apps import AppsController


# TODO: Implement multiple users and maybe app config
class SettingsTabController(QObject):
    def __init__(self, app_parent: 'AppsController'):
        super().__init__(app_parent)
        self.mw_parent = app_parent.mw_parent

        self.app_parent = app_parent
        self.ui = app_parent.ui

        self.main_client = app_parent.main_client

        # Controllers
        self.setup_slots()
    
    def setup_slots(self):
        # UI slots
        self.ui.accountsListWidget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ui.accountsListWidget.customContextMenuRequested.connect(self.on_context_menu)

        # UI stuff
        self.ui.logFilePathLabel.setText(f"Log File: {Path(dirs.user_config_dir) / 'client.log'}")

    def setup(self):
        loglevel_name = self.mw_parent.app_settings.log_level.name.capitalize()
        self.ui.logLevelComboBox.setCurrentText(loglevel_name)

        # Add slot only after first run
        self.ui.logLevelComboBox.currentTextChanged.connect(self.loglevel_changed)

        self.ui.clientVersionLabel.setText(f"Client version: {__version__}")
        self.ui.appCurrentUsernameLabel.setText(f"User: {self.app_parent.current_login.username}")

        self.ui.serverUrlLabel.setText(f"Server URL: {self.app_parent.current_login.server_url}")
        self.update_list_widget()

    def update_list_widget(self):
        self.ui.accountsListWidget.clear()
        logins = self.mw_parent.app_settings.logins

        for login_model in logins:
            lw_item = QListWidgetItem(f'{login_model.username} | Server: {login_model.server_url}')
            lw_item.setData(Qt.ItemDataRole.UserRole, login_model)

            if login_model == self.app_parent.current_login:
                current_icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.HelpAbout))
                lw_item.setIcon(current_icon)

            self.ui.accountsListWidget.addItem(lw_item)

        self.ui.appCurrentUsernameLabel.setText(f"User: {self.app_parent.current_login.username}")
        self.ui.serverUrlLabel.setText(f"Server URL: {self.app_parent.current_login.server_url}")
        
    @Slot()
    def on_context_menu(self, pos):
        context = QMenu(self.mw_parent)

        list_add_icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.ListAdd))
        logout_action = QAction(
            'Add account', self,
            icon=list_add_icon
        )

        logout_action.triggered.connect(lambda: self.add_account_triggered())
        context.addAction(logout_action)

        edit_clear_icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.EditDelete))
        logout_action = QAction(
            'Logout of current account', self,
            icon=edit_clear_icon
        )

        logout_action.triggered.connect(lambda: self.logout_current_triggered())
        context.addAction(logout_action)

        current_item = self.ui.accountsListWidget.itemAt(pos)
        if current_item is not None:
            icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.ListRemove))
            remove_account_action = QAction(
                'Remove account', self,
                icon=icon
            )

            remove_account_action.triggered.connect(lambda: self.remove_login_triggered(current_item))
            context.addAction(remove_account_action)

            if current_item.data(Qt.ItemDataRole.UserRole) != self.app_parent.current_login:
                go_next_icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.GoNext))
                switch_user_action = QAction(
                    'Switch to this account', self,
                    icon=go_next_icon
                )

                switch_user_action.triggered.connect(lambda: self.switch_user_triggered(current_item))
                context.addAction(switch_user_action)

        context.exec(self.ui.accountsListWidget.mapToGlobal(pos))

    @Slot(str)
    def loglevel_changed(self, log_level: str):
        match log_level.lower():
            case LogLevels.debug.name:
                level = logging.DEBUG
            case LogLevels.info.name:
                level = logging.INFO
            case LogLevels.warning.name:
                level = logging.WARNING
            case LogLevels.error.name:
                level = logging.ERROR
            case LogLevels.critical.name:
                level = logging.CRITICAL
            case _:
                level = logging.INFO
        
        self.mw_parent.app_settings.log_level = level
        self.mw_parent.app_settings.save_settings()

        logger.setLevel(level)
        self.ui.statusbar.showMessage(f"Set logging level to '{log_level}'", timeout=5000)

    def add_account_triggered(self):
        self.add_account_dialog = AddAccountDialog(self)
        self.add_account_dialog.loginDone.connect(lambda: self.update_list_widget())

        self.add_account_dialog.exec()
    
    def logout_current_triggered(self):
        current_login = self.app_parent.current_login
        btn = QMessageBox.question(
            self.mw_parent,
            'syncServer - Client',
            f"Logout of account '{current_login.username}' on server '{current_login.server_url}'? "
            "This will close the app.",
            buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            defaultButton=QMessageBox.StandardButton.No
        )
        if btn == QMessageBox.StandardButton.No:
            return

        logins = self.mw_parent.app_settings.logins
        logins.remove(current_login)

        keyring.delete_password('newguy103-syncserver', current_login.username)

        # Make the first user default
        if current_login.is_default and logins:
            logins[0].is_default = True
        
        self.mw_parent.app_settings.save_settings()
        self.mw_parent.close()

    def remove_login_triggered(self, item: QListWidgetItem):
        item_data: AvailableLogins = item.data(Qt.ItemDataRole.UserRole)
        if item_data == self.app_parent.current_login:
            self.logout_current_triggered()
            return
        
        btn = QMessageBox.question(
            self.mw_parent,
            'syncServer - Client',
            "Remove the selected login?",
            buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            defaultButton=QMessageBox.StandardButton.No
        )
        if btn == QMessageBox.StandardButton.No:
            return

        logins = self.mw_parent.app_settings.logins
        logins.remove(item_data)

        keyring.delete_password('newguy103-syncserver', item_data.username)

        # Make the first user default
        if item_data.is_default and logins:
            logins[0].is_default = True
            
        self.mw_parent.app_settings.save_settings()
        self.mw_parent.reload_config()

        self.update_list_widget()

    def switch_user_triggered(self, item: QListWidgetItem):
        item_data: AvailableLogins = item.data(Qt.ItemDataRole.UserRole)
        btn = QMessageBox.question(
            self.mw_parent,
            'syncServer - Client',
            f"Switch account to '{item_data.username}' on server '{item_data.server_url}'? "
            "This will close the app to switch the user.",
            buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            defaultButton=QMessageBox.StandardButton.No
        )
        if btn == QMessageBox.StandardButton.No:
            return
        
        # Mutable variables
        self.app_parent.current_login.is_default = False
        item_data.is_default = True

        self.mw_parent.app_settings.save_settings()
        self.app_parent.current_login = item_data

        self.update_list_widget()
        self.mw_parent.close()


class AddAccountDialog(QDialog):
    loginDone = Signal(AvailableLogins)

    def __init__(self, ctrl_parent: SettingsTabController):
        super().__init__(ctrl_parent.mw_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client
        self.ui = Ui_AddAccountDialog()

        self.ui.setupUi(self)
        self._can_close = False

        self.provided_username: str = None
        self.provided_server_url: str = None
    
    def accept(self):
        self.get_login_token()

        if self._can_close:
            return super().accept()

    def get_login_token(self):
        if self._can_close:
            return
        
        server_url = self.ui.serverUrlLineEdit.text()
        if not server_url:
            QMessageBox.warning(
                self, 
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
                self,
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
        
        self.login_worker.dataReady.connect(self.fetch_complete)
        self.login_worker.excReceived.connect(self.login_worker_exc)
        
        self.login_thread.started.connect(self.login_worker.run)
        self.login_worker.dataReady.connect(self.login_thread.quit)

        self.login_worker.excReceived.connect(self.login_thread.quit)
        self.login_thread.start()

        self.provided_username: str = username
        self.provided_server_url: str = server_url

    @Slot()
    def fetch_complete(self, data: AccessTokenResponse | AccessTokenError):
        if isinstance(data, AccessTokenError):
            QMessageBox.information(
                self,
                "syncServer - Client",
                f"Invalid credentials were passed:\n{data.error} - {data.error_description}",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok,
            )
            return
        
        login_model = AvailableLogins(
            username=self.provided_username,
            server_url=self.provided_server_url,
            is_default=False
        )

        for existing_login in self.mw_parent.app_settings.logins:
            if login_model.username != existing_login.username:
                continue
            
            if login_model.server_url != existing_login.server_url:
                continue

            QMessageBox.warning(
                self,
                "syncServer - Client",
                "An account with the same name and origin already exists.",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok,
            )
            return
        
        keyring.set_password(
            'newguy103-syncserver', 
            self.provided_username, 
            data.access_token
        )
        self.mw_parent.app_settings.logins.append(login_model)
        self.mw_parent.app_settings.save_settings()

        self.loginDone.emit(login_model)
        self._can_close = True

        self.accept()
        QMessageBox.information(
            self,
            "syncServer - Client",
            "Account added successfully!",
            buttons=QMessageBox.StandardButton.Ok,
            defaultButton=QMessageBox.StandardButton.Ok,
        )
        return

    @Slot(Exception)
    def login_worker_exc(self, exc: Exception):
        """Generic HTTP request failed function"""
        tb: str = ''.join(traceback.format_exception(exc, limit=1))

        match exc:
            case httpx.HTTPError():
                QMessageBox.warning(
                    self,
                    "syncServer - Client",
                    f"An HTTP error occured.\nDetails:\n\n{tb}",
                    buttons=QMessageBox.StandardButton.Ok,
                    defaultButton=QMessageBox.StandardButton.Ok,
                )
            case _:
                QMessageBox.critical(
                    self,
                    "syncServer - Client",
                    f"An unexpected error occured, check the log file for details.\nTraceback:\n\n{tb}"
                )
        return
    