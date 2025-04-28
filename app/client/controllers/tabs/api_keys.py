import traceback
import typing
import httpx

from functools import partial
from datetime import timezone, datetime

from PySide6.QtWidgets import (
    QApplication, QMessageBox, 
    QMenu, QListWidgetItem, QDialog
)
from PySide6.QtCore import QObject, QThread, Signal, Slot, Qt
from PySide6.QtGui import QAction, QIcon
from ...ui.create_apikey_dialog import Ui_CreateAPIKeyDialog
from ...ui.create_apikey_success_dialog import Ui_CreateAPIKeySuccess
from ...models import APIKeyInfo, GenericSuccess, APIKeyCreate
from ...workers import WorkerThread

if typing.TYPE_CHECKING:
    from ..apps import AppsController


class APIKeysTabController(QObject):
    def __init__(self, app_parent: 'AppsController'):
        super().__init__(app_parent)
        self.mw_parent = app_parent.mw_parent

        self.app_parent = app_parent
        self.ui = app_parent.ui

        self.main_client = app_parent.main_client

        self.ui.apiKeyListWidget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ui.apiKeyListWidget.customContextMenuRequested.connect(self.on_context_menu)

    @Slot(Exception)
    def on_worker_exc(self, exc: Exception):
        """Generic HTTP request failed function"""
        self.ui.statusbar.showMessage('API Keys - HTTP request failed', timeout=5000)
        tb: str = ''.join(traceback.format_exception(exc, limit=1))

        match exc:
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
    
    @Slot()
    def on_context_menu(self, pos):
        """Custom context menu for list widget."""
        context = QMenu(self.mw_parent)

        icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon. ListAdd))

        create_action = QAction("Create API Key", self, icon=icon)
        create_action.triggered.connect(self.create_apikey_triggered)

        context.addAction(create_action)
        current_item = self.ui.apiKeyListWidget.itemAt(pos)

        if current_item is not None:
            delete_icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.ListRemove))

            delete_action = QAction("Delete Selected Key", self, icon=delete_icon)
            delete_action.triggered.connect(self.delete_action_triggered)
            
            item_data: APIKeyInfo = current_item.data(Qt.ItemDataRole.UserRole)
            self._delete_key_name = item_data.key_name

            context.addAction(delete_action)
        
        context.exec(self.ui.apiKeyListWidget.mapToGlobal(pos))

    @Slot()
    def delete_action_triggered(self):
        """Triggered by clicking 'Delete Selected Key' in the context menu."""
        func = partial(self.main_client.api_keys.delete_key, self._delete_key_name)

        btn = QMessageBox.question(
            self.mw_parent,
            'syncServer - Client',
            f"Are you sure you want to delete the selected API key '{self._delete_key_name}'?",
            buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            defaultButton=QMessageBox.StandardButton.No
        )
        if btn == QMessageBox.StandardButton.No:
            return
        
        self.delete_action_worker = WorkerThread(func)
        self.delete_action_thread = QThread(self)
        
        self.delete_action_worker.moveToThread(self.delete_action_thread)
        
        self.delete_action_worker.dataReady.connect(self.delete_request_complete)
        self.delete_action_worker.excReceived.connect(self.on_worker_exc)
        
        self.delete_action_thread.started.connect(self.delete_action_worker.run)
        self.delete_action_worker.dataReady.connect(self.delete_action_thread.quit)

        self.delete_action_worker.excReceived.connect(self.delete_action_thread.quit)
        self.delete_action_thread.start()
        
        self.ui.statusbar.showMessage('API Keys - Delete request sent', timeout=5000)
    
    @Slot(GenericSuccess)
    def delete_request_complete(self, data: GenericSuccess):
        """If delete request is completed, called."""
        self.ui.statusbar.showMessage('API Keys - Key deleted successfully', timeout=5000)
        self.update_apikey_list()
    
    @Slot()
    def create_apikey_triggered(self):
        """Triggered by clicking 'Create API Key' in context menu."""
        self.create_dialog = CreateAPIKeyDialog(self)
        self.create_dialog.dataCompleted.connect(self.create_apikey_request)

        self.create_dialog.exec()
    
    @Slot(APIKeyCreate)
    def create_apikey_request(self, data: APIKeyCreate):
        """Triggered after accepting the create dialog."""
        func = partial(self.main_client.api_keys.create_key, data)

        self.create_worker = WorkerThread(func)
        self.create_thread = QThread(self)
        
        self.create_worker.moveToThread(self.create_thread)
        
        self.create_worker.dataReady.connect(self.create_request_complete)
        self.create_worker.excReceived.connect(self.on_worker_exc)
        
        self.create_thread.started.connect(self.create_worker.run)
        self.create_worker.dataReady.connect(self.create_thread.quit)

        self.create_worker.excReceived.connect(self.create_thread.quit)
        self.create_thread.start()

        self.ui.statusbar.showMessage('API Keys - Create request sent', timeout=5000)
    
    @Slot(str)
    def create_request_complete(self, data: str):
        """If create request succeeded, called."""
        self.ui.statusbar.showMessage('API Keys - Key created successfully', timeout=5000)
        self.create_success_dialog = CreateAPIKeySuccessDialog(self, data)

        self.create_success_dialog.exec()
        self.update_apikey_list()
    
    def update_apikey_list(self):
        """Updates API key list by calling server API."""
        self.worker = WorkerThread(self.main_client.api_keys.list_all_keys)
        self.thread = QThread(self)
        
        self.worker.moveToThread(self.thread)
        
        self.worker.dataReady.connect(self.update_list_widget)
        self.worker.excReceived.connect(self.on_worker_exc)
        
        self.thread.started.connect(self.worker.run)
        self.worker.dataReady.connect(self.thread.quit)

        self.worker.excReceived.connect(self.thread.quit)
        self.thread.start()

    @Slot(list)
    def update_list_widget(self, data: list[APIKeyInfo]):
        self.ui.apiKeyListWidget.clear()

        for key_model in data:
            # TODO: Do something better than displaying it in a formatted string

            data_str = f'{key_model.key_name} - Expires on: {key_model.expiry_date} - Expired: {key_model.expired}'
            widget_item = QListWidgetItem(data_str)

            widget_item.setData(Qt.ItemDataRole.UserRole, key_model)
            self.ui.apiKeyListWidget.addItem(widget_item)

        self.ui.statusbar.showMessage('API Keys - Updated key list', timeout=5000)

    def setup(self):
        self.update_apikey_list()


class CreateAPIKeyDialog(QDialog):
    dataCompleted = Signal(APIKeyCreate)

    def __init__(self, app_parent: APIKeysTabController):
        self.mw_parent = app_parent.mw_parent
        super().__init__(self.mw_parent)

        self.ui = Ui_CreateAPIKeyDialog()
        self.ui.setupUi(self)

        self.main_client = app_parent.main_client

    def get_data(self):
        datetime_value = self.ui.keyExpiryDateTimeEdit.dateTime()
        python_datetime: datetime = datetime_value.toPython()

        aware_datetime = python_datetime.replace(tzinfo=timezone.utc)

        create_perm = self.ui.createPermsCheckbox.isChecked()
        read_perm = self.ui.readPermsCheckbox.isChecked()

        update_perm = self.ui.updatePermsCheckbox.isChecked()
        delete_perm = self.ui.deletePermsCheckbox.isChecked()

        key_perms = []
        if create_perm:
            key_perms.append('create')
        
        if read_perm:
            key_perms.append('read')

        if update_perm:
            key_perms.append('update')

        if delete_perm:
            key_perms.append('delete')
        
        return APIKeyCreate(
            key_name=self.ui.keyNameLineEdit.text(),
            expiry_date=aware_datetime,
            key_permissions=key_perms
        )

    def accept(self):
        values_valid = self.check_valid_values()

        if values_valid:
            data = self.get_data()

            self.dataCompleted.emit(data)
            return super().accept()
    
    def check_valid_values(self):
        key_name = self.ui.keyNameLineEdit.text()
        if not key_name:
            QMessageBox.warning(
                self.mw_parent, 
                "syncServer - Client",
                "Enter a valid API key name.",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok
            )
            return

        datetime_value = self.ui.keyExpiryDateTimeEdit.dateTime()
        python_datetime: datetime = datetime_value.toPython()

        aware_datetime = python_datetime.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > aware_datetime:
            QMessageBox.warning(
                self.mw_parent, 
                "syncServer - Client",
                "Enter a datetime in the future.",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok
            )
            return

        create_perm = self.ui.createPermsCheckbox.isChecked()
        read_perm = self.ui.readPermsCheckbox.isChecked()

        update_perm = self.ui.updatePermsCheckbox.isChecked()
        delete_perm = self.ui.deletePermsCheckbox.isChecked()

        if not any([create_perm, read_perm, update_perm, delete_perm]):
            QMessageBox.warning(
                self.mw_parent, 
                "syncServer - Client",
                "Choose at least one key permission.",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok
            )
            return
        
        return True


class CreateAPIKeySuccessDialog(QDialog):
    def __init__(self, app_parent: APIKeysTabController, api_key: str):
        self.mw_parent = app_parent.mw_parent
        super().__init__(self.mw_parent)

        self.ui = Ui_CreateAPIKeySuccess()
        self.ui.setupUi(self)

        self.main_client = app_parent.main_client
        self._api_key = api_key

        self.ui.keyLineEdit.setText(api_key)
        self.ui.copyToClipboardButton.clicked.connect(self.copy_to_clipboard)
    
    @Slot()
    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self._api_key)

        self.ui.copyToClipboardButton.setText('Copied!')
