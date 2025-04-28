import traceback
import typing
import secrets

import httpx

from pathlib import PurePosixPath
from functools import partial

from PySide6.QtWidgets import (
    QMessageBox, QListWidgetItem, QMenu, 
    QDialog
)
from PySide6.QtCore import QObject, QThread, Slot, Qt, Signal
from PySide6.QtGui import QAction, QIcon
from ...ui.trashbin_manager import Ui_TrashbinManagerDialog
from ...models import DeletedFileVersionState, DeletedFilesGet, GenericSuccess
from ...workers import WorkerThread


if typing.TYPE_CHECKING:
    from ..apps import AppsController


# TODO: Use a signal to notify files tab controller about a file restore
# TODO: Use a signal so files can notify about a new delete
class TrashbinTabController(QObject):
    def __init__(self, app_parent: 'AppsController'):
        super().__init__(app_parent)
        self.mw_parent = app_parent.mw_parent

        self.app_parent = app_parent
        self.ui = app_parent.ui

        self.main_client = app_parent.main_client

        # Controllers
        self.empty_trashbin_ctrl = EmptyTrashbinController(self)
        self.delete_version_ctrl = DeleteVersionController(self)

        self.restore_version_ctrl = RestoreVersionController(self)
        self.trashbin_manager_dialog = TrashbinManagerDialog(self)

        self.setup_slots()
    
    def setup_slots(self):
        # UI slots
        self.ui.trashbinListWidget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ui.trashbinListWidget.customContextMenuRequested.connect(self.on_context_menu)

        self.ui.trashbinListWidget.itemDoubleClicked.connect(self.on_item_double_clicked)

        # Controller slots
        self.app_parent.signals.files_new_delete.connect(self.update_deleted_file_list)
        self.empty_trashbin_ctrl.deleteComplete.connect(self.update_deleted_file_list)

    @Slot(Exception)
    def on_worker_exc(self, exc: Exception):
        """Generic HTTP request failed function"""
        self.ui.statusbar.showMessage('Trashbin - HTTP request failed', timeout=5000)
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
        context = QMenu(self.mw_parent)

        edit_clear_icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.EditClear))
        empty_trashbin_action = QAction(
            'Empty Trashbin', self,
            icon=edit_clear_icon
        )

        empty_trashbin_action.triggered.connect(self.empty_trashbin_ctrl.empty_trashbin_triggered)
        context.addAction(empty_trashbin_action)

        current_item = self.ui.trashbinListWidget.itemAt(pos)
        if current_item is not None:
            icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.EditDelete))
            delete_all_versions_action = QAction(
                'Delete All Versions', self,
                icon=icon
            )

            context.addAction(delete_all_versions_action)

        context.exec(self.ui.trashbinListWidget.mapToGlobal(pos))
    
    @Slot()
    def on_item_double_clicked(self, item: QListWidgetItem):
        item_data: PurePosixPath = item.data(Qt.ItemDataRole.UserRole)

        self.trashbin_manager_dialog.setup_for_file(item_data)
        self.trashbin_manager_dialog.exec()
    
    def update_deleted_file_list(self):
        self.update_worker = WorkerThread(self.main_client.files.deleted.list_files_with_deletes)
        self.update_thread = QThread(self)
        
        self.update_worker.moveToThread(self.update_thread)
        
        self.update_worker.dataReady.connect(self.update_list_widget)
        self.update_worker.excReceived.connect(self.on_worker_exc)
        
        self.update_thread.started.connect(self.update_worker.run)
        self.update_worker.dataReady.connect(self.update_thread.quit)

        self.update_worker.excReceived.connect(self.update_thread.quit)
        self.update_thread.start()

        self.ui.statusbar.showMessage(
            "Trashbin - Sent HTTP request to update list of deleted files",
            timeout=5000
        )

    @Slot(list)
    def update_list_widget(self, paths: list[PurePosixPath]):
        self.ui.trashbinListWidget.clear()

        for path in paths:
            data_str = f'{path}'
            widget_item = QListWidgetItem(data_str)

            widget_item.setData(Qt.ItemDataRole.UserRole, path)
            self.ui.trashbinListWidget.addItem(widget_item)
        
        self.ui.statusbar.showMessage(
            'Trashbin - Updated list of deleted files',
            timeout=5000
        )
    
    def setup(self):
        self.update_deleted_file_list()


class EmptyTrashbinController(QObject):
    deleteComplete = Signal(str, GenericSuccess)

    def __init__(self, ctrl_parent: TrashbinTabController):
        super().__init__(ctrl_parent.app_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client

        self.ui = ctrl_parent.ui
        self.http_requests: dict[str, list[WorkerThread, QThread]] = {}

    @Slot()
    def empty_trashbin_triggered(self):
        btn = QMessageBox.question(
            self.mw_parent,
            'syncServer - Client',
            "This will delete all files in the trashbin. Proceed?",
            buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            defaultButton=QMessageBox.StandardButton.No
        )
        if btn == QMessageBox.StandardButton.No:
            return

        random_id = secrets.token_hex(16)
        
        delete_worker = WorkerThread(self.main_client.files.deleted.empty_trashbin)
        delete_thread = QThread(self)
        
        delete_worker.moveToThread(delete_thread)
        
        delete_worker.dataReady.connect(
            lambda data, random_id=random_id: self.delete_complete(data, random_id)
        )
        delete_worker.excReceived.connect(self.ctrl_parent.on_worker_exc)
        
        delete_thread.started.connect(delete_worker.run)
        delete_worker.dataReady.connect(delete_thread.quit)

        delete_worker.excReceived.connect(delete_thread.quit)
        delete_thread.start()

        self.http_requests[random_id] = [delete_worker, delete_thread]
        self.ui.statusbar.showMessage(
            'Trashbin - Sent request to empty trashbin',
            timeout=5000
        )
    
    def delete_complete(self, data: GenericSuccess, random_id: str):
        self.deleteComplete.emit(random_id, data)
        self.http_requests.pop(random_id, None)


class DeleteVersionController(QObject):
    deleteComplete = Signal(str, GenericSuccess)

    def __init__(self, ctrl_parent: TrashbinTabController):
        super().__init__(ctrl_parent.app_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client

        self.ui = ctrl_parent.ui
        self.http_requests: dict[str, list[WorkerThread, QThread]] = {}

    def delete_version_triggered(self, path: PurePosixPath, offset: int = 0, delete_all: bool = False):
        random_id = secrets.token_hex(16)
        func = partial(
            self.main_client.files.deleted.delete_file_version,
            path, offset=offset, delete_all=delete_all
        )

        delete_worker = WorkerThread(func)
        delete_thread = QThread(self)
        
        delete_worker.moveToThread(delete_thread)
        
        delete_worker.dataReady.connect(
            lambda data, random_id=random_id: self.delete_complete(data, random_id)
        )
        delete_worker.excReceived.connect(self.ctrl_parent.on_worker_exc)
        
        delete_thread.started.connect(delete_worker.run)
        delete_worker.dataReady.connect(delete_thread.quit)

        delete_worker.excReceived.connect(delete_thread.quit)
        delete_thread.start()

        self.http_requests[random_id] = [delete_worker, delete_thread]
        self.ui.statusbar.showMessage(
            f"Trashbin - Sent request to delete file version of '{path}'",
            timeout=5000
        )
    
    def delete_complete(self, data: GenericSuccess, random_id: str):
        self.deleteComplete.emit(random_id, data)
        self.http_requests.pop(random_id, None)
    

class RestoreVersionController(QObject):
    restoreComplete = Signal(str, GenericSuccess)

    def __init__(self, ctrl_parent: TrashbinTabController):
        super().__init__(ctrl_parent.app_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client

        self.ui = ctrl_parent.ui
        self.http_requests: dict[str, list[WorkerThread, QThread]] = {}

    def restore_version_triggered(self, path: PurePosixPath, offset: int = 0):
        random_id = secrets.token_hex(16)
        func = partial(
            self.main_client.files.deleted.restore_file_version,
            path, offset=offset
        )

        restore_worker = WorkerThread(func)
        restore_thread = QThread(self)
        
        restore_worker.moveToThread(restore_thread)
        
        restore_worker.dataReady.connect(
            lambda data, random_id=random_id: self.restore_complete(data, random_id)
        )
        restore_worker.excReceived.connect(self.ctrl_parent.on_worker_exc)
        
        restore_thread.started.connect(restore_worker.run)
        restore_worker.dataReady.connect(restore_thread.quit)

        restore_worker.excReceived.connect(restore_thread.quit)
        restore_thread.start()

        self.http_requests[random_id] = [restore_worker, restore_thread]
        self.ui.statusbar.showMessage(
            f"Trashbin - Sent request to restore file version of '{path}'",
            timeout=5000
        )
    
    def restore_complete(self, data: GenericSuccess, random_id: str):
        self.restoreComplete.emit(random_id, data)
        self.http_requests.pop(random_id, None)


class TrashbinManagerDialog(QDialog):
    def __init__(self, ctrl_parent: TrashbinTabController):
        super().__init__(ctrl_parent.mw_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client
        self.ui = Ui_TrashbinManagerDialog()    

        self.ui.setupUi(self)
        self._file_path: PurePosixPath = None

        self._deleted_index: int = None
        self._delete_all: bool = None

        self.setup_slots()
    
    def setup_slots(self):
        # UI slots
        self.ui.deletedFilesListWidget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ui.deletedFilesListWidget.customContextMenuRequested.connect(self.context_menu_slot)

        self.ui.deleteAllVersionsButton.clicked.connect(self.delete_all_clicked)

        # Controller slots
        self.ctrl_parent.delete_version_ctrl.deleteComplete.connect(self.delete_completed)
        self.ctrl_parent.restore_version_ctrl.restoreComplete.connect(self.restore_completed)

    def setup_for_file(self, path: PurePosixPath):
        # Reset state
        self._deleted_index: int = None
        self._delete_all: bool = None

        self._file_path = path

        self.ui.deletedFilesListWidget.clear()
        self.ui.currentFileLabel.setText(f'Current file: {path}')

        self.update_version_list()

    def update_version_list(self):
        func = partial(
            self.main_client.files.deleted.show_deleted_versions,
            self._file_path
        )

        self.update_worker = WorkerThread(func)
        self.update_thread = QThread(self)
        
        self.update_worker.moveToThread(self.update_thread)
        
        self.update_worker.dataReady.connect(self.update_list_widget)
        self.update_worker.excReceived.connect(self.ctrl_parent.on_worker_exc)
        
        self.update_thread.started.connect(self.update_worker.run)
        self.update_worker.dataReady.connect(self.update_thread.quit)

        self.update_worker.excReceived.connect(self.update_thread.quit)
        self.update_thread.start()
    
    @Slot()
    def context_menu_slot(self, pos):
        context = QMenu(self.mw_parent)
        current_item = self.ui.deletedFilesListWidget.itemAt(pos)

        if current_item is not None:
            delete_version_action = self.delete_file_version_action(current_item)
            context.addAction(delete_version_action)

            restore_version_action = self.restore_file_version_action(current_item)
            context.addAction(restore_version_action)
            
        context.exec(self.ui.deletedFilesListWidget.mapToGlobal(pos))
    
    def delete_all_clicked(self):
        btn = QMessageBox.question(
            self.mw_parent,
            'syncServer - Client',
            "Delete all file versions?",
            buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            defaultButton=QMessageBox.StandardButton.No
        )
        if btn == QMessageBox.StandardButton.No:
            return

        self.ctrl_parent.delete_version_ctrl.delete_version_triggered(
            self._file_path, offset=0, delete_all=True
        )
        self._delete_all = True

    def delete_file_version_action(self, item: QListWidgetItem):
        item_data: DeletedFileVersionState = item.data(Qt.ItemDataRole.UserRole)

        edit_delete_icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.EditDelete))
        delete_version_action = QAction(
            'Delete Version', self,
            icon=edit_delete_icon
        )

        @Slot()
        def on_action_triggered():
            self.ctrl_parent.delete_version_ctrl.delete_version_triggered(
                self._file_path, offset=item_data.index
            )
            self._deleted_index = item_data.index

        delete_version_action.triggered.connect(on_action_triggered)
        return delete_version_action
    
    def restore_file_version_action(self, item: QListWidgetItem):
        item_data: DeletedFileVersionState = item.data(Qt.ItemDataRole.UserRole)

        edit_undo_icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.EditUndo))
        restore_version_action = QAction(
            'Restore Version', self,
            icon=edit_undo_icon
        )

        @Slot()
        def on_action_triggered():
            self.ctrl_parent.restore_version_ctrl.restore_version_triggered(
                self._file_path, offset=item_data.index
            )

        restore_version_action.triggered.connect(on_action_triggered)
        return restore_version_action
    
    @Slot(GenericSuccess)
    def delete_completed(self, data: GenericSuccess):
        if self.ui.deletedFilesListWidget.count() == 1 or self._deleted_all:
            self.accept()
            self.ctrl_parent.update_deleted_file_list()
            return
        
        self.update_version_list()

    @Slot(GenericSuccess)
    def restore_completed(self, data: GenericSuccess):
        self.ctrl_parent.app_parent.signals.trashbin_new_restore.emit()
        
        if self.ui.deletedFilesListWidget.count() == 1:
            self.accept()
            self.ctrl_parent.update_deleted_file_list()
            return
        
        self.update_version_list()
    
    @Slot(list)
    def update_list_widget(self, versions: list[DeletedFilesGet]):
        self.ui.deletedFilesListWidget.clear()

        for i, data in enumerate(versions):
            data_str = f'{i}: {data.deleted_on}'
            widget_item = QListWidgetItem(data_str)

            state = DeletedFileVersionState(
                index=i, deleted_on=data.deleted_on
            )
            widget_item.setData(Qt.ItemDataRole.UserRole, state)
            self.ui.deletedFilesListWidget.addItem(widget_item)
