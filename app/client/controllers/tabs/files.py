import traceback
import typing
import secrets

import httpx

from pathlib import Path, PurePosixPath
from functools import partial

from PySide6.QtWidgets import QMessageBox, QListWidgetItem, QMenu, QFileDialog, QDialog
from PySide6.QtCore import QObject, QThread, Slot, Qt, Signal
from PySide6.QtGui import QAction
from ...models import (
    FolderContents, FileListWidgetData, DownloadStartedState,
    UploadStartedState, GenericSuccess
)
from ...ui.rename_file_dialog import Ui_RenameFileDialog
from ...ui.files_download_manager import Ui_FilesDownloadManagerDialog
from ...workers import WorkerThread


if typing.TYPE_CHECKING:
    from ..apps import AppsController


class FilesTabController(QObject):
    def __init__(self, app_parent: 'AppsController'):
        super().__init__(app_parent)
        self.mw_parent = app_parent.mw_parent

        self.app_parent = app_parent
        self.ui = app_parent.ui

        self.main_client = app_parent.main_client
        self.current_folder_contents: FolderContents = None

        self.current_folder = PurePosixPath('/')

        # Controllers defined after this point
        self.slot_callbacks = SlotCallbacks(self)
        self.context_menu_actions = CreateContextMenuActions(self)

        self.upload_ctrl = UploadController(self)
        self.delete_ctrl = DeleteController(self)

        self.rename_ctrl = RenameController(self)
        self.download_ctrl = DownloadController(self)

        self.download_manager_dialog = FilesDownloadManagerDialog(self)
        self.setup_slots()

    def setup_slots(self):
        # UI slots
        self.ui.fileListWidget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ui.fileListWidget.customContextMenuRequested.connect(self.on_context_menu)

        self.ui.fileListWidget.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.ui.showDownloadsManagerButton.clicked.connect(self.download_manager_dialog.exec)

        # Controller slots
        self.upload_ctrl.uploadComplete.connect(self.slot_callbacks.file_upload_complete)
        self.delete_ctrl.deleteComplete.connect(self.slot_callbacks.file_upload_complete)

        self.rename_ctrl.renameComplete.connect(self.slot_callbacks.file_rename_complete)
        self.download_ctrl.downloadComplete.connect(self.slot_callbacks.file_download_complete)

        self.upload_ctrl.uploadStarted.connect(self.slot_callbacks.file_upload_started)
        self.download_ctrl.downloadStarted.connect(self.slot_callbacks.file_download_started)

    @Slot(Exception)
    def on_worker_exc(self, exc: Exception):
        """Generic HTTP request failed function"""
        self.ui.statusbar.showMessage('Files - HTTP request failed', timeout=5000)
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

        create_action = QAction("Upload file", self)
        create_action.triggered.connect(self.upload_ctrl.upload_file_triggered)

        context.addAction(create_action)
        current_item = self.ui.fileListWidget.itemAt(pos)

        if current_item is not None:
            delete_action: QAction | None = self.context_menu_actions.file_delete_action(current_item)
            if delete_action:
                context.addAction(delete_action)

            rename_action: QAction | None = self.context_menu_actions.file_rename_action(current_item)
            if rename_action:
                context.addAction(rename_action)

            download_action: QAction | None = self.context_menu_actions.file_download_action(current_item)
            if download_action:
                context.addAction(download_action)
        
        context.exec(self.ui.fileListWidget.mapToGlobal(pos))

    def update_root_listing(self):
        self.update_root_worker = WorkerThread(self.main_client.folders.list_root_folder)
        self.update_root_thread = QThread()
        
        self.update_root_worker.moveToThread(self.update_root_thread)
        
        self.update_root_worker.dataReady.connect(self.slot_callbacks.update_list_widget)
        self.update_root_worker.excReceived.connect(self.on_worker_exc)
        
        self.update_root_thread.started.connect(self.update_root_worker.run)
        self.update_root_worker.dataReady.connect(self.update_root_thread.quit)

        self.update_root_worker.excReceived.connect(self.update_root_thread.quit)
        self.update_root_thread.start()

        self.ui.statusbar.showMessage(
            "Files - Sent HTTP request to update listing for '/'",
            timeout=5000
        )

    def update_folder_listing(self, folder_path: PurePosixPath):
        """Updates the UI widget"""
        func = partial(self.main_client.folders.list_folder_contents, folder_path)

        self.update_worker = WorkerThread(func)
        self.update_thread = QThread(self)
        
        self.update_worker.moveToThread(self.update_thread)
        
        self.update_worker.dataReady.connect(self.slot_callbacks.update_list_widget)
        self.update_worker.excReceived.connect(self.on_worker_exc)
        
        self.update_thread.started.connect(self.update_worker.run)
        self.update_worker.dataReady.connect(self.update_thread.quit)

        self.update_worker.excReceived.connect(self.update_thread.quit)
        self.update_thread.start()

        self.ui.statusbar.showMessage(
            f"Files - Sent HTTP request to update listing for '{folder_path}'",
            timeout=5000
        )

    @Slot()
    def on_item_double_clicked(self, item: QListWidgetItem):
        item_data: FileListWidgetData = item.data(Qt.ItemDataRole.UserRole)

        if item_data.data_type == 'file':
            return
        
        path: PurePosixPath = item_data.path
        if path == PurePosixPath('/'):
            self.update_root_listing()
        else:
            self.update_folder_listing(item_data.path)
    
    def setup(self):
        self.update_root_listing()


class SlotCallbacks(QObject):
    def __init__(self, ctrl_parent: FilesTabController):
        super().__init__(ctrl_parent.app_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client
        self.ui = ctrl_parent.ui

    @Slot(UploadStartedState)
    def file_upload_started(self, state: UploadStartedState):
        self.ctrl_parent.download_manager_dialog.add_running_upload(state)
        self.ui.statusbar.showMessage(
            f"Files - Uploading file '{state.local_path}' to server path '{state.server_path}'",
            timeout=5000
        )
    
    @Slot(str, GenericSuccess)
    def file_upload_complete(self, random_id: str, data: GenericSuccess):
        self.ctrl_parent.download_manager_dialog.complete_upload(random_id)
        self.ctrl_parent.update_folder_listing(self.ctrl_parent.current_folder)

        self.ui.statusbar.showMessage(
            "Files - Upload complete",
            timeout=5000
        )
    
    @Slot(str, GenericSuccess)
    def file_delete_complete(self, random_id: str, data: GenericSuccess):
        self.ctrl_parent.update_folder_listing(self.ctrl_parent.current_folder)
        self.ui.statusbar.showMessage(
            "Files - Delete complete",
            timeout=5000
        )

    @Slot(str, GenericSuccess)
    def file_rename_complete(self, random_id: str, data: GenericSuccess):
        self.ctrl_parent.update_folder_listing(self.ctrl_parent.current_folder)
        self.ui.statusbar.showMessage(
            "Files - Rename complete",
            timeout=5000
        )
    
    @Slot(DownloadStartedState)
    def file_download_started(self, state: DownloadStartedState):
        self.ctrl_parent.download_manager_dialog.add_running_download(state)
        self.ui.statusbar.showMessage(
            f"Files - Downloading file '{state.server_path}' to local file '{state.local_path}'",
            timeout=5000
        )
    
    @Slot(str, None)
    def file_download_complete(self, random_id: str, data: None):
        self.ctrl_parent.download_manager_dialog.complete_download(random_id)
        self.ctrl_parent.update_folder_listing(self.ctrl_parent.current_folder)

        self.ui.statusbar.showMessage(
            "Files - Download complete",
            timeout=5000
        )

    @Slot(FolderContents)
    def update_list_widget(self, data: FolderContents):
        self.ui.fileListWidget.clear()

        # TODO: Do something better than displaying it in a formatted string
        if data.folder_path != PurePosixPath('/'):
            data_str = f'Move up to parent: {str(data.folder_path.parent)}'
            root_item = QListWidgetItem(data_str)

            lw_data = FileListWidgetData(
                data_type='folder',
                path=data.folder_path.parent
            )

            root_item.setData(Qt.ItemDataRole.UserRole, lw_data)
            self.ui.fileListWidget.addItem(root_item)

        for folder in data.folders:
            data_str = f'Folder: {str(folder)}'
            folder_item = QListWidgetItem(data_str)

            lw_data = FileListWidgetData(
                data_type='folder',
                path=folder
            )
            folder_item.setData(Qt.ItemDataRole.UserRole, lw_data)

            self.ui.fileListWidget.addItem(folder_item)
        
        for file in data.files:
            data_str = f'File: {str(file)}'
            file_item = QListWidgetItem(data_str)

            lw_data = FileListWidgetData(
                data_type='file',
                path=file
            )
            file_item.setData(Qt.ItemDataRole.UserRole, lw_data)

            self.ui.fileListWidget.addItem(file_item)

        self.ui.fileListLabel.setText(f'Folder: {str(data.folder_path)}')
        self.ui.statusbar.showMessage(
            f"Files - Updated folder listing for '{str(data.folder_path)}'",
            timeout=5000
        )

        self.ctrl_parent.current_folder_contents = data
        self.ctrl_parent.current_folder = data.folder_path


class CreateContextMenuActions(QObject):
    def __init__(self, ctrl_parent: FilesTabController):
        super().__init__(ctrl_parent.app_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client
        self.ui = ctrl_parent.ui
    
    def file_delete_action(self, item: QListWidgetItem) -> QAction | None:
        item_data: FileListWidgetData = item.data(Qt.ItemDataRole.UserRole)

        @Slot()
        def on_delete_action():
            btn = QMessageBox.question(
                self.mw_parent,
                'syncServer - Client',
                f"Are you sure you want to delete the file '{item_data.path}'?",
                buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                defaultButton=QMessageBox.StandardButton.No
            )
            if btn == QMessageBox.StandardButton.No:
                return
            
            self.ctrl_parent.delete_ctrl.delete_file_triggered(item_data.path)
        
        if item_data.data_type == 'folder':
            return None
        
        delete_action = QAction("Delete Selected File", self)
        delete_action.triggered.connect(on_delete_action)

        return delete_action

    def file_rename_action(self, item: QListWidgetItem) -> QAction | None:
        item_data: FileListWidgetData = item.data(Qt.ItemDataRole.UserRole)

        @Slot()
        def on_rename_action():
            self.rename_dialog = RenameFileDialog(self, item_data.path)
            self.rename_dialog.dataComplete.connect(call_rename_triggered)

            self.rename_dialog.exec()
        
        @Slot(PurePosixPath)
        def call_rename_triggered(new_path: PurePosixPath):
            self.ctrl_parent.rename_ctrl.rename_file_triggered(item_data.path, new_path)
        
        if item_data.data_type == 'folder':
            return None
        
        rename_action = QAction("Rename Selected File", self)
        rename_action.triggered.connect(on_rename_action)

        return rename_action

    def file_download_action(self, item: QListWidgetItem) -> QAction | None:
        item_data: FileListWidgetData = item.data(Qt.ItemDataRole.UserRole)

        @Slot()
        def on_download_action():
            self.ctrl_parent.download_ctrl.download_file_triggered(item_data.path)

        if item_data.data_type == 'folder':
            return None
        
        download_action = QAction("Download Selected File", self)
        download_action.triggered.connect(on_download_action)

        return download_action        


class UploadController(QObject):
    uploadStarted = Signal(UploadStartedState)
    uploadComplete = Signal(str, GenericSuccess)

    def __init__(self, ctrl_parent: FilesTabController):
        super().__init__(ctrl_parent.app_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client

        self.ui = ctrl_parent.ui
        self.file_uploads: dict[str, list[WorkerThread, QThread]] = {}

    @Slot()
    def upload_file_triggered(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self.mw_parent, "Open File", "", 
            "All Files (*)"
        )
        if not file_path:
            return

        path = Path(file_path)

        # Copy current state before uploading
        folder_contents = self.ctrl_parent.current_folder_contents.model_copy(deep=True)
        current_folder = PurePosixPath(str(self.ctrl_parent.current_folder))

        for file in folder_contents.files:
            if file.name != path.name:
                continue

            btn = QMessageBox.question(
                self.mw_parent,
                'syncServer - Client',
                f"File '{file.name}' already exists, overwrite it with this upload?",
                buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                defaultButton=QMessageBox.StandardButton.No
            )
            if btn == QMessageBox.StandardButton.No:
                return
            
            self.handle_file_update(path, current_folder)
            return
        
        random_id = secrets.token_hex(16)
        func = partial(
            self.main_client.files.upload_file,
            str(current_folder), path.name, file_path
        )
        
        upload_worker = WorkerThread(func)
        upload_thread = QThread(self)
        
        upload_worker.moveToThread(upload_thread)
        
        upload_worker.dataReady.connect(
            lambda data, random_id=random_id: self.upload_complete(data, random_id)
        )
        upload_worker.excReceived.connect(self.ctrl_parent.on_worker_exc)
        
        upload_thread.started.connect(upload_worker.run)
        upload_worker.dataReady.connect(upload_thread.quit)

        upload_worker.excReceived.connect(upload_thread.quit)
        upload_thread.start()

        upload_started_state: UploadStartedState = UploadStartedState(
            random_id=random_id, local_path=path,
            server_path=current_folder / path.name
        )

        self.uploadStarted.emit(upload_started_state)
        self.file_uploads[random_id] = [upload_worker, upload_thread]
    
    def handle_file_update(self, path: Path, current_folder: PurePosixPath):
        random_id = secrets.token_hex(16)
        func = partial(
            self.main_client.files.update_file,
            str(current_folder), path.name, str(path)
        )

        update_worker = WorkerThread(func)
        update_thread = QThread(self)
        
        update_worker.moveToThread(update_thread)
        
        update_worker.dataReady.connect(
            lambda data, random_id=random_id: self.upload_complete(data, random_id)
        )
        update_worker.excReceived.connect(self.ctrl_parent.on_worker_exc)
        
        update_thread.started.connect(update_worker.run)
        update_worker.dataReady.connect(update_thread.quit)

        update_worker.excReceived.connect(update_thread.quit)
        update_thread.start()

        upload_started_state: UploadStartedState = UploadStartedState(
            random_id=random_id, local_path=path,
            server_path=current_folder / path.name
        )

        self.uploadStarted.emit(upload_started_state)
        self.file_uploads[random_id] = [update_worker, update_thread]
    
    def upload_complete(self, data: GenericSuccess, random_id: str):
        self.uploadComplete.emit(random_id, data)
        self.file_uploads.pop(random_id, None)


class DeleteController(QObject):
    deleteComplete = Signal(str, GenericSuccess)

    def __init__(self, ctrl_parent: FilesTabController):
        super().__init__(ctrl_parent.app_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client

        self.ui = ctrl_parent.ui
        self.file_deletes: dict[str, list[WorkerThread, QThread]] = {}

    def delete_file_triggered(self, file_path: PurePosixPath):
        random_id = secrets.token_hex(16)

        func = partial(
            self.main_client.files.delete_file,
            str(self.ctrl_parent.current_folder), file_path.name
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

        self.file_deletes[random_id] = [delete_worker, delete_thread]
        self.ui.statusbar.showMessage(
            f"Files - Deleting file '{file_path}'",
            timeout=5000
        )

    def delete_complete(self, data: GenericSuccess, random_id: str):
        self.deleteComplete.emit(random_id, data)
        self.file_deletes.pop(random_id, None)


class RenameController(QObject):
    renameComplete = Signal(str, GenericSuccess)

    def __init__(self, ctrl_parent: FilesTabController):
        super().__init__(ctrl_parent.app_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client

        self.ui = ctrl_parent.ui
        self.file_renames: dict[str, list[WorkerThread, QThread]] = {}

    def rename_file_triggered(self, old_path: PurePosixPath, new_path: PurePosixPath):
        random_id = secrets.token_hex(16)

        func = partial(
            self.main_client.files.rename_file,
            str(self.ctrl_parent.current_folder), old_path.name,
            new_path.name
        )
        rename_worker = WorkerThread(func)
        rename_thread = QThread(self)
        
        rename_worker.moveToThread(rename_thread)
        
        rename_worker.dataReady.connect(
            lambda data, random_id=random_id: self.rename_complete(data, random_id)
        )
        rename_worker.excReceived.connect(self.ctrl_parent.on_worker_exc)
        
        rename_thread.started.connect(rename_worker.run)
        rename_worker.dataReady.connect(rename_thread.quit)

        rename_worker.excReceived.connect(rename_thread.quit)
        rename_thread.start()

        self.file_renames[random_id] = [rename_worker, rename_thread]
        self.ui.statusbar.showMessage(
            f"Files - Renaming file '{old_path}' to '{new_path}'",
            timeout=5000
        )

    def rename_complete(self, data: GenericSuccess, random_id: str):
        self.renameComplete.emit(random_id, data)
        self.file_renames.pop(random_id, None)


class DownloadController(QObject):
    downloadStarted = Signal(DownloadStartedState)
    downloadComplete = Signal(str, None)

    def __init__(self, ctrl_parent: FilesTabController):
        super().__init__(ctrl_parent.app_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client

        self.ui = ctrl_parent.ui
        self.file_downloads: dict[str, list[WorkerThread, QThread]] = {}

    def download_file_triggered(self, server_path: PurePosixPath):
        local_path, _ = QFileDialog.getSaveFileName(
            parent=self.mw_parent,
            caption="Save To File",
            dir=server_path.name,
            filter='All Files (*)'
        )
        if not local_path:
            return

        path = Path(local_path)
        
        # Copy current state before downloading
        current_folder = PurePosixPath(str(self.ctrl_parent.current_folder))
        
        random_id = secrets.token_hex(16)
        func = partial(
            self.main_client.files.download_file,
            str(current_folder), server_path.name, path
        )
        
        download_worker = WorkerThread(func)
        download_thread = QThread(self)
        
        download_worker.moveToThread(download_thread)
        
        download_worker.dataReady.connect(
            lambda data, random_id=random_id: self.download_complete(data, random_id)
        )
        download_worker.excReceived.connect(self.ctrl_parent.on_worker_exc)
        
        download_thread.started.connect(download_worker.run)
        download_worker.dataReady.connect(download_thread.quit)

        download_worker.excReceived.connect(download_thread.quit)
        download_thread.start()

        download_started_state: DownloadStartedState = DownloadStartedState(
            random_id=random_id, local_path=path,
            server_path=server_path
        )

        self.downloadStarted.emit(download_started_state)
        self.file_downloads[random_id] = [download_worker, download_thread]
    
    def download_complete(self, data: None, random_id: str):
        self.downloadComplete.emit(random_id, data)
        self.file_downloads.pop(random_id, None)


class RenameFileDialog(QDialog):
    dataComplete = Signal(PurePosixPath)

    def __init__(self, ctrl_parent: FilesTabController, old_path: PurePosixPath):
        super().__init__(ctrl_parent.mw_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client
        self.ui = Ui_RenameFileDialog()    

        self.ui.setupUi(self)

        self.old_path = old_path
        self.ui.oldFilenameLineEdit.setText(str(old_path))

        self.ui.newFilenameLineEdit.setText(str(old_path))

    def accept(self):
        new_path = self.ui.newFilenameLineEdit.text()
        if not new_path:
            QMessageBox.warning(
                self.mw_parent,
                'syncServer - Client',
                "Enter a valid path and try again.",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok
            )
            return
        
        posix_new_path = PurePosixPath(new_path)
        if posix_new_path.parent != self.old_path.parent:
            QMessageBox.warning(
                self.mw_parent,
                'syncServer - Client',
                "New file path is not relative to old path, make sure the folder is the same.",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok
            )
            return
        
        if posix_new_path == self.old_path:
            QMessageBox.warning(
                self.mw_parent,
                'syncServer - Client',
                "New file path is the same as the old path, check the name and try again.",
                buttons=QMessageBox.StandardButton.Ok,
                defaultButton=QMessageBox.StandardButton.Ok
            )
            return
        
        self.dataComplete.emit(posix_new_path)
        return super().accept()


# TODO: Make a custom context menu to interact with the downloads/uploads
class FilesDownloadManagerDialog(QDialog):
    def __init__(self, ctrl_parent: FilesTabController):
        super().__init__(ctrl_parent.mw_parent)

        self.mw_parent = ctrl_parent.mw_parent
        self.ctrl_parent = ctrl_parent

        self.main_client = ctrl_parent.main_client
        self.ui = Ui_FilesDownloadManagerDialog()    

        self.ui.setupUi(self)
        self.running_downloads: dict[str, DownloadStartedState] = {}

        self.running_uploads: dict[str, UploadStartedState] = {}

    def add_running_download(self, state: DownloadStartedState):
        data_str = f"Downloading {state.server_path} -> {state.local_path}"

        dl_item = QListWidgetItem(data_str)
        dl_item.setData(Qt.ItemDataRole.UserRole, state)

        self.running_downloads[state.random_id] = state
        self.ui.runningDownloadsListWidget.addItem(dl_item)

    def complete_download(self, random_id: str):
        state = self.running_downloads[random_id]
        data_str = f"Download complete {state.server_path} -> {state.local_path}"

        complete_item = QListWidgetItem(data_str)

        # Get all items with order
        lw_items = [
            self.ui.runningDownloadsListWidget.item(i)
            for i in range(self.ui.runningDownloadsListWidget.count())
        ]

        for item in lw_items:
            item_data: DownloadStartedState = item.data(Qt.ItemDataRole.UserRole)
            index = self.ui.runningDownloadsListWidget.indexFromItem(item)

            if item_data.random_id != random_id:
                continue

            self.ui.runningDownloadsListWidget.takeItem(index.row())

        self.ui.completedDownloadsListWidget.addItem(complete_item)
        self.running_downloads.pop(random_id, None)

    def add_running_upload(self, state: UploadStartedState):
        data_str = f"Uploading {state.local_path} -> {state.server_path}"

        dl_item = QListWidgetItem(data_str)
        dl_item.setData(Qt.ItemDataRole.UserRole, state)

        self.running_uploads[state.random_id] = state
        self.ui.runningUploadsListWidget.addItem(dl_item)
    
    def complete_upload(self, random_id: str):
        state = self.running_uploads[random_id]
        data_str = f"Upload complete {state.local_path} -> {state.server_path}"

        complete_item = QListWidgetItem(data_str)

        # Get all items with order
        lw_items = [
            self.ui.runningUploadsListWidget.item(i)
            for i in range(self.ui.runningUploadsListWidget.count())
        ]

        for item in lw_items:
            item_data: UploadStartedState = item.data(Qt.ItemDataRole.UserRole)
            index = self.ui.runningUploadsListWidget.indexFromItem(item)

            if item_data.random_id != random_id:
                continue

            self.ui.runningUploadsListWidget.takeItem(index.row())

        self.ui.completedUploadsListWidget.addItem(complete_item)
        self.running_uploads.pop(random_id, None)
