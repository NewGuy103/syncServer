import os
import requests

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QMessageBox, 
    QDialog, QFileDialog, QVBoxLayout,
    QLabel, QListWidget, QScrollArea,
    QWidget, QLineEdit, QDialogButtonBox,
    QTextEdit
)
from PyQt5.QtCore import Qt, QDateTime

from cui import (
    Ui_loginWindow, Ui_MainWindow, Ui_FileManagerDialog,
    Ui_DeletedFilesDialog, Ui_DirManagerDialog,
    Ui_APIKeyManagerDialog, Ui_APIKeyCreateDialog
)
from interface import ServerInterface, logger


def make_msgbox(
        title: str, text: str,
        extra_text: str = "",
        
        icon: QMessageBox.Icon = QMessageBox.Information
) -> QMessageBox:
    msgbox: QMessageBox = QMessageBox()
    msgbox.setWindowTitle(title)

    msgbox.setText(text)
    msgbox.setInformativeText(extra_text)

    msgbox.setIcon(icon)
    return msgbox


class FileManagerDialog(QDialog):
    def __init__(
            self, interface: ServerInterface, 
            parent: "MainApp" = None
    ) -> None:
        super().__init__()
        self.ui: Ui_FileManagerDialog = Ui_FileManagerDialog()
        self.ui.setupUi(self)

        self.interface: ServerInterface = interface

        self.parent: MainApp = parent
        self.parent_widgets: dict[str, QListWidget] = parent.list_widgets

        self.setWindowTitle("syncServer File Manager")
        self.initUI()
    
    def local_filedialog_open(self, path_inputbox: QLineEdit):
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", 
            "All Files (*)", options=options
        )

        if filename:
            path_inputbox.setText(filename)
            
    def remote_filedialog_open(self, path_inputbox: QLineEdit):
        def on_listwidget_click(item):
            path_input.setText(item.text())

        dialog: QDialog = QDialog()
        dialog.setFixedSize(400, 250)

        dialog.setWindowTitle("Choose a remote file")
        dialogLayout = QVBoxLayout(dialog)

        scroll_area: QScrollArea = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)

        content_widget: QWidget = QWidget()
        layout: QVBoxLayout = QVBoxLayout(content_widget)

        for dir_path, list_widget in self.parent_widgets.items():
            label: QLabel = QLabel(dir_path)

            label.setAlignment(Qt.AlignCenter)
            cloned_widget: QListWidget = QListWidget()

            cloned_widget.setFixedHeight(120)
            cloned_widget.itemClicked.connect(on_listwidget_click)

            for i in range(list_widget.count()):
                cloned_widget.addItem(list_widget.item(i).text())
            
            layout.addWidget(label)
            layout.addWidget(cloned_widget)

        path_input: QLineEdit = QLineEdit()
        button_box: QLineEdit = QDialogButtonBox()

        button_box.setStandardButtons(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        scroll_area.setWidget(content_widget)

        dialogLayout.addWidget(scroll_area)
        dialogLayout.addWidget(path_input)

        dialogLayout.addWidget(button_box)
        dialog.setLayout(dialogLayout)

        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)

        code: int = dialog.exec_()
        if code == QDialog.Accepted:
            path_inputbox.setText(path_input.text())
    
    def initUI(self):
        self.ui.fileUploadDialogButton.clicked.connect(
            lambda: self.local_filedialog_open(self.ui.fileUploadPathInput))
        self.ui.fileModifyDialogButton.clicked.connect(
            lambda: self.local_filedialog_open(self.ui.fileModifyPathInput))
        
        self.ui.fileDeletePathSelectorButton.clicked.connect(
            lambda: self.remote_filedialog_open(self.ui.fileDeletePathInput))
        self.ui.fileReadPathSelector.clicked.connect(
            lambda: self.remote_filedialog_open(self.ui.fileReadPathInput))
        
        self.ui.fileUploadButton.clicked.connect(self.remote_file_upload)
        self.ui.fileModifyButton.clicked.connect(self.remote_file_modify)

        self.ui.fileDeleteButton.clicked.connect(self.remote_file_delete)
        self.ui.fileReadButton.clicked.connect(self.remote_file_download)

    def remote_file_upload(self):
        local_path: str = self.ui.fileUploadPathInput.text()
        if not os.path.isfile(local_path):
            msgbox: QMessageBox = make_msgbox(
                "syncServer", "File does not exist",
                extra_text=f"File '{local_path}' does not exist",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        remote_path: str = self.ui.fileUploadRemoteNameInput.text()
        if not remote_path:
            msgbox: QMessageBox = make_msgbox(
                "syncServer", "Remote path is blank",
                extra_text="Check if remote path is not blank",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return

        remote_path: str = remote_path.replace("%n%", os.path.basename(local_path))
        result: int | dict[str, dict[str, str]] = self.interface.files.upload([[local_path, remote_path]])

        if result == 0:
            msgbox = make_msgbox(
                "syncServer", "Upload Successful", 
                extra_text=f"Successfully uploaded [{local_path}] as [{remote_path}]"
            )
            msgbox.exec_()
            self.parent.update_list()

            return
        
        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        msgbox_msg: str = ""
        match ecode:
            case "FILE_EXISTS":
                msgbox_msg = "The remote path already exists on the server."
            case "EMPTY_STREAM":
                msgbox_msg = "The provided file has no contents. Check the file and try again."
            case "NO_DIR_EXISTS":
                msgbox_msg = "The directory path does not exist."
            case _:
                msgbox_msg = f"Failed to upload due to error code [{ecode}]: {emsg}"
        
        msgbox: QMessageBox = make_msgbox(
            "syncServer", "Upload Failed",
            extra_text=msgbox_msg
        )
        msgbox.exec_()

        return

    def remote_file_modify(self):
        local_path: str = self.ui.fileModifyPathInput.text()
        if not os.path.isfile(local_path):
            msgbox: QMessageBox = make_msgbox(
                "syncServer", "File does not exist",
                extra_text=f"File '{local_path}' does not exist",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        remote_path: str = self.ui.fileModifyRemoteNameInput.text()
        if not remote_path:
            msgbox: QMessageBox = make_msgbox(
                "syncServer", "Remote path is blank",
                extra_text="Check if remote path is not blank",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        remote_path: str = remote_path.replace("%n%", os.path.basename(local_path))
        result: int | dict[str, str] = self.interface.files.upload(
            [[local_path, remote_path]], modify_remote=True)

        if result == 0:
            msgbox = make_msgbox(
                "syncServer", "Upload Successful", 
                extra_text=f"Successfully modified [{remote_path}] with [{local_path}]"
            )
            msgbox.exec_()

            self.parent.update_list()
            return
        
        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        msgbox_msg: str = ""
        match ecode:
            case "NO_FILE_EXISTS":
                msgbox_msg = "The remote path does not exist on the server."
            case "EMPTY_STREAM":
                msgbox_msg = "The provided file has no contents. Check the file and try again."
            case "NO_DIR_EXISTS":
                msgbox_msg = "The directory path does not exist."
            case _:
                msgbox_msg = f"Failed to modify [{ecode}]: {emsg}"
        
        msgbox = make_msgbox(
            "syncServer", "Upload Failed",
            extra_text=msgbox_msg
        )
        msgbox.exec_()

        return

    def remote_file_delete(self):
        remote_path: str = self.ui.fileDeletePathInput.text()
        if not remote_path:
            msgbox: QMessageBox = make_msgbox(
                "syncServer", "Remote path is blank",
                extra_text="Check if remote path is not blank",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        perma_delete: bool = self.ui.fileDeleteBypassTrashCheckbox.isChecked() or False
        result: int | dict[str, str] = self.interface.files.remove(
            [remote_path], true_delete=perma_delete)

        if result == 0:
            msgbox = make_msgbox(
                "syncServer", "Delete Successful", 
                extra_text=f"Successfully deleted [{remote_path}]"
            )
            msgbox.exec_()
            self.parent.deleted_files_dialog.update_list()

            self.parent.update_list()
            return
        
        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        match ecode:
            case "NO_FILE_EXISTS":
                msgbox_msg = "The remote path does not exist on the server."
            case "NO_DIR_EXISTS":
                msgbox_msg = "The directory path does not exist."
            case _:
                msgbox_msg = f"Failed to upload due to error code [{ecode}]: {emsg}"
        
        msgbox = make_msgbox(
            "syncServer", "Delete Failed",
            extra_text=msgbox_msg
        )
        msgbox.exec_()
        return

    def remote_file_download(self):
        remote_path: str = self.ui.fileReadPathInput.text()
        if not remote_path:
            msgbox: QMessageBox = make_msgbox(
                "syncServer", "Remote path is blank",
                extra_text="Check if remote path is not blank",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        local_path: str = self.ui.fileReadSaveWhereInput.text()
        if not local_path:
            msgbox: QMessageBox = make_msgbox(
                "syncServer", "Local path is blank",
                extra_text="Check if local path is not blank",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        if not os.path.isabs(local_path):
            path_dir: str = os.path.join(os.path.expanduser("~"), "Downloads", "syncServer")
            os.makedirs(path_dir, exist_ok=True)

            local_path: str = os.path.join(path_dir, local_path)
        
        if os.path.exists(local_path):
            msgbox: QMessageBox = make_msgbox(
                "syncServer", "Local path exists",
                extra_text="A file already exists with the same path, check for conflicts",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        try:
            result: int | dict = self.interface.files.read(remote_path, local_path)
        except OSError as exc:
            msgbox = make_msgbox(
                "syncServer", "Save Failed with Error",
                extra_text=f"Failed to save downloaded file to [{local_path}]: {str(exc)}",
                icon=QMessageBox.Critical
            )
            msgbox.exec_()
            return

        if not isinstance(result, dict):
            msgbox = make_msgbox(
                "syncServer", "Download Successful", 
                extra_text=f"Successfully saved [{remote_path}] as [{local_path}]"
            )
            msgbox.exec_()    
            return
        
        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        match ecode:
            case "NO_FILE_EXISTS":
                msgbox_msg = "The remote path does not exist on the server."
            case "NO_DIR_EXISTS":
                msgbox_msg = "The directory path does not exist."
            case _:
                msgbox_msg = f"Failed to upload due to error code [{ecode}]: {emsg}"
        
        msgbox = make_msgbox(
            "syncServer", "Download Failed",
            extra_text=msgbox_msg
        )
        msgbox.exec_()
        return


class DirManagerDialog(QDialog):
    def __init__(
            self, interface: ServerInterface, 
            parent: "MainApp" = None
    ) -> None:
        super().__init__()

        self.ui: Ui_DirManagerDialog = Ui_DirManagerDialog()
        self.ui.setupUi(self)

        self.interface: ServerInterface = interface

        self.parent: MainApp = parent
        self.list_widgets: dict = parent.list_widgets

        self._list_widget: QListWidget = None
        self._label: QLabel = None

        self.dir_paths: dict[str, list[str]] = {}

        self.content_widget: QWidget = self.ui.mainScrollAreaWidgetContents
        self.layout: QVBoxLayout = QVBoxLayout(self.content_widget)

        self.setWindowTitle("syncServer Directory Manager")
        self.initUI()
    
    def initUI(self):
        def changeInput_onclick(item):
            self.ui.dirPathInput.setText(item.text())
        
        dir_paths: list[str] = self.interface.dirs.get_dir_paths()
        if isinstance(dir_paths, dict):
            ecode: str = dir_paths.get('ecode')
            emsg: str = dir_paths.get('error')

            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Error: Directory paths is an error dictionary',
                extra_text=f"Error Code: {ecode}\nError Message: {emsg}",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()

            logger.error(
                "(DirManagerDialog.initUI): Result is an error dictionary: [%s]",
                dir_paths)
            return

        self._label: QLabel = QLabel("Available directories:")
        lw: QListWidget = QListWidget()

        lw.itemClicked.connect(changeInput_onclick)
        lw.focusOutEvent = lambda event: lw.clearSelection()

        for path in dir_paths:
            lw.addItem(path)
        
        self.layout.addWidget(self._label)
        self.layout.addWidget(lw)

        self._list_widget: QListWidget = lw
        self.ui.createDirButton.clicked.connect(self.remote_dir_create)

        self.ui.deleteDirButton.clicked.connect(self.remote_dir_remove)
        self.ui.listDirButton.clicked.connect(self.remote_dir_list)
    
    def update_list(self):
        dir_paths: list[str] = self.interface.dirs.get_dir_paths()
        if isinstance(dir_paths, dict):
            ecode: str = dir_paths.get('ecode')
            emsg: str = dir_paths.get('error')

            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Error: Directory paths is an error dictionary',
                extra_text=f"Error Code: {ecode}\nError Message: {emsg}",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()

            logger.error(
                "(DirManagerDialog.update_list): Result is an error dictionary: [%s]",
                dir_paths)
            return
        
        self._list_widget.clear()
        for path in dir_paths:
            self._list_widget.addItem(path)
    
    def remote_dir_create(self):
        current_path: str = self.ui.dirPathInput.text()
        if not current_path:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Current directory path is empty',
                extra_text="Enter a directory path first",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        result: int | dict[str, str] = self.interface.dirs.create(current_path)
        if result == 0:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Create Successful',
                extra_text=f"Created directory [{current_path}] successfully",
                icon=QMessageBox.Information
            )
            msgbox.exec_()

            self.update_list()
            return
        
        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        match ecode:
            case "DIR_EXISTS":
                msgbox_msg: str = "Directory already exists, check the path and try again."
            case "INVALID_DIR_PATH":
                msgbox_msg: str = "Directory path is malformed or invalid."
            case _:
                msgbox_msg: str = f"Failed to create directory due to error code [{ecode}]: {emsg}"
        
        msgbox: QMessageBox = make_msgbox(
            'syncServer', 'Create Failed',
            extra_text=msgbox_msg,
            icon=QMessageBox.Warning
        )
        msgbox.exec_()
        return 
    
    def remote_dir_remove(self):
        current_path: str = self.ui.dirPathInput.text()
        if not current_path:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Current directory path is empty',
                extra_text="Enter a directory path first",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        if current_path == "/":
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Cannot remove root directory',
                extra_text="Check the directory path first",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
            
        dialog: QDialog = QDialog()
        dialog.setWindowTitle("syncServer")
        
        layout: QVBoxLayout = QVBoxLayout()
        label: QLabel = QLabel(
            "Do you want to proceed? This will delete the directory, all the files "
            "stored on it, and all deleted files in that directory!")
        
        label.setWordWrap(True)
        layout.addWidget(label)
        
        button_box: QDialogButtonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addWidget(button_box)
        
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)

        dialog.setLayout(layout)
        code: int = dialog.exec_()
        
        if code == QDialog.Rejected:
            return
        
        result: int | dict[str, str] = self.interface.dirs.delete(current_path)
        if result == 0:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Remove Successful',
                extra_text=f"Removed directory [{current_path}] successfully",
                icon=QMessageBox.Information
            )
            msgbox.exec_()

            self.update_list()
            self.parent.update_list()

            self.parent.deleted_files_dialog.update_list()
            return
    
        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        match ecode:
            case "NO_DIR_EXISTS":
                msgbox_msg: str = "Directory does not exist, check the path and try again."
            case "INVALID_DIR_PATH":
                msgbox_msg: str = "Directory path is malformed or invalid."
            case _:
                msgbox_msg: str = f"Failed to create directory due to error code [{ecode}]: {emsg}"
        
        msgbox: QMessageBox = make_msgbox(
            'syncServer', 'Remove Failed',
            extra_text=msgbox_msg,
            icon=QMessageBox.Warning
        )
        msgbox.exec_()
        return
    
    def remote_dir_list(self):
        current_path: str = self.ui.dirPathInput.text()
        if not current_path:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Current directory path is empty',
                extra_text="Enter a directory path first",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        result: list[str] | dict = self.interface.dirs.list_dir(current_path)
        if isinstance(result, dict):
            ecode: str = result.get('ecode')
            emsg: str = result.get('error')

            match ecode:
                case "NO_DIR_EXISTS":
                    msgbox_msg: str = "Directory does not exist, check the path and try again."
                case "INVALID_DIR_PATH":
                    msgbox_msg: str = "Directory path is malformed or invalid."
                case _:
                    msgbox_msg: str = f"Failed to create directory due to error code [{ecode}]: {emsg}"
            
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Listing Failed',
                extra_text=msgbox_msg,
                icon=QMessageBox.Warning
            )
            msgbox.exec_()

            return
        
        delete_list: list[str] = self.interface.dirs.list_dir(current_path, list_deleted_only=True)
        if not result and not delete_list:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Deleted and non-deleted lists are empty',
                extra_text="The directories do not have any files in them.",
                icon=QMessageBox.Information
            )
            msgbox.exec_()

            return
        
        dialog: QDialog = QDialog()

        dialog.setFixedSize(400, 350)
        dialog.setWindowTitle("Directory Listing")

        dialogLayout = QVBoxLayout(dialog)
        scroll_area: QScrollArea = QScrollArea()

        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)

        content_widget: QWidget = QWidget()
        layout: QVBoxLayout = QVBoxLayout(content_widget)

        lw_label1: QLabel = QLabel("Non deleted files:")
        lw_label2: QLabel = QLabel("Deleted files:")

        lw_label1.setAlignment(Qt.AlignCenter)
        lw_label2.setAlignment(Qt.AlignCenter)

        lw_1: QListWidget = QListWidget()
        lw_2: QListWidget = QListWidget()
        
        for path in result: 
            lw_1.addItem(path)
        
        for i, path in enumerate(delete_list):
            lw_2.addItem(f"{path} [version: {i}]")
        
        button_box: QLineEdit = QDialogButtonBox()

        button_box.setStandardButtons(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        scroll_area.setWidget(content_widget)

        dialogLayout.addWidget(scroll_area)
        layout.addWidget(lw_label1)

        layout.addWidget(lw_1)
        layout.addWidget(lw_label2)

        layout.addWidget(lw_2)
        dialogLayout.addWidget(button_box)

        dialog.setLayout(dialogLayout)
        button_box.accepted.connect(dialog.accept)

        button_box.rejected.connect(dialog.reject)
        dialog.exec_()

        return


class DeletedFilesDialog(QDialog):
    def __init__(
            self, interface: ServerInterface, 
            parent: "MainApp" = None
    ) -> None:
        super().__init__()

        self.ui: Ui_DeletedFilesDialog = Ui_DeletedFilesDialog()
        self.ui.setupUi(self)

        self.interface: ServerInterface = interface

        self.parent: MainApp = parent
        self.list_widgets: dict = parent.list_widgets

        self._list_widgets: dict[str, QListWidget] = {}
        self._lw_labels: dict[str, QLabel] = {}

        self.deleted_paths: dict[str, list[str]] = {}

        self.content_widget: QWidget = self.ui.mainScrollAreaWidgetContents
        self.layout: QVBoxLayout = QVBoxLayout(self.content_widget)

        self.setWindowTitle("syncServer Deleted Files")
        self.initUI()

    def changeInput_on_click(self, file_path: str):
        def inner(item):
            split_str: list[str] = item.text().split(" ")
            file_ver: str = split_str[2]

            self.ui.filePathInput.setText(file_path)
            self.ui.fileVersionInput.setText(file_ver)

        return inner

    def initUI(self):
        self.deleted_paths: dict[str, list[str]] | dict[str, str] = self.interface.files.list_deleted(":all:")
        if self.deleted_paths.get('ecode'):
            ecode: str = self.deleted_paths.get('ecode')
            emsg: str = self.deleted_paths.get('error')

            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Deleted Files Fetch Failed: Deleted paths is an error dictionary',
                extra_text=f"Error Code: {ecode}\nError Message: {emsg}",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()

            logger.error(
                "(DeletedFilesDialog.initUI): Failed to fetch files due to error code [%s] "
                "with error [%s]", ecode, emsg
            )
            return
        
        for file_path, file_versions in self.deleted_paths.items():
            if not file_versions:
                logger.debug(
                    "(DeletedFilesDialog.initUI): Skipped remote path '%s', "
                    "no deleted file versions available", file_path
                )
                continue

            self._lw_labels[file_path] = QLabel(f"File: {file_path}")
            self._lw_labels[file_path].setAlignment(Qt.AlignCenter)

            self.layout.addWidget(self._lw_labels[file_path])
            list_widget: QListWidget = QListWidget()

            list_widget.setFixedHeight(120)
            list_widget.itemClicked.connect(self.changeInput_on_click(file_path))

            list_widget.focusOutEvent = lambda event, lw=list_widget: lw.clearSelection()
            for i, path in enumerate(file_versions):
                list_widget.addItem(f"{path} {i}")

            self._list_widgets[file_path] = list_widget
            self.layout.addWidget(list_widget)

        self.ui.restoreFileButton.clicked.connect(self.remote_file_restore)
        self.ui.deleteFileButton.clicked.connect(self.remote_file_truedelete)

        self.ui.removeAllDeletedButton.clicked.connect(self.purge_all_deleted)
    
    def update_list(self) -> int | dict:
        deleted_paths: dict[str, list[str] | str] = self.interface.files.list_deleted(":all:")
        if deleted_paths.get('ecode'):
            return deleted_paths
        
        delpaths_copy: dict[str, list[str]] = self.deleted_paths.copy()
        for file_path, file_versions in delpaths_copy.items():
            new_versions: list[str] = deleted_paths.get(file_path)

            lw: QListWidget = self._list_widgets.get(file_path)
            lw_label: QLabel = self._lw_labels.get(file_path)

            if not new_versions and (lw and lw_label):
                self.layout.removeWidget(lw)
                self.layout.removeWidget(lw_label)

                lw.deleteLater()
                lw_label.deleteLater()

                self.layout.update()
                del self.deleted_paths[file_path]

                del self._list_widgets[file_path]
                del self._lw_labels[file_path]
        
        for file_path, file_versions in deleted_paths.items():
            lw: QListWidget = self._list_widgets.get(file_path)
            lw_label: QLabel = self._lw_labels.get(file_path)
            
            if not file_versions:
                continue
            
            if not lw and not lw_label:
                self._lw_labels[file_path] = QLabel(f"File: {file_path}")
                self._lw_labels[file_path].setAlignment(Qt.AlignCenter)

                self.layout.addWidget(self._lw_labels[file_path])
                new_lw: QListWidget = QListWidget()

                new_lw.setFixedHeight(120)
                new_lw.itemClicked.connect(self.changeInput_on_click(file_path))

                new_lw.focusOutEvent = lambda event: new_lw.clearSelection()
                self._list_widgets[file_path] = new_lw

                self.layout.addWidget(new_lw)
                lw: QListWidget = new_lw
            
            lw.clear()
            self.deleted_paths[file_path] = file_versions

            for i, path in enumerate(file_versions):
                lw.addItem(f"{path} {i}")
            
            if lw.count() == 0:
                self.layout.removeWidget(lw)
                self.layout.removeWidget(lw_label)

                lw.deleteLater()
                lw_label.deleteLater()

                self.layout.update()
                del self.deleted_paths[file_path]

                del self._list_widgets[file_path]
                del self._lw_labels[file_path]

        self.layout.update()
        return 0
    
    def purge_all_deleted(self):
        if not self.deleted_paths:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Delete All Failed',
                extra_text="No files are available for deletion",
                icon=QMessageBox.Information
            )
            msgbox.exec_()
            return
        
        dialog: QDialog = QDialog()
        dialog.setWindowTitle("syncServer")
        
        layout: QVBoxLayout = QVBoxLayout()
        label: QLabel = QLabel("Do you want to proceed? This will delete all the files marked deleted!")

        label.setWordWrap(True)
        layout.addWidget(label)
        
        button_box: QDialogButtonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addWidget(button_box)
        
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)

        dialog.setLayout(layout)
        code: int = dialog.exec_()
        
        if code == QDialog.Rejected:
            return
        
        ok_results: list[str] = []
        fail_results: dict[str, dict] = {}

        if not self.deleted_paths.keys():
            # Check empty list
            return
        
        for file_path in self.deleted_paths.keys():
            res: int | dict = self.interface.files.remove_deleted(file_path, ":all:")
            if res == 0:
                ok_results.append(file_path)
            else:
                fail_results[file_path] = res
        
        self.deleted_paths: dict[str, str] = {}
        for lw in self._list_widgets.values():
            self.layout.removeWidget(lw)
            lw.deleteLater()
        
        for label in self._lw_labels.values():
            self.layout.removeWidget(label)
            label.deleteLater()

        self._list_widgets: dict[str, QListWidget] = {}
        self._lw_labels: dict[str, QLabel] = {}

        self.layout.update()
        logger.info(
            "(DeletedFilesDialog.purge_all_deleted): Mass remove completed, successful: %s, "
            "failed: %s", ok_results, fail_results
        )

        msgbox: QMessageBox = make_msgbox(
            'syncServer', 'Delete All Successful',
            extra_text="Successfully removed all deleted files, details are in the log file",
            icon=QMessageBox.Information
        )
        msgbox.exec_()
        return
    
    def remote_file_restore(self):
        current_path: str = self.ui.filePathInput.text()
        current_version: str = self.ui.fileVersionInput.text()

        if not current_path:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Current file path is empty',
                extra_text="Select or enter a path and try again",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        if not current_version:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Current file version is empty',
                extra_text="Select or enter a version and try again",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        if not current_version.isdigit():
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'File version is not a number',
                extra_text="Enter a number above 0",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return

        current_version: int = int(current_version)
        result: int | dict = self.interface.files.restore(current_path, current_version)

        if result == 0:
            msgbox = make_msgbox(
                "syncServer", "Restore Successful", 
                extra_text=f"Successfully restored [{current_path}] version [{current_version}]"
            )
            msgbox.exec_()

            self.parent.update_list()
            self.update_list()
            return
        
        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        match ecode:
            case "NO_FILE_EXISTS":
                msgbox_msg = "The remote path does not exist on the server."
            case "NO_DIR_EXISTS":
                msgbox_msg = "The directory path does not exist."
            case _:
                msgbox_msg = f"Failed to upload due to error code [{ecode}]: {emsg}"
        
        msgbox = make_msgbox(
            "syncServer", "Restore Failed",
            extra_text=msgbox_msg
        )
        msgbox.exec_()
        return

    def remote_file_truedelete(self):
        current_path: str = self.ui.filePathInput.text()
        current_version: str = self.ui.fileVersionInput.text()

        if not current_path:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Current file path is empty',
                extra_text="Select or enter a path and try again",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        if not current_version:
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Current file version is empty',
                extra_text="Select or enter a version and try again",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        if not current_version.isdigit() and current_version != ":all:":
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'File version is not a number',
                extra_text="Enter a number above 0",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        if current_version != ":all:":
            current_version: int = int(current_version)
        
        result: int | dict = self.interface.files.remove_deleted(
            current_path, delete_which=current_version
        )
        
        if result == 0:
            msgbox = make_msgbox(
                "syncServer", "Delete Successful", 
                extra_text=f"Permanently removed [{current_path}] version [{current_version}]"
            )
            msgbox.exec_()
            
            self.update_list()
            return
        
        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        match ecode:
            case "NO_FILE_EXISTS":
                msgbox_msg = "The remote path does not exist on the server."
            case "NO_DIR_EXISTS":
                msgbox_msg = "The directory path does not exist."
            case _:
                msgbox_msg = f"Failed to upload due to error code [{ecode}]: {emsg}"
        
        msgbox = make_msgbox(
            "syncServer", "True Delete Failed",
            extra_text=msgbox_msg
        )
        msgbox.exec_()
        return


class APIKeyManagerDialog(QDialog):
    def __init__(
            self, interface: ServerInterface, 
            parent: "MainApp" = None
    ) -> None:
        super().__init__()
        self.ui: Ui_APIKeyManagerDialog = Ui_APIKeyManagerDialog()
        self.ui.setupUi(self)

        self.interface: ServerInterface = interface

        self.parent: MainApp = parent
        self.key_info: list = parent.key_info

        self.content_widget: QWidget = self.ui.mainScrollAreaWidgetContents
        self.layout: QVBoxLayout = QVBoxLayout(self.content_widget)

        self.setWindowTitle("syncServer API Key Manager")
        self.key_names: list[str] = []

        self.key_data: dict = {}
        self._textboxes: dict[str, QTextEdit] = {}

        self._txt_labels: dict[str, QLabel] = {}
        self.initUI()
    
    def initUI(self):
        self.ui.createKeyButton.clicked.connect(self.remote_apikey_create)
        self.ui.deleteKeyButton.clicked.connect(self.remote_apikey_delete)

        self.ui.getKeyInfoButton.clicked.connect(self.remote_apikey_getinfo)
        self.key_names: list[str] | dict = self.interface.api_keys.list_keys()
        if isinstance(self.key_names, dict):
            ecode: str = self.key_names.get('ecode')
            emsg: str = self.key_names.get('error')
            
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'API Key Listing Failed: Key names is an error dictionary',
                extra_text=f"Error Code: {ecode}\nError Message: {emsg}",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()

            logger.error(
                "(APIKeyManagerDialog.initUI): Failed to fetch API keys due to error code [%s] "
                "with error [%s]", ecode, emsg
            )
            return
        
        for key_name in self.key_names:
            key_data: list = self.interface.api_keys.get_key_data(key_name=key_name)
            self.key_data[key_name] = key_data

            self._txt_labels[key_name] = QLabel(f"Key name: {key_name}")
            self._txt_labels[key_name].setAlignment(Qt.AlignCenter)
  
            text_edit = QTextEdit()
            text_edit.setPlainText(
                f"API key permissions: {key_data[0]}\n"
                f"Expiry date: {key_data[1]}\n"
                f"Key Expired: {key_data[2]}"
            )

            text_edit.setFixedHeight(60)
            text_edit.setReadOnly(True)  # Make text read-only but selectable

            self._textboxes[key_name] = text_edit
            self.layout.addWidget(self._txt_labels[key_name])

            self.layout.addWidget(text_edit)
    
    def update_list(self) -> int | dict:
        key_names: list[str] | dict = self.interface.api_keys.list_keys()
        if isinstance(key_names, dict):
            ecode: str = key_names.get('ecode')
            emsg: str = key_names.get('error')
            
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'API Key Listing Failed: Key names is an error dictionary',
                extra_text=f"Error Code: {ecode}\nError Message: {emsg}",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()

            logger.error(
                "(APIKeyManagerDialog.update_list): Failed to fetch keys due to error code [%s] "
                "with error [%s]", ecode, emsg
            )
            return

        for i, key_name in enumerate(self.key_names.copy()):
            txtbox: QTextEdit = self._textboxes.get(key_name)
            label: QLabel = self._txt_labels.get(key_name)

            if key_name not in key_names and (txtbox and label):
                self.layout.removeWidget(txtbox)
                self.layout.removeWidget(label)

                txtbox.deleteLater()
                label.deleteLater()
                
                del self.key_names[i]
                del self.key_data[key_name]

                del self._textboxes[key_name]
                del self._txt_labels[key_name]
        
        self.layout.update()
        for key_name in key_names:
            if key_name in self.key_names:
                logger.debug(
                    "(APIKeyManagerDialog.update_list): Skipped key '%s', already exists in layout",
                    key_name
                )
                continue
            
            key_data: list = self.interface.api_keys.get_key_data(key_name=key_name)
            self.key_data[key_name] = key_data

            self._txt_labels[key_name] = QLabel(f"Key name: {key_name}")
            self._txt_labels[key_name].setAlignment(Qt.AlignCenter)
  
            text_edit = QTextEdit()
            text_edit.setPlainText(
                f"API key permissions: {key_data[0]}\n"
                f"Expiry date: {key_data[1]}\n"
                f"Key Expired: {key_data[2]}"
            )

            text_edit.setFixedHeight(60)
            text_edit.setReadOnly(True)  # Make text read-only but selectable

            self._textboxes[key_name] = text_edit
            self.layout.addWidget(self._txt_labels[key_name])

            self.layout.addWidget(text_edit)

        self.key_names: list = key_names
        return 0
    
    def remote_apikey_create(self):
        keycreate_ui: Ui_APIKeyCreateDialog = Ui_APIKeyCreateDialog()
        dialog: QDialog = QDialog()

        keycreate_ui.setupUi(dialog)
        dialog.setWindowTitle("Create API key")

        keycreate_ui.keyExpiryDateTimeEdit.setDateTime(QDateTime.currentDateTime())
        exec_res: int = dialog.exec_()

        if exec_res == QDialog.Rejected:
            return
        
        key_name: str = keycreate_ui.keyNameInput.text()
        if not key_name:
            msgbox = make_msgbox(
                "syncServer", "Key name is empty",
                extra_text="Enter a valid key name and try again"
            )
            msgbox.exec_()
            return
        
        exp_date: str = keycreate_ui.keyExpiryDateTimeEdit.date().toString("yyyy-MM-dd")
        exp_time: str = keycreate_ui.keyExpiryDateTimeEdit.time().toString("hh:mm:ss")

        key_expiry: str = f"{exp_date} {exp_time}"  # %Y-%M-%D %H:%M:%S
        key_perms: list = []

        create_perm: bool = keycreate_ui.createPermCheckbox.isChecked()
        read_perm: bool = keycreate_ui.readPermCheckbox.isChecked()
        
        update_perm: bool = keycreate_ui.updatePermCheckbox.isChecked()
        delete_perm: bool = keycreate_ui.deletePermCheckbox.isChecked()

        if create_perm:
            key_perms.append('create')
        if read_perm:
            key_perms.append('read')
        if update_perm:
            key_perms.append('update')
        if delete_perm:
            key_perms.append('delete')

        if not key_perms:
            msgbox = make_msgbox(
                "syncServer", "No Permissions Specified",
                extra_text="Check the boxes with the permissions you want to give the key.",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        result: str | dict = self.interface.api_keys.create_key(key_name, key_perms, key_expiry)
        if isinstance(result, str):
            dialog.hide()
            dialog.deleteLater()

            keydialog = QDialog()
            keydialog.setWindowTitle("syncServer")
            
            layout = QVBoxLayout()

            text_edit = QTextEdit()
            text_edit.setPlainText(
                f"Created API key named '{key_name}' successfully!\n"
                "This API key will not be shown anymore, so copy it somewhere!\n"
                f"API key: {result}"
            )

            text_edit.setReadOnly(True)  # Make text read-only but selectable
            layout.addWidget(text_edit)

            keydialog.setLayout(layout)
            keydialog.exec_()

            self.update_list()
            return

        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        match ecode:
            case "APIKEY_EXISTS":
                msgbox_msg: str = "An API key with that name already exists."
            case "DATE_EXPIRED":
                msgbox_msg: str = "Cannot create an already expired API key"
            case _:
                msgbox_msg: str = f"Failed to create API key due to error code [{ecode}]: {emsg}"
        
        msgbox = make_msgbox(
            "syncServer", "Key Create Failed",
            extra_text=msgbox_msg
        )
        msgbox.exec_()
        return 
    
    def remote_apikey_delete(self):
        using_rawkey: bool = self.ui.useRawKeyRadio.isChecked()
        if using_rawkey:
            msgbox = make_msgbox(
                "syncServer", "Cannot use raw API key",
                extra_text="Deleting an API key can only be done using the key name"
            )
            msgbox.exec_()
            return
        
        key_name: str = self.ui.apikeyInput.text()
        if not key_name:
            msgbox = make_msgbox(
                "syncServer", "Key name is empty",
                extra_text="Enter a valid API key and try again"
            )
            msgbox.exec_()
            return
        
        result: int | dict = self.interface.api_keys.delete_key(key_name)
        if result == 0:
            self.update_list()
            msgbox = make_msgbox(
                "syncServer", "Key Deleted Successfully",
                extra_text=f"API key '{key_name}' was deleted successfully"
            )

            msgbox.exec_()
            return
        
        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        match ecode:
            case "INVALID_APIKEY":
                msgbox_msg: str = "API key provided is not valid."
            case _:
                msgbox_msg: str = f"Failed to delete API key due to error code [{ecode}]: {emsg}"

        msgbox = make_msgbox(
            "syncServer", "Key Delete Failed",
            extra_text=msgbox_msg
        )
        msgbox.exec_()

        return
    
    def remote_apikey_getinfo(self):
        key: str = self.ui.apikeyInput.text()
        if not key:
            msgbox = make_msgbox(
                "syncServer", "Key input is empty",
                extra_text="Enter a valid raw API key or API key name"
            )
            msgbox.exec_()
            return
        
        use_rawkey: bool = self.ui.useRawKeyRadio.isChecked()
        if use_rawkey:
            result: list | dict = self.interface.api_keys.get_key_data(api_key=key)
        else:
            result: list | dict = self.interface.api_keys.get_key_data(key_name=key)

        if isinstance(result, list):
            keydialog = QDialog()
            keydialog.setWindowTitle("syncServer")

            keydialog.setFixedSize(200, 150)
            keydialog.setMaximumSize(200, 150)

            keydialog.setMinimumSize(200, 150)
            layout = QVBoxLayout()

            text_edit = QTextEdit()
            text_edit.setPlainText(
                "Key information:\n"
                f"Permissions: {result[0]}\n"
                f"Expiry Date: {result[1]}\n"
                f"Key Expired: {result[2]}"
            )

            text_edit.setReadOnly(True)  # Make text read-only but selectable
            layout.addWidget(text_edit)

            keydialog.setLayout(layout)
            keydialog.exec_()

            keydialog.deleteLater() 
            return
        
        ecode: str = result.get('ecode')
        emsg: str = result.get('error')

        match ecode:
            case "INVALID_APIKEY":
                msgbox_msg: str = "API key provided is not valid."
            case _:
                msgbox_msg: str = f"Failed to create API key due to error code [{ecode}]: {emsg}"
        
        msgbox = make_msgbox(
            "syncServer", "Get Key Info Failed",
            extra_text=msgbox_msg
        )
        msgbox.exec_()
        return 

    
class StartLogin(QMainWindow):
    def __init__(self, url: str = '') -> None:
        super().__init__()

        self.server_url: str = url
        self.perms: list[str] | str = None

        self.interface: ServerInterface | None = None
        self.initUI()
    
    def initUI(self):
        self.loginUI: Ui_loginWindow = Ui_loginWindow()
        self.loginUI.setupUi(self)

        self.loginUI.loginButton.clicked.connect(self.start_login)
        self.setWindowTitle("syncServer Login")

        syncserver_url: str = os.environ.get('SYNCSERVER_URL')
        if not self.server_url and syncserver_url:
            self.server_url: str = syncserver_url
        
        self.loginUI.serverURLInput.setText(self.server_url)
        self.show()
    
    def start_login(self):
        self.server_url: str = self.loginUI.serverURLInput.text()
        
        use_unamePw: bool = self.loginUI.useUnamePwRadio.isChecked()
        use_apiKey: bool = self.loginUI.useApiKeyRadio.isChecked()

        username: str = self.loginUI.usernameInput.text()

        password: str = self.loginUI.passwordInput.text()
        apikey: str = self.loginUI.apikeyInput.text()
        
        if use_unamePw and (not username or not password):
            msgbox: QMessageBox = make_msgbox(
                title='syncServer', text="Missing username/password fields.",
                extra_text="Check the username and password field to see if it's not blank.",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        if use_apiKey and not apikey:
            msgbox: QMessageBox = make_msgbox(
                title='syncServer', text="Missing API key.",
                extra_text="Check the API key field to see if it's not blank.",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
            return
        
        # prevent entering api key to override username
        if use_unamePw:
            apikey: str = ''
        else:
            username: str = ''
            password: str = ''
        
        try:
            self.interface: ServerInterface = ServerInterface(
                self.server_url, username=username, password=password,
                api_key=apikey
            )
        except ValueError as e:
            if use_unamePw:
                msgbox: QMessageBox = make_msgbox(
                    title='syncServer', text="Invalid username/password.",
                    extra_text="Check your username and password and try again.",
                    icon=QMessageBox.Warning
                )
            else:
                msgbox: QMessageBox = make_msgbox(
                    title='syncServer', text="API key authorization failed",
                    extra_text=f"Could not authenticate with server due to error:\n{str(e)}",
                    icon=QMessageBox.Warning
                )
            
            msgbox.exec_()
            return
        except requests.RequestException as e:
            msgbox: QMessageBox = make_msgbox(
                title="syncServer", text="Connection Error",
                extra_text=f"Could not connect to server:\n{str(e)}",
                icon=QMessageBox.Critical
            )
            msgbox.exec_()
            return                
        except Exception as e:
            self.close()
            msgbox: QMessageBox = make_msgbox(
                title="syncServer", text="Application Error",
                extra_text=f"Exception: \n{str(e)}\nMore details in the log file",
                icon=QMessageBox.Critical
            )
            
            logger.exception('')
            msgbox.exec_()
            return
        
        if use_apiKey:
            keydata: list[list[str], str] = self.interface.api_keys.get_key_data(
                api_key=apikey
            )
            if 'read' not in keydata[0] and keydata[0][0] != 'all':
                msgbox: QMessageBox = make_msgbox(
                    title="syncServer", text="Permission Error",
                    extra_text="The API key provided does not have the 'read' permission.\n"
                    "This is required to list the files.",
                    icon=QMessageBox.Warning
                )

                msgbox.exec_()
                return
            
            self.perms: list[str] = keydata[0]
            self.key_info: list = keydata

            self.username: str = "__keyuser"
        else:
            self.perms: list[str] = ['create', 'read', 'update', 'delete']
            self.key_info: list = []

            self.username: str = username

        self.close()
        self.main_app = MainApp(self)

        return 0


class MainApp(QMainWindow):
    def __init__(self, parent: StartLogin = None) -> None:
        super().__init__()
        self.server_url: str = parent.server_url
        self.list_widgets: dict[str, QListWidget] = {}

        self.lw_labels: dict[str, QLabel] = {}
        self.file_paths: dict[str, list[str]] = {}

        self.parent: StartLogin = parent
        self.perms: list[str] = parent.perms
        
        self.key_info: list = parent.key_info
        
        self.interface: ServerInterface = parent.interface
        self.clientUI: Ui_MainWindow = Ui_MainWindow()

        self.clientUI.setupUi(self)
        self.setWindowTitle("syncServer Dashboard")

        self.clientUI.usernameLabel.setText(f"Welcome, {parent.username}")
        self.file_mgr_dialog: FileManagerDialog = FileManagerDialog(self.interface, parent=self)

        self.deleted_files_dialog: DeletedFilesDialog = DeletedFilesDialog(self.interface, parent=self)
        self.dir_mgr_dialog: DirManagerDialog = DirManagerDialog(self.interface, parent=self)

        self.apikey_mgr_dialog: APIKeyManagerDialog = APIKeyManagerDialog(self.interface, parent=self)
        self.clientUI.fileInterfaceButton.clicked.connect(self.file_mgr_dialog.show)

        self.clientUI.showDeletedFilesButton.clicked.connect(self.deleted_files_dialog.show)        
        self.clientUI.dirInterfaceButton.clicked.connect(self.dir_mgr_dialog.show)
        
        self.clientUI.apikeyInterfaceButton.clicked.connect(self.apikey_mgr_dialog.show)
        self.add_files()

        self.show()

    def add_files(self):
        dir_paths: list[str] = self.interface.dirs.get_dir_paths()
        if isinstance(dir_paths, dict):
            ecode: str = dir_paths.get('ecode')
            emsg: str = dir_paths.get('error')

            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Error: Directory paths is an error dictionary',
                extra_text=f"Error Code: {ecode}\nError Message: {emsg}",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()

            logger.error(
                "(MainApp.add_files): Result is an error dictionary: [%s]",
                dir_paths)
            return
        
        content_widget: QWidget = self.clientUI.mainScrollAreaWidgetContents
        self.layout: QVBoxLayout = QVBoxLayout(content_widget)

        for dir_path in dir_paths:
            file_paths: list[str] = self.interface.dirs.list_dir(dir_path)
            if not file_paths:
                continue

            self.file_paths[dir_path] = file_paths

        for dir_path, file_paths in self.file_paths.items():
            label: QLabel = QLabel(f"Directory: {dir_path}")
            label.setAlignment(Qt.AlignCenter)

            self.layout.addWidget(label)
            list_widget: QListWidget = QListWidget()

            list_widget.setFixedHeight(120)
            list_widget.focusOutEvent = lambda event: list_widget.clearSelection()

            for path in file_paths:
                list_widget.addItem(path)

            self.list_widgets[dir_path] = list_widget
            self.lw_labels[dir_path] = label

            self.layout.addWidget(list_widget)
        
    def update_list(self) -> int: 
        dir_paths: list[str] = self.interface.dirs.get_dir_paths()
        if isinstance(dir_paths, dict):
            ecode: str = dir_paths.get('ecode')
            emsg: str = dir_paths.get('error')

            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Error: Directory paths is an error dictionary',
                extra_text=f"Error Code: {ecode}\nError Message: {emsg}",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()

            logger.error(
                "(MainApp.update_list): Result is an error dictionary: [%s]",
                dir_paths)
            return

        tmp_file_paths: dict[str, list[str]] = {}
        for dir_path in dir_paths:
            file_paths: list[str] = self.interface.dirs.list_dir(dir_path)
            tmp_file_paths[dir_path] = file_paths
        
        filepaths_copy: dict[str, list[str]] = self.file_paths.copy()
        for dir_path, file_paths in filepaths_copy.items():
            new_paths: list[str] = tmp_file_paths.get(dir_path)

            lw: QListWidget = self.list_widgets.get(dir_path)
            lw_label: QLabel = self.lw_labels.get(dir_path)

            if not new_paths and (lw and lw_label):
                self.layout.removeWidget(lw)
                self.layout.removeWidget(lw_label)

                lw.deleteLater()
                lw_label.deleteLater()

                self.layout.update()
                del self.file_paths[dir_path]

                del self.list_widgets[dir_path]
                del self.lw_labels[dir_path]
        
        for dir_path, file_paths in tmp_file_paths.items():
            lw: QListWidget = self.list_widgets.get(dir_path)
            lw_label: QLabel = self.lw_labels.get(dir_path)
            
            if not file_paths:
                continue
            
            if not lw and not lw_label:
                self.lw_labels[dir_path] = QLabel(f"Directory: {dir_path}")
                self.lw_labels[dir_path].setAlignment(Qt.AlignCenter)

                self.layout.addWidget(self.lw_labels[dir_path])
                new_lw: QListWidget = QListWidget()

                new_lw.setFixedHeight(120)
                new_lw.focusOutEvent = lambda event: new_lw.clearSelection()

                self.list_widgets[dir_path] = new_lw
                self.layout.addWidget(new_lw)

                lw: QListWidget = new_lw
            
            lw.clear()
            self.file_paths[dir_path] = file_paths

            for path in file_paths:
                lw.addItem(f"{path}")
            
            if not file_paths:
                self.layout.removeWidget(lw)
                self.layout.removeWidget(lw_label)

                lw.deleteLater()
                lw_label.deleteLater()

                self.layout.update()
                del self.file_paths[dir_path]

                del self.list_widgets[dir_path]
                del self.lw_labels[dir_path]

        self.layout.update()
        return 0


def run_gui():
    import sys
    app = QApplication(sys.argv)
    login = StartLogin()  # type: ignore
    sys.exit(app.exec_())


if __name__ == '__main__':
    run_gui()
