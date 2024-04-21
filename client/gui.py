import os

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QMessageBox, 
    QDialog, QFileDialog, QVBoxLayout,
    QLabel, QListWidget, QScrollArea,
    QWidget, QLineEdit, QDialogButtonBox
)
from PyQt5.QtCore import Qt

from cui import Ui_loginWindow, Ui_MainWindow, Ui_FileManagerDialog, Ui_DeletedFilesDialog
from interface import ServerInterface, ClientEncryptionHandler, logger


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
            cipher_handler: ClientEncryptionHandler | None = None,
            parent: "MainApp" = None
    ) -> None:
        super().__init__()
        self.ui: Ui_FileManagerDialog = Ui_FileManagerDialog()
        self.ui.setupUi(self)

        self.interface: ServerInterface = interface
        self.cipher: ClientEncryptionHandler | None = cipher_handler

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
        
        err_dict: dict[str, str] = result.get(remote_path)
        ecode: str = err_dict.get('ecode')
        emsg: str = err_dict.get('error')

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
        local_path = self.ui.fileModifyPathInput.text()
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
        result = self.interface.files.upload([[local_path, remote_path]], modify_remote=True)

        if result == 0:
            msgbox = make_msgbox(
                "syncServer", "Upload Successful", 
                extra_text=f"Successfully modified [{remote_path}] with [{local_path}]"
            )
            msgbox.exec_()

            self.parent.update_list()
            return
        
        err_dict = result.get(remote_path)
        ecode = err_dict.get('ecode')
        emsg = err_dict.get('error')

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
        result = self.interface.files.remove([remote_path], true_delete=perma_delete)

        if result == 0:
            msgbox = make_msgbox(
                "syncServer", "Delete Successful", 
                extra_text=f"Successfully deleted [{remote_path}]"
            )
            msgbox.exec_()
            self.parent.deleted_files_dialog.update_list()

            self.parent.update_list()
            return
        
        err_dict = result.get(remote_path)
        if not err_dict:
            err_dict: dict = result

        ecode = err_dict.get('ecode')
        emsg = err_dict.get('error')

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
        
        result: bytes = self.interface.files.read(remote_path)
        if not isinstance(result, dict):
            try:
                with open(local_path, 'wb') as f:
                    f.write(result)
            except OSError as exc:
                msgbox = make_msgbox(
                    "syncServer", "Save Failed",
                    extra_text=f"Failed to save downloaded file to [{local_path}]: {str(exc)}"
                )
                msgbox.exec_()
                return
            
            msgbox = make_msgbox(
                "syncServer", "Download Successful", 
                extra_text=f"Successfully saved [{remote_path}] as [{local_path}]"
            )
            msgbox.exec_()
            
            return
        
        ecode = result.get('ecode')
        emsg = result.get('error')

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


class DeletedFilesDialog(QDialog):
    def __init__(
            self, interface: ServerInterface, 
            cipher_handler: ClientEncryptionHandler | None = None,
            parent: "MainApp" = None
    ) -> None:
        super().__init__()

        self.ui: Ui_DeletedFilesDialog = Ui_DeletedFilesDialog()
        self.ui.setupUi(self)

        self.interface: ServerInterface = interface
        self.cipher: ClientEncryptionHandler | None = cipher_handler

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
                logger.info(
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

                del deleted_paths[file_path]
        
        for file_path, file_versions in deleted_paths.items():
            lw: QListWidget = self._list_widgets.get(file_path)
            lw_label: QLabel = self._lw_labels.get(file_path)
            
            if not file_versions:
                continue
            
            if not lw and not lw_label:
                self._lw_labels[file_path] = QLabel(f"File: {file_path}")
                self._lw_labels[file_path].setAlignment(Qt.AlignCenter)

                self.layout.addWidget(self._lw_labels[file_path])
                lw: QListWidget = QListWidget()

                lw.setFixedHeight(120)
                lw.itemClicked.connect(self.changeInput_on_click(file_path))

                lw.focusOutEvent = lambda event: lw.clearSelection()
                self._list_widgets[file_path] = lw

                self.layout.addWidget(lw)
            
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
        dialog: QDialog = QDialog()
        dialog.setWindowTitle("syncServer")
        
        layout: QVBoxLayout = QVBoxLayout()
        label: QLabel = QLabel("Do you want to proceed? This will delete all the files marked deleted!")
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
        
        err_dict = result.get(current_path)
        if not err_dict:
            err_dict: dict = result

        ecode = err_dict.get('ecode')
        emsg = err_dict.get('error')

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
        
        err_dict = result
        ecode = err_dict.get('ecode')
        emsg = err_dict.get('error')

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


class StartLogin(QMainWindow):
    def __init__(self, url: str) -> None:
        super().__init__()
        self.initUI()

        self.server_url: str = url
        self.perms: list[str] | str = None

        self.interface: ServerInterface | None = None
        self.cipher: ClientEncryptionHandler | None = None
    
    def initUI(self):
        def disableClientEncryption():
            self.loginUI.clientEncryptionCheckbox.setStyleSheet('color: #808080;')
            self.loginUI.clientEncryptionCheckbox.setChecked(False)

            self.loginUI.clientEncryptionCheckbox.setCheckable(False)
        
        def enableClientEncryption():
            self.loginUI.clientEncryptionCheckbox.setStyleSheet('color: #000000;')
            self.loginUI.clientEncryptionCheckbox.setCheckable(True)
        
        self.loginUI: Ui_loginWindow = Ui_loginWindow()
        self.loginUI.setupUi(self)

        self.loginUI.loginButton.clicked.connect(self.start_login)
        self.loginUI.useApiKeyRadio.clicked.connect(disableClientEncryption)

        self.loginUI.useUnamePwRadio.clicked.connect(enableClientEncryption)
        self.setWindowTitle("syncServer Login")

        self.show()
    
    def start_login(self):
        use_unamePw: bool = self.loginUI.useUnamePwRadio.isChecked()
        use_apiKey: bool = self.loginUI.useApiKeyRadio.isChecked()

        username: str = self.loginUI.usernameInput.text()
        self.username: str = username

        password: str = self.loginUI.passwordInput.text()
        apikey: str = self.loginUI.apikeyInput.text()
        
        if use_unamePw:
            if not username and not password:
                msgbox: QMessageBox = make_msgbox(
                    title='syncServer', text="Missing username/password fields.",
                    extra_text="Check the username and password field to see if it's not blank.",
                    icon=QMessageBox.Warning
                )
                msgbox.exec_()
                return
            
            try:
                self.interface: ServerInterface = ServerInterface(
                    self.server_url, username=username, password=password
                )
            except ValueError:
                msgbox: QMessageBox = make_msgbox(
                    title='syncServer', text="Invalid username/password.",
                    extra_text="Check your username and password and try again.",
                    icon=QMessageBox.Warning
                )
                msgbox.exec_()
                return
            except RuntimeError as e:
                self.close()
                msgbox: QMessageBox = make_msgbox(
                    title="syncServer", text="Application Error",
                    extra_text=str(e),
                    icon=QMessageBox.Critical
                )

                msgbox.exec_()
                return

            self.perms: list[str] = ["user/pass"]
        else:
            if not apikey:
                msgbox: QMessageBox = make_msgbox(
                    title='syncServer', text="Missing API key.",
                    extra_text="Check the API key field to see if it's not blank.",
                    icon=QMessageBox.Warning
                )
                msgbox.exec_()
                return
            
            try:
                self.interface: ServerInterface = ServerInterface(self.server_url, api_key=apikey)
            except ValueError:
                msgbox: QMessageBox = make_msgbox(
                    title='syncServer', text="Invalid API key.",
                    extra_text="Check if your API key is valid and try again.",
                    icon=QMessageBox.Warning
                )
                msgbox.exec_()
                return
            except RuntimeError as e:
                self.close()
                msgbox: QMessageBox = make_msgbox(
                    title="syncServer", text="Application Error",
                    extra_text=str(e),
                    icon=QMessageBox.Critical
                )

                msgbox.exec_()
                return
            
            self.perms: list[str] = self.interface.api_keys.get_key_perms(apikey)
        
        cse_checked: bool = self.loginUI.clientEncryptionCheckbox.isChecked()
        if cse_checked:
            self.cipher: ClientEncryptionHandler = ClientEncryptionHandler(password)
        else:
            self.cipher = None
        
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

        self.cipher: ClientEncryptionHandler = parent.cipher
        self.interface: ServerInterface = parent.interface

        self.clientUI: Ui_MainWindow = Ui_MainWindow()
        self.clientUI.setupUi(self)

        self.setWindowTitle("syncServer Dashboard")
        self.clientUI.usernameLabel.setText(f"Welcome, {parent.username}")

        self.file_mgr_dialog: FileManagerDialog = FileManagerDialog(self.interface, parent=self)
        self.deleted_files_dialog: DeletedFilesDialog = DeletedFilesDialog(self.interface, parent=self)

        self.clientUI.fileInterfaceButton.clicked.connect(self.file_mgr_dialog.show)
        self.clientUI.showDeletedFilesButton.clicked.connect(self.deleted_files_dialog.show)        

        self.add_files()
        self.show()

    def add_files(self):
        dir_paths: list[str] = self.interface.dirs.get_dir_paths()
        if isinstance(dir_paths, dict):
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Error: Directory paths is an error dictionary',
                extra_text=f"Ended up fetching this: {dir_paths}",
                icon=QMessageBox.Warning
            )
            msgbox.exec_()
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
            msgbox: QMessageBox = make_msgbox(
                'syncServer', 'Error: Directory paths is an error dictionary',
                extra_text=f"Ended up fetching this: {dir_paths}",
                icon=QMessageBox.Warning
            )

            msgbox.exec_()
            return 1

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
                lw: QListWidget = QListWidget()

                lw.setFixedHeight(120)
                lw.focusOutEvent = lambda event: lw.clearSelection()

                self.list_widgets[dir_path] = lw
                self.layout.addWidget(lw)
            
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


if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    login = StartLogin("http://localhost:8561")
    sys.exit(app.exec_())
