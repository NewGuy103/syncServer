import sys
import webbrowser
import traceback

from PySide6.QtWidgets import QMainWindow, QApplication, QMessageBox
from PySide6.QtGui import QCloseEvent

from .config import AppSettings
from .ui.main import Ui_MainWindow
from .controllers.login import LoginController
from .controllers.apps import AppsController


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.login_ctrl = None
        self.apps_ctrl = None

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.mainStackedWidget.setCurrentIndex(0)

        # TODO: Make a dialog that shows copyright info and link to source code
        # link it to the fastapi-rewrite branch until its merged into main
        self.ui.actionSource_Code.triggered.connect(
            lambda: webbrowser.open('https://github.com/NewGuy103/syncServer/tree/fastapi-rewrite')
        )
        self.setup_config()
    
    def setup_config(self):
        try:
            self.app_settings = AppSettings()
            self.config_loaded()
        except Exception as exc:
            self.config_load_failed(exc)

    def config_loaded(self):
        self.login_ctrl = LoginController(self)
        self.apps_ctrl = AppsController(self)

        self.login_ctrl.login_done.connect(self.apps_ctrl.setup)
        self.login_ctrl.check_saved_credentials()

    def config_load_failed(self, exc: Exception):
        tb: str = ''.join(traceback.format_exception(exc, limit=1))

        QMessageBox.critical(
            self,
            'syncServer - Client',
            f"Could not load configuration, exiting.\nTraceback:\n\n{tb}"
        )
        self.close()
    
    def closeEvent(self, event: QCloseEvent):
        if self.apps_ctrl is not None:
            if self.apps_ctrl.main_client is not None:
                self.apps_ctrl.main_client.close()
        
        event.accept()
        return super().closeEvent(event)


def main():
    app = QApplication(sys.argv)

    mw = MainWindow()  # type: ignore
    mw.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
