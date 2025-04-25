import sys
import webbrowser
import traceback

from PySide6.QtWidgets import QMainWindow, QApplication, QMessageBox
from PySide6.QtCore import QThread, Slot
from PySide6.QtGui import QCloseEvent
from .interface import ConfigManager
from .ui.main import Ui_MainWindow
from .controllers.login import LoginController
from .controllers.apps import AppsController
from .workers import WorkerThread


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.login_ctrl = None
        self.apps_ctrl = None

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.mainStackedWidget.setCurrentIndex(0)
        self.config_manager = ConfigManager()

        # TODO: Make a dialog that shows copyright info and link to source code
        # link it to the fastapi-rewrite branch until its merged into main
        self.ui.actionSource_Code.triggered.connect(
            lambda: webbrowser.open('https://github.com/NewGuy103/syncServer/tree/fastapi-rewrite')
        )
        self.setup_config()
    
    def setup_config(self):
        self.setup_worker = WorkerThread(self.config_manager.load_from_save)
        self.setup_thread = QThread(self)
        
        self.setup_worker.moveToThread(self.setup_thread)
        
        self.setup_worker.dataReady.connect(self.config_loaded)
        self.setup_worker.excReceived.connect(self.config_load_failed)
        
        self.setup_thread.started.connect(self.setup_worker.run)
        self.setup_worker.dataReady.connect(self.setup_thread.quit)

        self.setup_worker.excReceived.connect(self.setup_thread.quit)
        self.setup_thread.start()
    
    @Slot(None)
    def config_loaded(self, data: None):
        self.login_ctrl = LoginController(self)
        self.apps_ctrl = AppsController(self)

        self.login_ctrl.login_done.connect(self.apps_ctrl.setup)
        self.login_ctrl.check_saved_credentials()

    @Slot(Exception)
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
