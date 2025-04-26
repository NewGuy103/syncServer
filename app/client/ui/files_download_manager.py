# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'files_download_manager.ui'
##
## Created by: Qt User Interface Compiler version 6.9.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QAbstractButton, QApplication, QDialog, QDialogButtonBox,
    QFrame, QLabel, QListWidget, QListWidgetItem,
    QSizePolicy, QVBoxLayout, QWidget)

class Ui_FilesDownloadManagerDialog(object):
    def setupUi(self, FilesDownloadManagerDialog):
        if not FilesDownloadManagerDialog.objectName():
            FilesDownloadManagerDialog.setObjectName(u"FilesDownloadManagerDialog")
        FilesDownloadManagerDialog.resize(716, 632)
        self.verticalLayout = QVBoxLayout(FilesDownloadManagerDialog)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.mainDialogFrame = QFrame(FilesDownloadManagerDialog)
        self.mainDialogFrame.setObjectName(u"mainDialogFrame")
        self.mainDialogFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.mainDialogFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.verticalLayout_2 = QVBoxLayout(self.mainDialogFrame)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.runningDownloadsLayout = QVBoxLayout()
        self.runningDownloadsLayout.setObjectName(u"runningDownloadsLayout")
        self.runningDownloadsLabel = QLabel(self.mainDialogFrame)
        self.runningDownloadsLabel.setObjectName(u"runningDownloadsLabel")

        self.runningDownloadsLayout.addWidget(self.runningDownloadsLabel)

        self.runningDownloadsListWidget = QListWidget(self.mainDialogFrame)
        self.runningDownloadsListWidget.setObjectName(u"runningDownloadsListWidget")

        self.runningDownloadsLayout.addWidget(self.runningDownloadsListWidget)


        self.verticalLayout_2.addLayout(self.runningDownloadsLayout)

        self.completedDownloadsLayout = QVBoxLayout()
        self.completedDownloadsLayout.setObjectName(u"completedDownloadsLayout")
        self.completedDownloadsLabel = QLabel(self.mainDialogFrame)
        self.completedDownloadsLabel.setObjectName(u"completedDownloadsLabel")

        self.completedDownloadsLayout.addWidget(self.completedDownloadsLabel)

        self.completedDownloadsListWidget = QListWidget(self.mainDialogFrame)
        self.completedDownloadsListWidget.setObjectName(u"completedDownloadsListWidget")

        self.completedDownloadsLayout.addWidget(self.completedDownloadsListWidget)


        self.verticalLayout_2.addLayout(self.completedDownloadsLayout)

        self.runningUploadsLayout = QVBoxLayout()
        self.runningUploadsLayout.setObjectName(u"runningUploadsLayout")
        self.runningUploadsLabel = QLabel(self.mainDialogFrame)
        self.runningUploadsLabel.setObjectName(u"runningUploadsLabel")

        self.runningUploadsLayout.addWidget(self.runningUploadsLabel)

        self.runningUploadsListWidget = QListWidget(self.mainDialogFrame)
        self.runningUploadsListWidget.setObjectName(u"runningUploadsListWidget")

        self.runningUploadsLayout.addWidget(self.runningUploadsListWidget)


        self.verticalLayout_2.addLayout(self.runningUploadsLayout)

        self.completedUploadsLayout = QVBoxLayout()
        self.completedUploadsLayout.setObjectName(u"completedUploadsLayout")
        self.completedUploadsLabel = QLabel(self.mainDialogFrame)
        self.completedUploadsLabel.setObjectName(u"completedUploadsLabel")

        self.completedUploadsLayout.addWidget(self.completedUploadsLabel)

        self.completedUploadsListWidget = QListWidget(self.mainDialogFrame)
        self.completedUploadsListWidget.setObjectName(u"completedUploadsListWidget")

        self.completedUploadsLayout.addWidget(self.completedUploadsListWidget)


        self.verticalLayout_2.addLayout(self.completedUploadsLayout)


        self.verticalLayout.addWidget(self.mainDialogFrame)

        self.dialogButtonBox = QDialogButtonBox(FilesDownloadManagerDialog)
        self.dialogButtonBox.setObjectName(u"dialogButtonBox")
        self.dialogButtonBox.setOrientation(Qt.Orientation.Horizontal)
        self.dialogButtonBox.setStandardButtons(QDialogButtonBox.StandardButton.Close|QDialogButtonBox.StandardButton.Ok)

        self.verticalLayout.addWidget(self.dialogButtonBox)


        self.retranslateUi(FilesDownloadManagerDialog)
        self.dialogButtonBox.accepted.connect(FilesDownloadManagerDialog.accept)
        self.dialogButtonBox.rejected.connect(FilesDownloadManagerDialog.reject)

        QMetaObject.connectSlotsByName(FilesDownloadManagerDialog)
    # setupUi

    def retranslateUi(self, FilesDownloadManagerDialog):
        FilesDownloadManagerDialog.setWindowTitle(QCoreApplication.translate("FilesDownloadManagerDialog", u"syncServer - Download Manager", None))
        self.runningDownloadsLabel.setText(QCoreApplication.translate("FilesDownloadManagerDialog", u"Running Downloads", None))
        self.completedDownloadsLabel.setText(QCoreApplication.translate("FilesDownloadManagerDialog", u"Completed Downloads", None))
        self.runningUploadsLabel.setText(QCoreApplication.translate("FilesDownloadManagerDialog", u"Running Uploads", None))
        self.completedUploadsLabel.setText(QCoreApplication.translate("FilesDownloadManagerDialog", u"Completed Uploads", None))
    # retranslateUi

