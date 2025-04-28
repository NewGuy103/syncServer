# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'trashbin_manager.ui'
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
from PySide6.QtWidgets import (QAbstractButton, QApplication, QComboBox, QDialog,
    QDialogButtonBox, QFrame, QHBoxLayout, QLabel,
    QListWidget, QListWidgetItem, QPushButton, QSizePolicy,
    QVBoxLayout, QWidget)

class Ui_TrashbinManagerDialog(object):
    def setupUi(self, TrashbinManagerDialog):
        if not TrashbinManagerDialog.objectName():
            TrashbinManagerDialog.setObjectName(u"TrashbinManagerDialog")
        TrashbinManagerDialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        TrashbinManagerDialog.resize(588, 536)
        self.verticalLayout = QVBoxLayout(TrashbinManagerDialog)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.mainDialogFrame = QFrame(TrashbinManagerDialog)
        self.mainDialogFrame.setObjectName(u"mainDialogFrame")
        self.mainDialogFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.mainDialogFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.verticalLayout_3 = QVBoxLayout(self.mainDialogFrame)
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.currentFileLabel = QLabel(self.mainDialogFrame)
        self.currentFileLabel.setObjectName(u"currentFileLabel")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.currentFileLabel.sizePolicy().hasHeightForWidth())
        self.currentFileLabel.setSizePolicy(sizePolicy)
        font = QFont()
        font.setPointSize(12)
        self.currentFileLabel.setFont(font)

        self.verticalLayout_3.addWidget(self.currentFileLabel)

        self.deletedFilesListWidget = QListWidget(self.mainDialogFrame)
        self.deletedFilesListWidget.setObjectName(u"deletedFilesListWidget")
        sizePolicy1 = QSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.deletedFilesListWidget.sizePolicy().hasHeightForWidth())
        self.deletedFilesListWidget.setSizePolicy(sizePolicy1)

        self.verticalLayout_3.addWidget(self.deletedFilesListWidget)

        self.currentPageFrame = QFrame(self.mainDialogFrame)
        self.currentPageFrame.setObjectName(u"currentPageFrame")
        sizePolicy.setHeightForWidth(self.currentPageFrame.sizePolicy().hasHeightForWidth())
        self.currentPageFrame.setSizePolicy(sizePolicy)
        self.currentPageFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.currentPageFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.horizontalLayout = QHBoxLayout(self.currentPageFrame)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.deleteAllVersionsButton = QPushButton(self.currentPageFrame)
        self.deleteAllVersionsButton.setObjectName(u"deleteAllVersionsButton")
        sizePolicy2 = QSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        sizePolicy2.setHorizontalStretch(0)
        sizePolicy2.setVerticalStretch(0)
        sizePolicy2.setHeightForWidth(self.deleteAllVersionsButton.sizePolicy().hasHeightForWidth())
        self.deleteAllVersionsButton.setSizePolicy(sizePolicy2)
        icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.EditDelete))
        self.deleteAllVersionsButton.setIcon(icon)

        self.horizontalLayout.addWidget(self.deleteAllVersionsButton)

        self.currentPageLabel = QLabel(self.currentPageFrame)
        self.currentPageLabel.setObjectName(u"currentPageLabel")
        self.currentPageLabel.setFont(font)
        self.currentPageLabel.setAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignTrailing|Qt.AlignmentFlag.AlignVCenter)

        self.horizontalLayout.addWidget(self.currentPageLabel)

        self.goBackButton = QPushButton(self.currentPageFrame)
        self.goBackButton.setObjectName(u"goBackButton")
        sizePolicy3 = QSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Maximum)
        sizePolicy3.setHorizontalStretch(0)
        sizePolicy3.setVerticalStretch(0)
        sizePolicy3.setHeightForWidth(self.goBackButton.sizePolicy().hasHeightForWidth())
        self.goBackButton.setSizePolicy(sizePolicy3)
        icon1 = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.GoPrevious))
        self.goBackButton.setIcon(icon1)

        self.horizontalLayout.addWidget(self.goBackButton)

        self.currentPageComboBox = QComboBox(self.currentPageFrame)
        self.currentPageComboBox.addItem("")
        self.currentPageComboBox.setObjectName(u"currentPageComboBox")
        sizePolicy2.setHeightForWidth(self.currentPageComboBox.sizePolicy().hasHeightForWidth())
        self.currentPageComboBox.setSizePolicy(sizePolicy2)

        self.horizontalLayout.addWidget(self.currentPageComboBox)

        self.goForwardButton = QPushButton(self.currentPageFrame)
        self.goForwardButton.setObjectName(u"goForwardButton")
        sizePolicy2.setHeightForWidth(self.goForwardButton.sizePolicy().hasHeightForWidth())
        self.goForwardButton.setSizePolicy(sizePolicy2)
        icon2 = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.GoNext))
        self.goForwardButton.setIcon(icon2)

        self.horizontalLayout.addWidget(self.goForwardButton)


        self.verticalLayout_3.addWidget(self.currentPageFrame)


        self.verticalLayout.addWidget(self.mainDialogFrame)

        self.dialogButtonBox = QDialogButtonBox(TrashbinManagerDialog)
        self.dialogButtonBox.setObjectName(u"dialogButtonBox")
        self.dialogButtonBox.setOrientation(Qt.Orientation.Horizontal)
        self.dialogButtonBox.setStandardButtons(QDialogButtonBox.StandardButton.Close|QDialogButtonBox.StandardButton.Ok)

        self.verticalLayout.addWidget(self.dialogButtonBox)


        self.retranslateUi(TrashbinManagerDialog)
        self.dialogButtonBox.accepted.connect(TrashbinManagerDialog.accept)
        self.dialogButtonBox.rejected.connect(TrashbinManagerDialog.reject)

        QMetaObject.connectSlotsByName(TrashbinManagerDialog)
    # setupUi

    def retranslateUi(self, TrashbinManagerDialog):
        TrashbinManagerDialog.setWindowTitle(QCoreApplication.translate("TrashbinManagerDialog", u"syncServer - Trashbin Manager", None))
        self.currentFileLabel.setText(QCoreApplication.translate("TrashbinManagerDialog", u"Current File: /file.txt", None))
        self.deleteAllVersionsButton.setText(QCoreApplication.translate("TrashbinManagerDialog", u"Delete All Versions", None))
        self.currentPageLabel.setText(QCoreApplication.translate("TrashbinManagerDialog", u"Page:", None))
        self.goBackButton.setText("")
        self.currentPageComboBox.setItemText(0, QCoreApplication.translate("TrashbinManagerDialog", u"1", None))

        self.goForwardButton.setText("")
    # retranslateUi

