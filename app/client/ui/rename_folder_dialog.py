# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'rename_folder_dialog.ui'
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
    QFrame, QLabel, QLineEdit, QSizePolicy,
    QVBoxLayout, QWidget)

class Ui_RenameFolderDialog(object):
    def setupUi(self, RenameFolderDialog):
        if not RenameFolderDialog.objectName():
            RenameFolderDialog.setObjectName(u"RenameFolderDialog")
        RenameFolderDialog.resize(400, 222)
        self.verticalLayout = QVBoxLayout(RenameFolderDialog)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.mainDialogFrame = QFrame(RenameFolderDialog)
        self.mainDialogFrame.setObjectName(u"mainDialogFrame")
        self.mainDialogFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.mainDialogFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.verticalLayoutWidget = QWidget(self.mainDialogFrame)
        self.verticalLayoutWidget.setObjectName(u"verticalLayoutWidget")
        self.verticalLayoutWidget.setGeometry(QRect(10, 10, 351, 61))
        self.oldNameLayout = QVBoxLayout(self.verticalLayoutWidget)
        self.oldNameLayout.setObjectName(u"oldNameLayout")
        self.oldNameLayout.setContentsMargins(0, 0, 0, 0)
        self.oldFolderNameLabel = QLabel(self.verticalLayoutWidget)
        self.oldFolderNameLabel.setObjectName(u"oldFolderNameLabel")

        self.oldNameLayout.addWidget(self.oldFolderNameLabel)

        self.oldFolderNameLineEdit = QLineEdit(self.verticalLayoutWidget)
        self.oldFolderNameLineEdit.setObjectName(u"oldFolderNameLineEdit")
        self.oldFolderNameLineEdit.setReadOnly(True)

        self.oldNameLayout.addWidget(self.oldFolderNameLineEdit)

        self.verticalLayoutWidget_2 = QWidget(self.mainDialogFrame)
        self.verticalLayoutWidget_2.setObjectName(u"verticalLayoutWidget_2")
        self.verticalLayoutWidget_2.setGeometry(QRect(10, 90, 351, 61))
        self.newNameLayout = QVBoxLayout(self.verticalLayoutWidget_2)
        self.newNameLayout.setObjectName(u"newNameLayout")
        self.newNameLayout.setContentsMargins(0, 0, 0, 0)
        self.newFolderNameLabel = QLabel(self.verticalLayoutWidget_2)
        self.newFolderNameLabel.setObjectName(u"newFolderNameLabel")

        self.newNameLayout.addWidget(self.newFolderNameLabel)

        self.newFolderNameLineEdit = QLineEdit(self.verticalLayoutWidget_2)
        self.newFolderNameLineEdit.setObjectName(u"newFolderNameLineEdit")

        self.newNameLayout.addWidget(self.newFolderNameLineEdit)


        self.verticalLayout.addWidget(self.mainDialogFrame)

        self.dialogButtonBox = QDialogButtonBox(RenameFolderDialog)
        self.dialogButtonBox.setObjectName(u"dialogButtonBox")
        self.dialogButtonBox.setOrientation(Qt.Orientation.Horizontal)
        self.dialogButtonBox.setStandardButtons(QDialogButtonBox.StandardButton.Cancel|QDialogButtonBox.StandardButton.Ok)

        self.verticalLayout.addWidget(self.dialogButtonBox)


        self.retranslateUi(RenameFolderDialog)
        self.dialogButtonBox.accepted.connect(RenameFolderDialog.accept)
        self.dialogButtonBox.rejected.connect(RenameFolderDialog.reject)

        QMetaObject.connectSlotsByName(RenameFolderDialog)
    # setupUi

    def retranslateUi(self, RenameFolderDialog):
        RenameFolderDialog.setWindowTitle(QCoreApplication.translate("RenameFolderDialog", u"syncServer - Rename folder", None))
        self.oldFolderNameLabel.setText(QCoreApplication.translate("RenameFolderDialog", u"Old folder name:", None))
        self.oldFolderNameLineEdit.setPlaceholderText(QCoreApplication.translate("RenameFolderDialog", u"/file.txt", None))
        self.newFolderNameLabel.setText(QCoreApplication.translate("RenameFolderDialog", u"New folder name:", None))
    # retranslateUi

