# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'rename_file_dialog.ui'
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

class Ui_RenameFileDialog(object):
    def setupUi(self, RenameFileDialog):
        if not RenameFileDialog.objectName():
            RenameFileDialog.setObjectName(u"RenameFileDialog")
        RenameFileDialog.resize(400, 222)
        self.verticalLayout = QVBoxLayout(RenameFileDialog)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.mainDialogFrame = QFrame(RenameFileDialog)
        self.mainDialogFrame.setObjectName(u"mainDialogFrame")
        self.mainDialogFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.mainDialogFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.verticalLayoutWidget = QWidget(self.mainDialogFrame)
        self.verticalLayoutWidget.setObjectName(u"verticalLayoutWidget")
        self.verticalLayoutWidget.setGeometry(QRect(10, 10, 351, 61))
        self.oldNameLayout = QVBoxLayout(self.verticalLayoutWidget)
        self.oldNameLayout.setObjectName(u"oldNameLayout")
        self.oldNameLayout.setContentsMargins(0, 0, 0, 0)
        self.oldFilenameLabel = QLabel(self.verticalLayoutWidget)
        self.oldFilenameLabel.setObjectName(u"oldFilenameLabel")

        self.oldNameLayout.addWidget(self.oldFilenameLabel)

        self.oldFilenameLineEdit = QLineEdit(self.verticalLayoutWidget)
        self.oldFilenameLineEdit.setObjectName(u"oldFilenameLineEdit")
        self.oldFilenameLineEdit.setReadOnly(True)

        self.oldNameLayout.addWidget(self.oldFilenameLineEdit)

        self.verticalLayoutWidget_2 = QWidget(self.mainDialogFrame)
        self.verticalLayoutWidget_2.setObjectName(u"verticalLayoutWidget_2")
        self.verticalLayoutWidget_2.setGeometry(QRect(10, 90, 351, 61))
        self.newNameLayout = QVBoxLayout(self.verticalLayoutWidget_2)
        self.newNameLayout.setObjectName(u"newNameLayout")
        self.newNameLayout.setContentsMargins(0, 0, 0, 0)
        self.newFilenameLabel = QLabel(self.verticalLayoutWidget_2)
        self.newFilenameLabel.setObjectName(u"newFilenameLabel")

        self.newNameLayout.addWidget(self.newFilenameLabel)

        self.newFilenameLineEdit = QLineEdit(self.verticalLayoutWidget_2)
        self.newFilenameLineEdit.setObjectName(u"newFilenameLineEdit")

        self.newNameLayout.addWidget(self.newFilenameLineEdit)


        self.verticalLayout.addWidget(self.mainDialogFrame)

        self.dialogButtonBox = QDialogButtonBox(RenameFileDialog)
        self.dialogButtonBox.setObjectName(u"dialogButtonBox")
        self.dialogButtonBox.setOrientation(Qt.Orientation.Horizontal)
        self.dialogButtonBox.setStandardButtons(QDialogButtonBox.StandardButton.Cancel|QDialogButtonBox.StandardButton.Ok)

        self.verticalLayout.addWidget(self.dialogButtonBox)


        self.retranslateUi(RenameFileDialog)
        self.dialogButtonBox.accepted.connect(RenameFileDialog.accept)
        self.dialogButtonBox.rejected.connect(RenameFileDialog.reject)

        QMetaObject.connectSlotsByName(RenameFileDialog)
    # setupUi

    def retranslateUi(self, RenameFileDialog):
        RenameFileDialog.setWindowTitle(QCoreApplication.translate("RenameFileDialog", u"syncServer - Rename file", None))
        self.oldFilenameLabel.setText(QCoreApplication.translate("RenameFileDialog", u"Old filename:", None))
        self.oldFilenameLineEdit.setPlaceholderText(QCoreApplication.translate("RenameFileDialog", u"/file.txt", None))
        self.newFilenameLabel.setText(QCoreApplication.translate("RenameFileDialog", u"New filename:", None))
    # retranslateUi

