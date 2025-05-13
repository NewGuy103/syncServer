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
        self.verticalLayout_2 = QVBoxLayout(self.mainDialogFrame)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.oldNameLayout = QVBoxLayout()
        self.oldNameLayout.setObjectName(u"oldNameLayout")
        self.oldFilenameLabel = QLabel(self.mainDialogFrame)
        self.oldFilenameLabel.setObjectName(u"oldFilenameLabel")

        self.oldNameLayout.addWidget(self.oldFilenameLabel)

        self.oldFilenameLineEdit = QLineEdit(self.mainDialogFrame)
        self.oldFilenameLineEdit.setObjectName(u"oldFilenameLineEdit")
        self.oldFilenameLineEdit.setReadOnly(True)

        self.oldNameLayout.addWidget(self.oldFilenameLineEdit)


        self.verticalLayout_2.addLayout(self.oldNameLayout)

        self.newNameLayout = QVBoxLayout()
        self.newNameLayout.setObjectName(u"newNameLayout")
        self.newFilenameLabel = QLabel(self.mainDialogFrame)
        self.newFilenameLabel.setObjectName(u"newFilenameLabel")

        self.newNameLayout.addWidget(self.newFilenameLabel)

        self.newFilenameLineEdit = QLineEdit(self.mainDialogFrame)
        self.newFilenameLineEdit.setObjectName(u"newFilenameLineEdit")

        self.newNameLayout.addWidget(self.newFilenameLineEdit)


        self.verticalLayout_2.addLayout(self.newNameLayout)


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

