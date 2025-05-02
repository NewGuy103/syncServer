# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'create_apikey_dialog.ui'
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
from PySide6.QtWidgets import (QAbstractButton, QApplication, QCheckBox, QDateTimeEdit,
    QDialog, QDialogButtonBox, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QSizePolicy, QVBoxLayout,
    QWidget)

class Ui_CreateAPIKeyDialog(object):
    def setupUi(self, CreateAPIKeyDialog):
        if not CreateAPIKeyDialog.objectName():
            CreateAPIKeyDialog.setObjectName(u"CreateAPIKeyDialog")
        CreateAPIKeyDialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        CreateAPIKeyDialog.resize(400, 321)
        CreateAPIKeyDialog.setModal(True)
        self.verticalLayout = QVBoxLayout(CreateAPIKeyDialog)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.mainDialogFrame = QFrame(CreateAPIKeyDialog)
        self.mainDialogFrame.setObjectName(u"mainDialogFrame")
        self.mainDialogFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.mainDialogFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.verticalLayoutWidget = QWidget(self.mainDialogFrame)
        self.verticalLayoutWidget.setObjectName(u"verticalLayoutWidget")
        self.verticalLayoutWidget.setGeometry(QRect(10, 10, 351, 61))
        self.enterKeyNameLayout = QVBoxLayout(self.verticalLayoutWidget)
        self.enterKeyNameLayout.setObjectName(u"enterKeyNameLayout")
        self.enterKeyNameLayout.setContentsMargins(0, 0, 0, 0)
        self.enterKeyNameLabel = QLabel(self.verticalLayoutWidget)
        self.enterKeyNameLabel.setObjectName(u"enterKeyNameLabel")

        self.enterKeyNameLayout.addWidget(self.enterKeyNameLabel)

        self.keyNameLineEdit = QLineEdit(self.verticalLayoutWidget)
        self.keyNameLineEdit.setObjectName(u"keyNameLineEdit")

        self.enterKeyNameLayout.addWidget(self.keyNameLineEdit)

        self.verticalLayoutWidget_2 = QWidget(self.mainDialogFrame)
        self.verticalLayoutWidget_2.setObjectName(u"verticalLayoutWidget_2")
        self.verticalLayoutWidget_2.setGeometry(QRect(10, 100, 351, 61))
        self.enterExpiryDateLayout = QVBoxLayout(self.verticalLayoutWidget_2)
        self.enterExpiryDateLayout.setObjectName(u"enterExpiryDateLayout")
        self.enterExpiryDateLayout.setContentsMargins(0, 0, 0, 0)
        self.enterExpiryDateLabel = QLabel(self.verticalLayoutWidget_2)
        self.enterExpiryDateLabel.setObjectName(u"enterExpiryDateLabel")

        self.enterExpiryDateLayout.addWidget(self.enterExpiryDateLabel)

        self.keyExpiryDateTimeEdit = QDateTimeEdit(self.verticalLayoutWidget_2)
        self.keyExpiryDateTimeEdit.setObjectName(u"keyExpiryDateTimeEdit")
        self.keyExpiryDateTimeEdit.setDate(QDate(2025, 3, 14))
        self.keyExpiryDateTimeEdit.setTimeSpec(Qt.TimeSpec.LocalTime)

        self.enterExpiryDateLayout.addWidget(self.keyExpiryDateTimeEdit)

        self.verticalLayoutWidget_3 = QWidget(self.mainDialogFrame)
        self.verticalLayoutWidget_3.setObjectName(u"verticalLayoutWidget_3")
        self.verticalLayoutWidget_3.setGeometry(QRect(10, 190, 354, 61))
        self.chooseKeyPermsLayout = QVBoxLayout(self.verticalLayoutWidget_3)
        self.chooseKeyPermsLayout.setObjectName(u"chooseKeyPermsLayout")
        self.chooseKeyPermsLayout.setContentsMargins(0, 0, 0, 0)
        self.chooseKeyPermsLabel = QLabel(self.verticalLayoutWidget_3)
        self.chooseKeyPermsLabel.setObjectName(u"chooseKeyPermsLabel")

        self.chooseKeyPermsLayout.addWidget(self.chooseKeyPermsLabel)

        self.keyPermsLayout = QHBoxLayout()
        self.keyPermsLayout.setObjectName(u"keyPermsLayout")
        self.createPermsCheckbox = QCheckBox(self.verticalLayoutWidget_3)
        self.createPermsCheckbox.setObjectName(u"createPermsCheckbox")

        self.keyPermsLayout.addWidget(self.createPermsCheckbox)

        self.readPermsCheckbox = QCheckBox(self.verticalLayoutWidget_3)
        self.readPermsCheckbox.setObjectName(u"readPermsCheckbox")

        self.keyPermsLayout.addWidget(self.readPermsCheckbox)

        self.updatePermsCheckbox = QCheckBox(self.verticalLayoutWidget_3)
        self.updatePermsCheckbox.setObjectName(u"updatePermsCheckbox")

        self.keyPermsLayout.addWidget(self.updatePermsCheckbox)

        self.deletePermsCheckbox = QCheckBox(self.verticalLayoutWidget_3)
        self.deletePermsCheckbox.setObjectName(u"deletePermsCheckbox")

        self.keyPermsLayout.addWidget(self.deletePermsCheckbox)


        self.chooseKeyPermsLayout.addLayout(self.keyPermsLayout)


        self.verticalLayout.addWidget(self.mainDialogFrame)

        self.dialogButtonBox = QDialogButtonBox(CreateAPIKeyDialog)
        self.dialogButtonBox.setObjectName(u"dialogButtonBox")
        self.dialogButtonBox.setOrientation(Qt.Orientation.Horizontal)
        self.dialogButtonBox.setStandardButtons(QDialogButtonBox.StandardButton.Cancel|QDialogButtonBox.StandardButton.Ok)

        self.verticalLayout.addWidget(self.dialogButtonBox)

        QWidget.setTabOrder(self.keyNameLineEdit, self.keyExpiryDateTimeEdit)
        QWidget.setTabOrder(self.keyExpiryDateTimeEdit, self.createPermsCheckbox)
        QWidget.setTabOrder(self.createPermsCheckbox, self.readPermsCheckbox)
        QWidget.setTabOrder(self.readPermsCheckbox, self.updatePermsCheckbox)
        QWidget.setTabOrder(self.updatePermsCheckbox, self.deletePermsCheckbox)

        self.retranslateUi(CreateAPIKeyDialog)
        self.dialogButtonBox.accepted.connect(CreateAPIKeyDialog.accept)
        self.dialogButtonBox.rejected.connect(CreateAPIKeyDialog.reject)

        QMetaObject.connectSlotsByName(CreateAPIKeyDialog)
    # setupUi

    def retranslateUi(self, CreateAPIKeyDialog):
        CreateAPIKeyDialog.setWindowTitle(QCoreApplication.translate("CreateAPIKeyDialog", u"syncServer - Create API Key", None))
        self.enterKeyNameLabel.setText(QCoreApplication.translate("CreateAPIKeyDialog", u"Enter API key name:", None))
        self.enterExpiryDateLabel.setText(QCoreApplication.translate("CreateAPIKeyDialog", u"Enter API key name:", None))
        self.keyExpiryDateTimeEdit.setDisplayFormat(QCoreApplication.translate("CreateAPIKeyDialog", u"M/d/yyyy h:mm\u202fAp", None))
        self.chooseKeyPermsLabel.setText(QCoreApplication.translate("CreateAPIKeyDialog", u"Choose key permissions:", None))
        self.createPermsCheckbox.setText(QCoreApplication.translate("CreateAPIKeyDialog", u"Create", None))
        self.readPermsCheckbox.setText(QCoreApplication.translate("CreateAPIKeyDialog", u"Read", None))
        self.updatePermsCheckbox.setText(QCoreApplication.translate("CreateAPIKeyDialog", u"Update", None))
        self.deletePermsCheckbox.setText(QCoreApplication.translate("CreateAPIKeyDialog", u"Delete", None))
    # retranslateUi

