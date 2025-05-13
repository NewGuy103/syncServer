# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'create_apikey_success_dialog.ui'
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
    QFrame, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSizePolicy, QVBoxLayout, QWidget)

class Ui_CreateAPIKeySuccess(object):
    def setupUi(self, CreateAPIKeySuccess):
        if not CreateAPIKeySuccess.objectName():
            CreateAPIKeySuccess.setObjectName(u"CreateAPIKeySuccess")
        CreateAPIKeySuccess.resize(400, 186)
        self.verticalLayout = QVBoxLayout(CreateAPIKeySuccess)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.mainDialogFrame = QFrame(CreateAPIKeySuccess)
        self.mainDialogFrame.setObjectName(u"mainDialogFrame")
        self.mainDialogFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.mainDialogFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.verticalLayout_2 = QVBoxLayout(self.mainDialogFrame)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.mainDialogLayout = QVBoxLayout()
        self.mainDialogLayout.setObjectName(u"mainDialogLayout")
        self.keyLabel = QLabel(self.mainDialogFrame)
        self.keyLabel.setObjectName(u"keyLabel")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.keyLabel.sizePolicy().hasHeightForWidth())
        self.keyLabel.setSizePolicy(sizePolicy)

        self.mainDialogLayout.addWidget(self.keyLabel)

        self.keyLineEdit = QLineEdit(self.mainDialogFrame)
        self.keyLineEdit.setObjectName(u"keyLineEdit")
        self.keyLineEdit.setReadOnly(True)

        self.mainDialogLayout.addWidget(self.keyLineEdit)


        self.verticalLayout_2.addLayout(self.mainDialogLayout)

        self.copyLayout = QHBoxLayout()
        self.copyLayout.setObjectName(u"copyLayout")
        self.copyToClipboardButton = QPushButton(self.mainDialogFrame)
        self.copyToClipboardButton.setObjectName(u"copyToClipboardButton")
        sizePolicy1 = QSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Maximum)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.copyToClipboardButton.sizePolicy().hasHeightForWidth())
        self.copyToClipboardButton.setSizePolicy(sizePolicy1)
        icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.EditCopy))
        self.copyToClipboardButton.setIcon(icon)

        self.copyLayout.addWidget(self.copyToClipboardButton)


        self.verticalLayout_2.addLayout(self.copyLayout)


        self.verticalLayout.addWidget(self.mainDialogFrame)

        self.dialogButtonBox = QDialogButtonBox(CreateAPIKeySuccess)
        self.dialogButtonBox.setObjectName(u"dialogButtonBox")
        self.dialogButtonBox.setStandardButtons(QDialogButtonBox.StandardButton.Ok)

        self.verticalLayout.addWidget(self.dialogButtonBox)


        self.retranslateUi(CreateAPIKeySuccess)
        self.dialogButtonBox.accepted.connect(CreateAPIKeySuccess.accept)
        self.dialogButtonBox.rejected.connect(CreateAPIKeySuccess.reject)

        QMetaObject.connectSlotsByName(CreateAPIKeySuccess)
    # setupUi

    def retranslateUi(self, CreateAPIKeySuccess):
        CreateAPIKeySuccess.setWindowTitle(QCoreApplication.translate("CreateAPIKeySuccess", u"syncServer - Client", None))
        self.keyLabel.setText(QCoreApplication.translate("CreateAPIKeySuccess", u"This is your API key, copy it and store it somewhere safe.", None))
        self.keyLineEdit.setPlaceholderText(QCoreApplication.translate("CreateAPIKeySuccess", u"syncserver-xxxxxx", None))
        self.copyToClipboardButton.setText(QCoreApplication.translate("CreateAPIKeySuccess", u"Copy to Clipboard", None))
    # retranslateUi

