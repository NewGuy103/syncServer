# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'add_account_dialog.ui'
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

class Ui_AddAccountDialog(object):
    def setupUi(self, AddAccountDialog):
        if not AddAccountDialog.objectName():
            AddAccountDialog.setObjectName(u"AddAccountDialog")
        AddAccountDialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        AddAccountDialog.resize(400, 300)
        self.verticalLayout = QVBoxLayout(AddAccountDialog)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.mainDialogFrame = QFrame(AddAccountDialog)
        self.mainDialogFrame.setObjectName(u"mainDialogFrame")
        self.mainDialogFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.mainDialogFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.verticalLayout_5 = QVBoxLayout(self.mainDialogFrame)
        self.verticalLayout_5.setObjectName(u"verticalLayout_5")
        self.serverUrlWidget = QWidget(self.mainDialogFrame)
        self.serverUrlWidget.setObjectName(u"serverUrlWidget")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.serverUrlWidget.sizePolicy().hasHeightForWidth())
        self.serverUrlWidget.setSizePolicy(sizePolicy)
        self.verticalLayout_2 = QVBoxLayout(self.serverUrlWidget)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.enterServerURLLabel = QLabel(self.serverUrlWidget)
        self.enterServerURLLabel.setObjectName(u"enterServerURLLabel")
        sizePolicy.setHeightForWidth(self.enterServerURLLabel.sizePolicy().hasHeightForWidth())
        self.enterServerURLLabel.setSizePolicy(sizePolicy)

        self.verticalLayout_2.addWidget(self.enterServerURLLabel)

        self.serverUrlLineEdit = QLineEdit(self.serverUrlWidget)
        self.serverUrlLineEdit.setObjectName(u"serverUrlLineEdit")

        self.verticalLayout_2.addWidget(self.serverUrlLineEdit)


        self.verticalLayout_5.addWidget(self.serverUrlWidget)

        self.usernameWidget = QWidget(self.mainDialogFrame)
        self.usernameWidget.setObjectName(u"usernameWidget")
        sizePolicy.setHeightForWidth(self.usernameWidget.sizePolicy().hasHeightForWidth())
        self.usernameWidget.setSizePolicy(sizePolicy)
        self.verticalLayout_4 = QVBoxLayout(self.usernameWidget)
        self.verticalLayout_4.setObjectName(u"verticalLayout_4")
        self.enterUsernameLabel = QLabel(self.usernameWidget)
        self.enterUsernameLabel.setObjectName(u"enterUsernameLabel")
        sizePolicy.setHeightForWidth(self.enterUsernameLabel.sizePolicy().hasHeightForWidth())
        self.enterUsernameLabel.setSizePolicy(sizePolicy)

        self.verticalLayout_4.addWidget(self.enterUsernameLabel)

        self.usernameLineEdit = QLineEdit(self.usernameWidget)
        self.usernameLineEdit.setObjectName(u"usernameLineEdit")
        self.usernameLineEdit.setMaxLength(30)

        self.verticalLayout_4.addWidget(self.usernameLineEdit)


        self.verticalLayout_5.addWidget(self.usernameWidget)

        self.passwordWidget = QWidget(self.mainDialogFrame)
        self.passwordWidget.setObjectName(u"passwordWidget")
        sizePolicy.setHeightForWidth(self.passwordWidget.sizePolicy().hasHeightForWidth())
        self.passwordWidget.setSizePolicy(sizePolicy)
        self.verticalLayout_3 = QVBoxLayout(self.passwordWidget)
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.enterPasswordLabel = QLabel(self.passwordWidget)
        self.enterPasswordLabel.setObjectName(u"enterPasswordLabel")
        sizePolicy.setHeightForWidth(self.enterPasswordLabel.sizePolicy().hasHeightForWidth())
        self.enterPasswordLabel.setSizePolicy(sizePolicy)

        self.verticalLayout_3.addWidget(self.enterPasswordLabel)

        self.passwordLineEdit = QLineEdit(self.passwordWidget)
        self.passwordLineEdit.setObjectName(u"passwordLineEdit")
        self.passwordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        self.verticalLayout_3.addWidget(self.passwordLineEdit)


        self.verticalLayout_5.addWidget(self.passwordWidget)


        self.verticalLayout.addWidget(self.mainDialogFrame)

        self.dialogButtonBox = QDialogButtonBox(AddAccountDialog)
        self.dialogButtonBox.setObjectName(u"dialogButtonBox")
        self.dialogButtonBox.setOrientation(Qt.Orientation.Horizontal)
        self.dialogButtonBox.setStandardButtons(QDialogButtonBox.StandardButton.Cancel|QDialogButtonBox.StandardButton.Ok)

        self.verticalLayout.addWidget(self.dialogButtonBox)

        QWidget.setTabOrder(self.serverUrlLineEdit, self.usernameLineEdit)
        QWidget.setTabOrder(self.usernameLineEdit, self.passwordLineEdit)

        self.retranslateUi(AddAccountDialog)
        self.dialogButtonBox.accepted.connect(AddAccountDialog.accept)
        self.dialogButtonBox.rejected.connect(AddAccountDialog.reject)
        self.serverUrlLineEdit.returnPressed.connect(self.usernameLineEdit.setFocus)
        self.usernameLineEdit.returnPressed.connect(self.passwordLineEdit.setFocus)

        QMetaObject.connectSlotsByName(AddAccountDialog)
    # setupUi

    def retranslateUi(self, AddAccountDialog):
        AddAccountDialog.setWindowTitle(QCoreApplication.translate("AddAccountDialog", u"Dialog", None))
        self.enterServerURLLabel.setText(QCoreApplication.translate("AddAccountDialog", u"Enter server URL:", None))
        self.serverUrlLineEdit.setPlaceholderText(QCoreApplication.translate("AddAccountDialog", u"Enter server URL", None))
        self.enterUsernameLabel.setText(QCoreApplication.translate("AddAccountDialog", u"Enter username:", None))
        self.usernameLineEdit.setPlaceholderText(QCoreApplication.translate("AddAccountDialog", u"Enter username", None))
        self.enterPasswordLabel.setText(QCoreApplication.translate("AddAccountDialog", u"Enter password:", None))
        self.passwordLineEdit.setPlaceholderText(QCoreApplication.translate("AddAccountDialog", u"Enter password", None))
    # retranslateUi

