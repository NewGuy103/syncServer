# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'main.ui'
##
## Created by: Qt User Interface Compiler version 6.9.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QAction, QBrush, QColor, QConicalGradient,
    QCursor, QFont, QFontDatabase, QGradient,
    QIcon, QImage, QKeySequence, QLinearGradient,
    QPainter, QPalette, QPixmap, QRadialGradient,
    QTransform)
from PySide6.QtWidgets import (QApplication, QFrame, QGridLayout, QLabel,
    QLineEdit, QMainWindow, QMenu, QMenuBar,
    QPushButton, QSizePolicy, QStackedWidget, QStatusBar,
    QTabWidget, QVBoxLayout, QWidget)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(1366, 696)
        self.actionSource_Code = QAction(MainWindow)
        self.actionSource_Code.setObjectName(u"actionSource_Code")
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.verticalLayout = QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.mainStackedWidget = QStackedWidget(self.centralwidget)
        self.mainStackedWidget.setObjectName(u"mainStackedWidget")
        self.page = QWidget()
        self.page.setObjectName(u"page")
        self.gridLayout_2 = QGridLayout(self.page)
        self.gridLayout_2.setObjectName(u"gridLayout_2")
        self.loginMainFrame = QFrame(self.page)
        self.loginMainFrame.setObjectName(u"loginMainFrame")
        self.loginMainFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.loginMainFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.loginFrame = QFrame(self.loginMainFrame)
        self.loginFrame.setObjectName(u"loginFrame")
        self.loginFrame.setGeometry(QRect(490, 220, 361, 231))
        self.loginFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.loginFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.gridLayoutWidget = QWidget(self.loginFrame)
        self.gridLayoutWidget.setObjectName(u"gridLayoutWidget")
        self.gridLayoutWidget.setGeometry(QRect(10, 10, 341, 211))
        self.loginGridLayout = QGridLayout(self.gridLayoutWidget)
        self.loginGridLayout.setObjectName(u"loginGridLayout")
        self.loginGridLayout.setVerticalSpacing(12)
        self.loginGridLayout.setContentsMargins(0, 0, 0, 0)
        self.passwordLineEdit = QLineEdit(self.gridLayoutWidget)
        self.passwordLineEdit.setObjectName(u"passwordLineEdit")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.passwordLineEdit.sizePolicy().hasHeightForWidth())
        self.passwordLineEdit.setSizePolicy(sizePolicy)
        font = QFont()
        font.setPointSize(12)
        self.passwordLineEdit.setFont(font)
        self.passwordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        self.loginGridLayout.addWidget(self.passwordLineEdit, 2, 0, 1, 1)

        self.loginButton = QPushButton(self.gridLayoutWidget)
        self.loginButton.setObjectName(u"loginButton")
        sizePolicy1 = QSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Preferred)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.loginButton.sizePolicy().hasHeightForWidth())
        self.loginButton.setSizePolicy(sizePolicy1)
        self.loginButton.setFont(font)

        self.loginGridLayout.addWidget(self.loginButton, 3, 0, 1, 1)

        self.usernameLineEdit = QLineEdit(self.gridLayoutWidget)
        self.usernameLineEdit.setObjectName(u"usernameLineEdit")
        sizePolicy.setHeightForWidth(self.usernameLineEdit.sizePolicy().hasHeightForWidth())
        self.usernameLineEdit.setSizePolicy(sizePolicy)
        self.usernameLineEdit.setFont(font)
        self.usernameLineEdit.setMaxLength(30)

        self.loginGridLayout.addWidget(self.usernameLineEdit, 1, 0, 1, 1)

        self.serverUrlLineEdit = QLineEdit(self.gridLayoutWidget)
        self.serverUrlLineEdit.setObjectName(u"serverUrlLineEdit")
        sizePolicy.setHeightForWidth(self.serverUrlLineEdit.sizePolicy().hasHeightForWidth())
        self.serverUrlLineEdit.setSizePolicy(sizePolicy)
        self.serverUrlLineEdit.setFont(font)
        self.serverUrlLineEdit.setTabletTracking(False)

        self.loginGridLayout.addWidget(self.serverUrlLineEdit, 0, 0, 1, 1)

        self.loginLabel = QLabel(self.loginMainFrame)
        self.loginLabel.setObjectName(u"loginLabel")
        self.loginLabel.setGeometry(QRect(500, 170, 339, 33))
        sizePolicy2 = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        sizePolicy2.setHorizontalStretch(0)
        sizePolicy2.setVerticalStretch(0)
        sizePolicy2.setHeightForWidth(self.loginLabel.sizePolicy().hasHeightForWidth())
        self.loginLabel.setSizePolicy(sizePolicy2)
        font1 = QFont()
        font1.setPointSize(22)
        self.loginLabel.setFont(font1)
        self.loginLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.gridLayout_2.addWidget(self.loginMainFrame, 0, 0, 1, 1)

        self.mainStackedWidget.addWidget(self.page)
        self.page_2 = QWidget()
        self.page_2.setObjectName(u"page_2")
        self.gridLayout = QGridLayout(self.page_2)
        self.gridLayout.setObjectName(u"gridLayout")
        self.appTabWidget = QTabWidget(self.page_2)
        self.appTabWidget.setObjectName(u"appTabWidget")
        self.dashboardTab = QWidget()
        self.dashboardTab.setObjectName(u"dashboardTab")
        self.appTabWidget.addTab(self.dashboardTab, "")
        self.tab_2 = QWidget()
        self.tab_2.setObjectName(u"tab_2")
        self.appTabWidget.addTab(self.tab_2, "")

        self.gridLayout.addWidget(self.appTabWidget, 0, 0, 1, 1)

        self.mainStackedWidget.addWidget(self.page_2)

        self.verticalLayout.addWidget(self.mainStackedWidget)

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QMenuBar(MainWindow)
        self.menubar.setObjectName(u"menubar")
        self.menubar.setGeometry(QRect(0, 0, 1366, 20))
        self.menuAbout = QMenu(self.menubar)
        self.menuAbout.setObjectName(u"menuAbout")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(u"statusbar")
        MainWindow.setStatusBar(self.statusbar)
        QWidget.setTabOrder(self.serverUrlLineEdit, self.usernameLineEdit)
        QWidget.setTabOrder(self.usernameLineEdit, self.passwordLineEdit)
        QWidget.setTabOrder(self.passwordLineEdit, self.loginButton)

        self.menubar.addAction(self.menuAbout.menuAction())
        self.menuAbout.addSeparator()
        self.menuAbout.addSeparator()
        self.menuAbout.addSeparator()
        self.menuAbout.addAction(self.actionSource_Code)

        self.retranslateUi(MainWindow)
        self.serverUrlLineEdit.returnPressed.connect(self.usernameLineEdit.setFocus)
        self.usernameLineEdit.returnPressed.connect(self.passwordLineEdit.setFocus)
        self.passwordLineEdit.returnPressed.connect(self.loginButton.click)

        self.mainStackedWidget.setCurrentIndex(1)
        self.appTabWidget.setCurrentIndex(0)


        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"syncServer Client", None))
        self.actionSource_Code.setText(QCoreApplication.translate("MainWindow", u"Source Code", None))
#if QT_CONFIG(tooltip)
        self.loginMainFrame.setToolTip("")
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        self.passwordLineEdit.setToolTip(QCoreApplication.translate("MainWindow", u"Enter a password.", None))
#endif // QT_CONFIG(tooltip)
        self.passwordLineEdit.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Enter password", None))
        self.loginButton.setText(QCoreApplication.translate("MainWindow", u"Login", None))
#if QT_CONFIG(tooltip)
        self.usernameLineEdit.setToolTip(QCoreApplication.translate("MainWindow", u"Enter a username less than 30 characters.", None))
#endif // QT_CONFIG(tooltip)
        self.usernameLineEdit.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Enter username", None))
#if QT_CONFIG(tooltip)
        self.serverUrlLineEdit.setToolTip(QCoreApplication.translate("MainWindow", u"Enter a server hostname. Example: http://syncserver.example.com", None))
#endif // QT_CONFIG(tooltip)
        self.serverUrlLineEdit.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Enter server hostname", None))
        self.loginLabel.setText(QCoreApplication.translate("MainWindow", u"syncServer Login", None))
        self.appTabWidget.setTabText(self.appTabWidget.indexOf(self.dashboardTab), QCoreApplication.translate("MainWindow", u"Dashboard", None))
        self.appTabWidget.setTabText(self.appTabWidget.indexOf(self.tab_2), QCoreApplication.translate("MainWindow", u"Tab 2", None))
        self.menuAbout.setTitle(QCoreApplication.translate("MainWindow", u"Help", None))
    # retranslateUi

