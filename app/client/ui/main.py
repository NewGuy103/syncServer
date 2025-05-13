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
from PySide6.QtWidgets import (QApplication, QComboBox, QFrame, QGridLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMainWindow, QMenu,
    QMenuBar, QPushButton, QSizePolicy, QSpacerItem,
    QStackedWidget, QStatusBar, QTabWidget, QVBoxLayout,
    QWidget)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(1366, 696)
        self.actionSource_Code = QAction(MainWindow)
        self.actionSource_Code.setObjectName(u"actionSource_Code")
        icon = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.HelpAbout))
        self.actionSource_Code.setIcon(icon)
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
        self.gridLayout_11 = QGridLayout(self.loginMainFrame)
        self.gridLayout_11.setObjectName(u"gridLayout_11")
        self.loginLabel = QLabel(self.loginMainFrame)
        self.loginLabel.setObjectName(u"loginLabel")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.loginLabel.sizePolicy().hasHeightForWidth())
        self.loginLabel.setSizePolicy(sizePolicy)
        font = QFont()
        font.setPointSize(22)
        self.loginLabel.setFont(font)
        self.loginLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.gridLayout_11.addWidget(self.loginLabel, 1, 0, 1, 1)

        self.verticalSpacer_2 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.gridLayout_11.addItem(self.verticalSpacer_2, 0, 0, 1, 1)

        self.gridFrame = QFrame(self.loginMainFrame)
        self.gridFrame.setObjectName(u"gridFrame")
        self.gridFrame.setMinimumSize(QSize(350, 230))
        self.gridFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.loginGridLayout = QGridLayout(self.gridFrame)
        self.loginGridLayout.setObjectName(u"loginGridLayout")
        self.loginGridLayout.setVerticalSpacing(12)
        self.loginGridLayout.setContentsMargins(10, 10, 10, 10)
        self.loginButton = QPushButton(self.gridFrame)
        self.loginButton.setObjectName(u"loginButton")
        sizePolicy1 = QSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Preferred)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.loginButton.sizePolicy().hasHeightForWidth())
        self.loginButton.setSizePolicy(sizePolicy1)
        font1 = QFont()
        font1.setPointSize(12)
        self.loginButton.setFont(font1)

        self.loginGridLayout.addWidget(self.loginButton, 4, 0, 1, 1)

        self.passwordLineEdit = QLineEdit(self.gridFrame)
        self.passwordLineEdit.setObjectName(u"passwordLineEdit")
        sizePolicy2 = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy2.setHorizontalStretch(0)
        sizePolicy2.setVerticalStretch(0)
        sizePolicy2.setHeightForWidth(self.passwordLineEdit.sizePolicy().hasHeightForWidth())
        self.passwordLineEdit.setSizePolicy(sizePolicy2)
        self.passwordLineEdit.setFont(font1)
        self.passwordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        self.loginGridLayout.addWidget(self.passwordLineEdit, 3, 0, 1, 1)

        self.usernameLineEdit = QLineEdit(self.gridFrame)
        self.usernameLineEdit.setObjectName(u"usernameLineEdit")
        sizePolicy2.setHeightForWidth(self.usernameLineEdit.sizePolicy().hasHeightForWidth())
        self.usernameLineEdit.setSizePolicy(sizePolicy2)
        self.usernameLineEdit.setFont(font1)
        self.usernameLineEdit.setMaxLength(30)

        self.loginGridLayout.addWidget(self.usernameLineEdit, 2, 0, 1, 1)

        self.serverUrlLineEdit = QLineEdit(self.gridFrame)
        self.serverUrlLineEdit.setObjectName(u"serverUrlLineEdit")
        sizePolicy2.setHeightForWidth(self.serverUrlLineEdit.sizePolicy().hasHeightForWidth())
        self.serverUrlLineEdit.setSizePolicy(sizePolicy2)
        self.serverUrlLineEdit.setFont(font1)
        self.serverUrlLineEdit.setTabletTracking(False)

        self.loginGridLayout.addWidget(self.serverUrlLineEdit, 1, 0, 1, 1)


        self.gridLayout_11.addWidget(self.gridFrame, 2, 0, 1, 1, Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignVCenter)

        self.verticalSpacer_3 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.gridLayout_11.addItem(self.verticalSpacer_3, 3, 0, 1, 1)


        self.gridLayout_2.addWidget(self.loginMainFrame, 0, 0, 1, 1)

        self.mainStackedWidget.addWidget(self.page)
        self.page_2 = QWidget()
        self.page_2.setObjectName(u"page_2")
        self.gridLayout = QGridLayout(self.page_2)
        self.gridLayout.setObjectName(u"gridLayout")
        self.appTabWidget = QTabWidget(self.page_2)
        self.appTabWidget.setObjectName(u"appTabWidget")
        self.filesTab = QWidget()
        self.filesTab.setObjectName(u"filesTab")
        self.gridLayout_5 = QGridLayout(self.filesTab)
        self.gridLayout_5.setObjectName(u"gridLayout_5")
        self.fileTabFrame = QFrame(self.filesTab)
        self.fileTabFrame.setObjectName(u"fileTabFrame")
        self.fileTabFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.fileTabFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.gridLayout_4 = QGridLayout(self.fileTabFrame)
        self.gridLayout_4.setObjectName(u"gridLayout_4")
        self.fileListLayout = QVBoxLayout()
        self.fileListLayout.setSpacing(6)
        self.fileListLayout.setObjectName(u"fileListLayout")
        self.fileListLabel = QLabel(self.fileTabFrame)
        self.fileListLabel.setObjectName(u"fileListLabel")
        font2 = QFont()
        font2.setPointSize(12)
        font2.setBold(False)
        self.fileListLabel.setFont(font2)
        self.fileListLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.fileListLabel.setIndent(0)

        self.fileListLayout.addWidget(self.fileListLabel)

        self.fileListWidget = QListWidget(self.fileTabFrame)
        self.fileListWidget.setObjectName(u"fileListWidget")

        self.fileListLayout.addWidget(self.fileListWidget)

        self.optionButtonsLayout = QHBoxLayout()
        self.optionButtonsLayout.setObjectName(u"optionButtonsLayout")
        self.showDownloadsManagerButton = QPushButton(self.fileTabFrame)
        self.showDownloadsManagerButton.setObjectName(u"showDownloadsManagerButton")

        self.optionButtonsLayout.addWidget(self.showDownloadsManagerButton)


        self.fileListLayout.addLayout(self.optionButtonsLayout)


        self.gridLayout_4.addLayout(self.fileListLayout, 0, 0, 1, 1)


        self.gridLayout_5.addWidget(self.fileTabFrame, 0, 0, 1, 1)

        icon1 = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.DocumentOpen))
        self.appTabWidget.addTab(self.filesTab, icon1, "")
        self.trashbinTab = QWidget()
        self.trashbinTab.setObjectName(u"trashbinTab")
        self.gridLayout_6 = QGridLayout(self.trashbinTab)
        self.gridLayout_6.setObjectName(u"gridLayout_6")
        self.trashbinTabFrame = QFrame(self.trashbinTab)
        self.trashbinTabFrame.setObjectName(u"trashbinTabFrame")
        self.trashbinTabFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.trashbinTabFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.gridLayout_7 = QGridLayout(self.trashbinTabFrame)
        self.gridLayout_7.setObjectName(u"gridLayout_7")
        self.trashbinLayout = QVBoxLayout()
        self.trashbinLayout.setSpacing(6)
        self.trashbinLayout.setObjectName(u"trashbinLayout")
        self.trashbinLabel = QLabel(self.trashbinTabFrame)
        self.trashbinLabel.setObjectName(u"trashbinLabel")
        self.trashbinLabel.setFont(font2)
        self.trashbinLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)
        self.trashbinLabel.setIndent(0)

        self.trashbinLayout.addWidget(self.trashbinLabel)

        self.trashbinListWidget = QListWidget(self.trashbinTabFrame)
        self.trashbinListWidget.setObjectName(u"trashbinListWidget")

        self.trashbinLayout.addWidget(self.trashbinListWidget)


        self.gridLayout_7.addLayout(self.trashbinLayout, 0, 0, 1, 1)


        self.gridLayout_6.addWidget(self.trashbinTabFrame, 0, 0, 1, 1)

        icon2 = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.FolderVisiting))
        self.appTabWidget.addTab(self.trashbinTab, icon2, "")
        self.apiKeysTab = QWidget()
        self.apiKeysTab.setObjectName(u"apiKeysTab")
        self.gridLayout_8 = QGridLayout(self.apiKeysTab)
        self.gridLayout_8.setObjectName(u"gridLayout_8")
        self.frame = QFrame(self.apiKeysTab)
        self.frame.setObjectName(u"frame")
        self.frame.setFrameShape(QFrame.Shape.StyledPanel)
        self.apiKeyListLayout = QVBoxLayout(self.frame)
        self.apiKeyListLayout.setSpacing(10)
        self.apiKeyListLayout.setObjectName(u"apiKeyListLayout")
        self.apiKeyListLabel = QLabel(self.frame)
        self.apiKeyListLabel.setObjectName(u"apiKeyListLabel")
        self.apiKeyListLabel.setFont(font1)

        self.apiKeyListLayout.addWidget(self.apiKeyListLabel)

        self.apiKeyListWidget = QListWidget(self.frame)
        self.apiKeyListWidget.setObjectName(u"apiKeyListWidget")

        self.apiKeyListLayout.addWidget(self.apiKeyListWidget)


        self.gridLayout_8.addWidget(self.frame, 0, 0, 1, 1)

        icon3 = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.DialogPassword))
        self.appTabWidget.addTab(self.apiKeysTab, icon3, "")
        self.settingsTab = QWidget()
        self.settingsTab.setObjectName(u"settingsTab")
        self.gridLayout_3 = QGridLayout(self.settingsTab)
        self.gridLayout_3.setObjectName(u"gridLayout_3")
        self.settingsMainFrame = QFrame(self.settingsTab)
        self.settingsMainFrame.setObjectName(u"settingsMainFrame")
        self.settingsMainFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.settingsMainFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.gridLayout_9 = QGridLayout(self.settingsMainFrame)
        self.gridLayout_9.setObjectName(u"gridLayout_9")
        self.appConfigGroupbox = QGroupBox(self.settingsMainFrame)
        self.appConfigGroupbox.setObjectName(u"appConfigGroupbox")
        self.verticalLayout_3 = QVBoxLayout(self.appConfigGroupbox)
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.clientInfoWidget = QWidget(self.appConfigGroupbox)
        self.clientInfoWidget.setObjectName(u"clientInfoWidget")
        sizePolicy3 = QSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)
        sizePolicy3.setHorizontalStretch(0)
        sizePolicy3.setVerticalStretch(0)
        sizePolicy3.setHeightForWidth(self.clientInfoWidget.sizePolicy().hasHeightForWidth())
        self.clientInfoWidget.setSizePolicy(sizePolicy3)
        self.gridLayout_10 = QGridLayout(self.clientInfoWidget)
        self.gridLayout_10.setObjectName(u"gridLayout_10")
        self.serverUrlLabel = QLabel(self.clientInfoWidget)
        self.serverUrlLabel.setObjectName(u"serverUrlLabel")
        self.serverUrlLabel.setFont(font1)
        self.serverUrlLabel.setCursor(QCursor(Qt.CursorShape.IBeamCursor))
        self.serverUrlLabel.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)

        self.gridLayout_10.addWidget(self.serverUrlLabel, 2, 0, 1, 1)

        self.clientVersionLabel = QLabel(self.clientInfoWidget)
        self.clientVersionLabel.setObjectName(u"clientVersionLabel")
        sizePolicy4 = QSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        sizePolicy4.setHorizontalStretch(0)
        sizePolicy4.setVerticalStretch(0)
        sizePolicy4.setHeightForWidth(self.clientVersionLabel.sizePolicy().hasHeightForWidth())
        self.clientVersionLabel.setSizePolicy(sizePolicy4)
        self.clientVersionLabel.setFont(font1)
        self.clientVersionLabel.setCursor(QCursor(Qt.CursorShape.IBeamCursor))
        self.clientVersionLabel.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)

        self.gridLayout_10.addWidget(self.clientVersionLabel, 0, 0, 1, 1)

        self.appCurrentUsernameLabel = QLabel(self.clientInfoWidget)
        self.appCurrentUsernameLabel.setObjectName(u"appCurrentUsernameLabel")
        self.appCurrentUsernameLabel.setFont(font1)
        self.appCurrentUsernameLabel.setCursor(QCursor(Qt.CursorShape.IBeamCursor))
        self.appCurrentUsernameLabel.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)

        self.gridLayout_10.addWidget(self.appCurrentUsernameLabel, 1, 0, 1, 1)


        self.verticalLayout_3.addWidget(self.clientInfoWidget)

        self.logLevelWidget = QWidget(self.appConfigGroupbox)
        self.logLevelWidget.setObjectName(u"logLevelWidget")
        sizePolicy3.setHeightForWidth(self.logLevelWidget.sizePolicy().hasHeightForWidth())
        self.logLevelWidget.setSizePolicy(sizePolicy3)
        self.horizontalLayout = QHBoxLayout(self.logLevelWidget)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.horizontalLayout.setContentsMargins(-1, -1, -1, 0)
        self.logLevelLabel = QLabel(self.logLevelWidget)
        self.logLevelLabel.setObjectName(u"logLevelLabel")
        sizePolicy4.setHeightForWidth(self.logLevelLabel.sizePolicy().hasHeightForWidth())
        self.logLevelLabel.setSizePolicy(sizePolicy4)
        self.logLevelLabel.setAlignment(Qt.AlignmentFlag.AlignLeading|Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter)

        self.horizontalLayout.addWidget(self.logLevelLabel)

        self.logLevelComboBox = QComboBox(self.logLevelWidget)
        self.logLevelComboBox.addItem("")
        self.logLevelComboBox.addItem("")
        self.logLevelComboBox.addItem("")
        self.logLevelComboBox.addItem("")
        self.logLevelComboBox.addItem("")
        self.logLevelComboBox.setObjectName(u"logLevelComboBox")
        sizePolicy4.setHeightForWidth(self.logLevelComboBox.sizePolicy().hasHeightForWidth())
        self.logLevelComboBox.setSizePolicy(sizePolicy4)

        self.horizontalLayout.addWidget(self.logLevelComboBox)


        self.verticalLayout_3.addWidget(self.logLevelWidget)

        self.logFileWidget = QWidget(self.appConfigGroupbox)
        self.logFileWidget.setObjectName(u"logFileWidget")
        sizePolicy4.setHeightForWidth(self.logFileWidget.sizePolicy().hasHeightForWidth())
        self.logFileWidget.setSizePolicy(sizePolicy4)
        self.horizontalLayout_2 = QHBoxLayout(self.logFileWidget)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.horizontalLayout_2.setContentsMargins(-1, 0, -1, -1)
        self.logFilePathLabel = QLabel(self.logFileWidget)
        self.logFilePathLabel.setObjectName(u"logFilePathLabel")
        self.logFilePathLabel.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)

        self.horizontalLayout_2.addWidget(self.logFilePathLabel)


        self.verticalLayout_3.addWidget(self.logFileWidget)

        self.verticalSpacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_3.addItem(self.verticalSpacer)


        self.gridLayout_9.addWidget(self.appConfigGroupbox, 0, 1, 1, 1)

        self.usersGroupbox = QGroupBox(self.settingsMainFrame)
        self.usersGroupbox.setObjectName(u"usersGroupbox")
        self.verticalLayout_2 = QVBoxLayout(self.usersGroupbox)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.accountsListWidget = QListWidget(self.usersGroupbox)
        self.accountsListWidget.setObjectName(u"accountsListWidget")
        sizePolicy1.setHeightForWidth(self.accountsListWidget.sizePolicy().hasHeightForWidth())
        self.accountsListWidget.setSizePolicy(sizePolicy1)

        self.verticalLayout_2.addWidget(self.accountsListWidget)


        self.gridLayout_9.addWidget(self.usersGroupbox, 0, 0, 1, 1)


        self.gridLayout_3.addWidget(self.settingsMainFrame, 0, 0, 1, 1)

        icon4 = QIcon(QIcon.fromTheme(QIcon.ThemeIcon.DialogInformation))
        self.appTabWidget.addTab(self.settingsTab, icon4, "")

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

        self.mainStackedWidget.setCurrentIndex(1)
        self.appTabWidget.setCurrentIndex(3)


        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"syncServer Client", None))
        self.actionSource_Code.setText(QCoreApplication.translate("MainWindow", u"Source Code", None))
#if QT_CONFIG(tooltip)
        self.loginMainFrame.setToolTip("")
#endif // QT_CONFIG(tooltip)
        self.loginLabel.setText(QCoreApplication.translate("MainWindow", u"syncServer Login", None))
        self.loginButton.setText(QCoreApplication.translate("MainWindow", u"Login", None))
#if QT_CONFIG(tooltip)
        self.passwordLineEdit.setToolTip(QCoreApplication.translate("MainWindow", u"Enter a password.", None))
#endif // QT_CONFIG(tooltip)
        self.passwordLineEdit.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Enter password", None))
#if QT_CONFIG(tooltip)
        self.usernameLineEdit.setToolTip(QCoreApplication.translate("MainWindow", u"Enter a username less than 30 characters.", None))
#endif // QT_CONFIG(tooltip)
        self.usernameLineEdit.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Enter username", None))
#if QT_CONFIG(tooltip)
        self.serverUrlLineEdit.setToolTip(QCoreApplication.translate("MainWindow", u"Enter a server hostname. Example: http://syncserver.example.com", None))
#endif // QT_CONFIG(tooltip)
        self.serverUrlLineEdit.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Enter server hostname", None))
        self.fileListLabel.setText(QCoreApplication.translate("MainWindow", u"Folder: /", None))
        self.showDownloadsManagerButton.setText(QCoreApplication.translate("MainWindow", u"Downloads Manager", None))
        self.appTabWidget.setTabText(self.appTabWidget.indexOf(self.filesTab), QCoreApplication.translate("MainWindow", u"Files", None))
        self.trashbinLabel.setText(QCoreApplication.translate("MainWindow", u"List of deleted files:", None))
        self.appTabWidget.setTabText(self.appTabWidget.indexOf(self.trashbinTab), QCoreApplication.translate("MainWindow", u"Trash Bin", None))
        self.apiKeyListLabel.setText(QCoreApplication.translate("MainWindow", u"Your API Keys", None))
        self.appTabWidget.setTabText(self.appTabWidget.indexOf(self.apiKeysTab), QCoreApplication.translate("MainWindow", u"API Keys", None))
        self.appConfigGroupbox.setTitle(QCoreApplication.translate("MainWindow", u"App Config", None))
        self.serverUrlLabel.setText(QCoreApplication.translate("MainWindow", u"Server URL: {server_url}", None))
        self.clientVersionLabel.setText(QCoreApplication.translate("MainWindow", u"Client version: {version}", None))
        self.appCurrentUsernameLabel.setText(QCoreApplication.translate("MainWindow", u"User: {username}", None))
        self.logLevelLabel.setText(QCoreApplication.translate("MainWindow", u"Log Level:", None))
        self.logLevelComboBox.setItemText(0, QCoreApplication.translate("MainWindow", u"Debug", None))
        self.logLevelComboBox.setItemText(1, QCoreApplication.translate("MainWindow", u"Info", None))
        self.logLevelComboBox.setItemText(2, QCoreApplication.translate("MainWindow", u"Warning", None))
        self.logLevelComboBox.setItemText(3, QCoreApplication.translate("MainWindow", u"Error", None))
        self.logLevelComboBox.setItemText(4, QCoreApplication.translate("MainWindow", u"Critical", None))

        self.logFilePathLabel.setText(QCoreApplication.translate("MainWindow", u"Log File: {file_path}", None))
        self.usersGroupbox.setTitle(QCoreApplication.translate("MainWindow", u"Logged in accounts", None))
        self.appTabWidget.setTabText(self.appTabWidget.indexOf(self.settingsTab), QCoreApplication.translate("MainWindow", u"Settings", None))
        self.menuAbout.setTitle(QCoreApplication.translate("MainWindow", u"Help", None))
    # retranslateUi

