# Form implementation generated from reading ui file '.\src\ui\maingui.ui'
#
# Created by: PyQt6 UI code generator 6.4.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(904, 573)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/antivirus.ico"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setIconSize(QtCore.QSize(64, 64))
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setStyleSheet("background-color: rgb(230, 230, 230);")
        self.centralwidget.setObjectName("centralwidget")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout(self.centralwidget)
        self.horizontalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_4.setSpacing(0)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.widget_sidbar = QtWidgets.QWidget(parent=self.centralwidget)
        self.widget_sidbar.setStyleSheet("background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:1, stop:0.443182 rgba(175, 78, 83, 255), stop:0.863636 rgba(255, 170, 170, 255));\n"
"color: rgb(0, 0, 0);")
        self.widget_sidbar.setObjectName("widget_sidbar")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.widget_sidbar)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.sidebar_load = QtWidgets.QCommandLinkButton(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.sidebar_load.setFont(font)
        self.sidebar_load.setStyleSheet("background-color: qconicalgradient(cx:0, cy:0, angle:135, stop:0 rgba(255, 255, 0, 69), stop:0.375 rgba(255, 255, 0, 69), stop:0.423533 rgba(251, 255, 0, 145), stop:0.45 rgba(247, 255, 0, 208), stop:0.477581 rgba(255, 244, 71, 130), stop:0.518717 rgba(255, 218, 71, 130), stop:0.55 rgba(255, 255, 0, 255), stop:0.57754 rgba(255, 203, 0, 130), stop:0.625 rgba(255, 255, 0, 69), stop:1 rgba(255, 255, 0, 69));\n"
"border-color: rgb(255, 0, 0);")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/reload.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.sidebar_load.setIcon(icon1)
        self.sidebar_load.setIconSize(QtCore.QSize(40, 30))
        self.sidebar_load.setObjectName("sidebar_load")
        self.verticalLayout_3.addWidget(self.sidebar_load)
        self.sidebar_load_folder = QtWidgets.QCommandLinkButton(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.sidebar_load_folder.setFont(font)
        self.sidebar_load_folder.setStyleSheet("background-color: qconicalgradient(cx:0, cy:0, angle:135, stop:0 rgba(255, 255, 0, 69), stop:0.375 rgba(255, 255, 0, 69), stop:0.423533 rgba(251, 255, 0, 145), stop:0.45 rgba(247, 255, 0, 208), stop:0.477581 rgba(255, 244, 71, 130), stop:0.518717 rgba(255, 218, 71, 130), stop:0.55 rgba(255, 255, 0, 255), stop:0.57754 rgba(255, 203, 0, 130), stop:0.625 rgba(255, 255, 0, 69), stop:1 rgba(255, 255, 0, 69));\n"
"border-color: rgb(255, 0, 0);")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/add-folder-svgrepo-com.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.sidebar_load_folder.setIcon(icon2)
        self.sidebar_load_folder.setIconSize(QtCore.QSize(40, 30))
        self.sidebar_load_folder.setObjectName("sidebar_load_folder")
        self.verticalLayout_3.addWidget(self.sidebar_load_folder)
        self.sidebar_scan = QtWidgets.QCommandLinkButton(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.sidebar_scan.setFont(font)
        self.sidebar_scan.setStyleSheet("background-color: qconicalgradient(cx:0, cy:0, angle:135, stop:0 rgba(255, 255, 0, 69), stop:0.375 rgba(255, 255, 0, 69), stop:0.423533 rgba(251, 255, 0, 145), stop:0.45 rgba(247, 255, 0, 208), stop:0.477581 rgba(255, 244, 71, 130), stop:0.518717 rgba(255, 218, 71, 130), stop:0.55 rgba(255, 255, 0, 255), stop:0.57754 rgba(255, 203, 0, 130), stop:0.625 rgba(255, 255, 0, 69), stop:1 rgba(255, 255, 0, 69));\n"
"border-color: rgb(255, 0, 0);")
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/icons8-virus-scan-64.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.sidebar_scan.setIcon(icon3)
        self.sidebar_scan.setIconSize(QtCore.QSize(40, 30))
        self.sidebar_scan.setObjectName("sidebar_scan")
        self.verticalLayout_3.addWidget(self.sidebar_scan)
        self.sidebar_totalApi = QtWidgets.QCommandLinkButton(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.sidebar_totalApi.setFont(font)
        self.sidebar_totalApi.setStyleSheet("background-color: qconicalgradient(cx:0, cy:0, angle:135, stop:0 rgba(255, 255, 0, 69), stop:0.375 rgba(255, 255, 0, 69), stop:0.423533 rgba(251, 255, 0, 145), stop:0.45 rgba(247, 255, 0, 208), stop:0.477581 rgba(255, 244, 71, 130), stop:0.518717 rgba(255, 218, 71, 130), stop:0.55 rgba(255, 255, 0, 255), stop:0.57754 rgba(255, 203, 0, 130), stop:0.625 rgba(255, 255, 0, 69), stop:1 rgba(255, 255, 0, 69));\n"
"border-color: rgb(255, 0, 0);")
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/virustotal-svgrepo-com.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.sidebar_totalApi.setIcon(icon4)
        self.sidebar_totalApi.setIconSize(QtCore.QSize(40, 30))
        self.sidebar_totalApi.setObjectName("sidebar_totalApi")
        self.verticalLayout_3.addWidget(self.sidebar_totalApi)
        self.sidebar_metaApi = QtWidgets.QCommandLinkButton(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.sidebar_metaApi.setFont(font)
        self.sidebar_metaApi.setStyleSheet("background-color: qconicalgradient(cx:0, cy:0, angle:135, stop:0 rgba(255, 255, 0, 69), stop:0.375 rgba(255, 255, 0, 69), stop:0.423533 rgba(251, 255, 0, 145), stop:0.45 rgba(247, 255, 0, 208), stop:0.477581 rgba(255, 244, 71, 130), stop:0.518717 rgba(255, 218, 71, 130), stop:0.55 rgba(255, 255, 0, 255), stop:0.57754 rgba(255, 203, 0, 130), stop:0.625 rgba(255, 255, 0, 69), stop:1 rgba(255, 255, 0, 69));\n"
"border-color: rgb(255, 0, 0);")
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/safe-and-stable-svgrepo-com.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.sidebar_metaApi.setIcon(icon5)
        self.sidebar_metaApi.setIconSize(QtCore.QSize(40, 30))
        self.sidebar_metaApi.setObjectName("sidebar_metaApi")
        self.verticalLayout_3.addWidget(self.sidebar_metaApi)
        self.sidebar_vt_url = QtWidgets.QCommandLinkButton(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.sidebar_vt_url.setFont(font)
        self.sidebar_vt_url.setStyleSheet("background-color: qconicalgradient(cx:0, cy:0, angle:135, stop:0 rgba(255, 255, 0, 69), stop:0.375 rgba(255, 255, 0, 69), stop:0.423533 rgba(251, 255, 0, 145), stop:0.45 rgba(247, 255, 0, 208), stop:0.477581 rgba(255, 244, 71, 130), stop:0.518717 rgba(255, 218, 71, 130), stop:0.55 rgba(255, 255, 0, 255), stop:0.57754 rgba(255, 203, 0, 130), stop:0.625 rgba(255, 255, 0, 69), stop:1 rgba(255, 255, 0, 69));\n"
"border-color: rgb(255, 0, 0);")
        icon6 = QtGui.QIcon()
        icon6.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/icons8-scan-96.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.sidebar_vt_url.setIcon(icon6)
        self.sidebar_vt_url.setIconSize(QtCore.QSize(40, 30))
        self.sidebar_vt_url.setObjectName("sidebar_vt_url")
        self.verticalLayout_3.addWidget(self.sidebar_vt_url)
        self.sidebar_meta_url = QtWidgets.QCommandLinkButton(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.sidebar_meta_url.setFont(font)
        self.sidebar_meta_url.setStyleSheet("background-color: qconicalgradient(cx:0, cy:0, angle:135, stop:0 rgba(255, 255, 0, 69), stop:0.375 rgba(255, 255, 0, 69), stop:0.423533 rgba(251, 255, 0, 145), stop:0.45 rgba(247, 255, 0, 208), stop:0.477581 rgba(255, 244, 71, 130), stop:0.518717 rgba(255, 218, 71, 130), stop:0.55 rgba(255, 255, 0, 255), stop:0.57754 rgba(255, 203, 0, 130), stop:0.625 rgba(255, 255, 0, 69), stop:1 rgba(255, 255, 0, 69));\n"
"border-color: rgb(255, 0, 0);")
        icon7 = QtGui.QIcon()
        icon7.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/scan-it-svgrepo-com.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.sidebar_meta_url.setIcon(icon7)
        self.sidebar_meta_url.setIconSize(QtCore.QSize(40, 30))
        self.sidebar_meta_url.setObjectName("sidebar_meta_url")
        self.verticalLayout_3.addWidget(self.sidebar_meta_url)
        spacerItem = QtWidgets.QSpacerItem(20, 1, QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        self.verticalLayout_3.addItem(spacerItem)
        self.sidebar_feedback = QtWidgets.QCommandLinkButton(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.sidebar_feedback.setFont(font)
        self.sidebar_feedback.setStyleSheet("background-color: qconicalgradient(cx:0, cy:0, angle:135, stop:0 rgba(255, 255, 0, 69), stop:0.375 rgba(255, 255, 0, 69), stop:0.423533 rgba(251, 255, 0, 145), stop:0.45 rgba(247, 255, 0, 208), stop:0.477581 rgba(255, 244, 71, 130), stop:0.518717 rgba(255, 218, 71, 130), stop:0.55 rgba(255, 255, 0, 255), stop:0.57754 rgba(255, 203, 0, 130), stop:0.625 rgba(255, 255, 0, 69), stop:1 rgba(255, 255, 0, 69));\n"
"border-color: rgb(255, 0, 0);")
        icon8 = QtGui.QIcon()
        icon8.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/icons8-feedback-96.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.sidebar_feedback.setIcon(icon8)
        self.sidebar_feedback.setIconSize(QtCore.QSize(40, 30))
        self.sidebar_feedback.setObjectName("sidebar_feedback")
        self.verticalLayout_3.addWidget(self.sidebar_feedback)
        self.sidebar_setting = QtWidgets.QCommandLinkButton(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.sidebar_setting.setFont(font)
        self.sidebar_setting.setStyleSheet("background-color: qconicalgradient(cx:0, cy:0, angle:135, stop:0 rgba(255, 255, 0, 69), stop:0.375 rgba(255, 255, 0, 69), stop:0.423533 rgba(251, 255, 0, 145), stop:0.45 rgba(247, 255, 0, 208), stop:0.477581 rgba(255, 244, 71, 130), stop:0.518717 rgba(255, 218, 71, 130), stop:0.55 rgba(255, 255, 0, 255), stop:0.57754 rgba(255, 203, 0, 130), stop:0.625 rgba(255, 255, 0, 69), stop:1 rgba(255, 255, 0, 69));\n"
"border-color: rgb(255, 0, 0);")
        icon9 = QtGui.QIcon()
        icon9.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/icons8-setting.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.sidebar_setting.setIcon(icon9)
        self.sidebar_setting.setIconSize(QtCore.QSize(40, 30))
        self.sidebar_setting.setObjectName("sidebar_setting")
        self.verticalLayout_3.addWidget(self.sidebar_setting)
        self.side_exit = QtWidgets.QCommandLinkButton(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.side_exit.setFont(font)
        self.side_exit.setStyleSheet("background-color: qconicalgradient(cx:0, cy:0, angle:135, stop:0 rgba(255, 255, 0, 69), stop:0.375 rgba(255, 255, 0, 69), stop:0.423533 rgba(251, 255, 0, 145), stop:0.45 rgba(247, 255, 0, 208), stop:0.477581 rgba(255, 244, 71, 130), stop:0.518717 rgba(255, 218, 71, 130), stop:0.55 rgba(255, 255, 0, 255), stop:0.57754 rgba(255, 203, 0, 130), stop:0.625 rgba(255, 255, 0, 69), stop:1 rgba(255, 255, 0, 69));\n"
"border-color: rgb(255, 0, 0);")
        icon10 = QtGui.QIcon()
        icon10.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/icons8-exit.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.side_exit.setIcon(icon10)
        self.side_exit.setIconSize(QtCore.QSize(40, 30))
        self.side_exit.setObjectName("side_exit")
        self.verticalLayout_3.addWidget(self.side_exit)
        self.verticalLayout_4.addLayout(self.verticalLayout_3)
        self.sidebar_version = QtWidgets.QLabel(parent=self.widget_sidbar)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.sidebar_version.setFont(font)
        self.sidebar_version.setStyleSheet("color: rgb(255, 255, 255);")
        self.sidebar_version.setText("")
        self.sidebar_version.setObjectName("sidebar_version")
        self.verticalLayout_4.addWidget(self.sidebar_version)
        self.horizontalLayout_4.addWidget(self.widget_sidbar)
        self.mainWidget = QtWidgets.QWidget(parent=self.centralwidget)
        self.mainWidget.setStyleSheet("background-color: qlineargradient(spread:pad, x1:0.994318, y1:0.238, x2:1, y2:0.773, stop:0.0397727 rgba(6, 92, 131, 255), stop:0.460227 rgba(11, 57, 88, 255), stop:0.943182 rgba(15, 31, 56, 255));")
        self.mainWidget.setObjectName("mainWidget")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.mainWidget)
        self.verticalLayout_5.setContentsMargins(9, 9, 9, 9)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.WidgetTop = QtWidgets.QWidget(parent=self.mainWidget)
        self.WidgetTop.setStyleSheet("background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:1, stop:0.352273 rgba(45, 135, 0, 255), stop:1 rgba(255, 255, 255, 255));")
        self.WidgetTop.setObjectName("WidgetTop")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.WidgetTop)
        self.verticalLayout.setContentsMargins(9, 9, 9, 9)
        self.verticalLayout.setSpacing(9)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(parent=self.WidgetTop)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setContentsMargins(1, 1, 1, 1)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lineEdit_select_file = QtWidgets.QLineEdit(parent=self.WidgetTop)
        font = QtGui.QFont()
        font.setPointSize(11)
        self.lineEdit_select_file.setFont(font)
        self.lineEdit_select_file.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.lineEdit_select_file.setObjectName("lineEdit_select_file")
        self.horizontalLayout.addWidget(self.lineEdit_select_file)
        self.pushButton_load_file = QtWidgets.QPushButton(parent=self.WidgetTop)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.pushButton_load_file.setFont(font)
        self.pushButton_load_file.setStyleSheet("background-color: rgb(217, 145, 0);\n"
"color: rgb(0, 0, 0);\n"
"border-color: rgb(255, 0, 0);")
        self.pushButton_load_file.setIcon(icon1)
        self.pushButton_load_file.setIconSize(QtCore.QSize(25, 18))
        self.pushButton_load_file.setObjectName("pushButton_load_file")
        self.horizontalLayout.addWidget(self.pushButton_load_file)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.verticalLayout_5.addWidget(self.WidgetTop)
        self.WidgetCentner = QtWidgets.QWidget(parent=self.mainWidget)
        self.WidgetCentner.setObjectName("WidgetCentner")
        self.gridLayout = QtWidgets.QGridLayout(self.WidgetCentner)
        self.gridLayout.setContentsMargins(1, 9, 1, 9)
        self.gridLayout.setObjectName("gridLayout")
        self.label_2 = QtWidgets.QLabel(parent=self.WidgetCentner)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_2.setFont(font)
        self.label_2.setStyleSheet("color: rgb(255, 255, 255);")
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 0, 0, 1, 1)
        self.label_3 = QtWidgets.QLabel(parent=self.WidgetCentner)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_3.setFont(font)
        self.label_3.setStyleSheet("color: rgb(255, 255, 255);")
        self.label_3.setObjectName("label_3")
        self.gridLayout.addWidget(self.label_3, 0, 1, 1, 1)
        self.listWidget_scanned_file = QtWidgets.QListWidget(parent=self.WidgetCentner)
        self.listWidget_scanned_file.setStyleSheet("background-color: rgb(255, 255, 255);\n"
"color: rgb(64, 191, 0);")
        self.listWidget_scanned_file.setObjectName("listWidget_scanned_file")
        self.gridLayout.addWidget(self.listWidget_scanned_file, 1, 1, 1, 1)
        self.listWidget_load_file = QtWidgets.QListWidget(parent=self.WidgetCentner)
        self.listWidget_load_file.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.listWidget_load_file.setObjectName("listWidget_load_file")
        self.gridLayout.addWidget(self.listWidget_load_file, 1, 0, 1, 1)
        self.verticalLayout_5.addWidget(self.WidgetCentner)
        self.WidgetButtom = QtWidgets.QWidget(parent=self.mainWidget)
        self.WidgetButtom.setStyleSheet("background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:1, stop:0.352273 rgba(45, 135, 0, 255), stop:1 rgba(255, 255, 255, 255));")
        self.WidgetButtom.setObjectName("WidgetButtom")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.WidgetButtom)
        self.verticalLayout_2.setContentsMargins(9, 9, 9, 9)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setContentsMargins(4, 4, 4, 4)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.pushButton_scan = QtWidgets.QPushButton(parent=self.WidgetButtom)
        self.pushButton_scan.setStyleSheet("background-color: rgb(217, 145, 0);\n"
"color: rgb(0, 0, 0);\n"
"border-color: rgb(255, 0, 0);")
        icon11 = QtGui.QIcon()
        icon11.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/scan-svgrepo-com.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.pushButton_scan.setIcon(icon11)
        self.pushButton_scan.setObjectName("pushButton_scan")
        self.horizontalLayout_2.addWidget(self.pushButton_scan)
        self.pushButton_scan_total_api = QtWidgets.QPushButton(parent=self.WidgetButtom)
        self.pushButton_scan_total_api.setStyleSheet("background-color: rgb(217, 145, 0);\n"
"color: rgb(0, 0, 0);\n"
"border-color: rgb(255, 0, 0);")
        self.pushButton_scan_total_api.setIcon(icon4)
        self.pushButton_scan_total_api.setObjectName("pushButton_scan_total_api")
        self.horizontalLayout_2.addWidget(self.pushButton_scan_total_api)
        self.pushButton_scan_meta_api = QtWidgets.QPushButton(parent=self.WidgetButtom)
        self.pushButton_scan_meta_api.setStyleSheet("background-color: rgb(217, 145, 0);\n"
"color: rgb(0, 0, 0);\n"
"border-color: rgb(255, 0, 0);")
        self.pushButton_scan_meta_api.setIcon(icon6)
        self.pushButton_scan_meta_api.setObjectName("pushButton_scan_meta_api")
        self.horizontalLayout_2.addWidget(self.pushButton_scan_meta_api)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setContentsMargins(2, 2, 2, 2)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_count = QtWidgets.QLabel(parent=self.WidgetButtom)
        self.label_count.setStyleSheet("background-color: rgb(217, 145, 0);\n"
"color: rgb(0, 0, 0);\n"
"")
        self.label_count.setObjectName("label_count")
        self.horizontalLayout_3.addWidget(self.label_count)
        self.progressBar = QtWidgets.QProgressBar(parent=self.WidgetButtom)
        self.progressBar.setStatusTip("")
        self.progressBar.setStyleSheet("")
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName("progressBar")
        self.horizontalLayout_3.addWidget(self.progressBar)
        self.pushButton_cancel = QtWidgets.QPushButton(parent=self.WidgetButtom)
        self.pushButton_cancel.setStyleSheet("background-color: rgb(217, 145, 0);\n"
"color: rgb(0, 0, 0);\n"
"border-color: rgb(255, 0, 0);")
        self.pushButton_cancel.setObjectName("pushButton_cancel")
        self.horizontalLayout_3.addWidget(self.pushButton_cancel)
        self.verticalLayout_2.addLayout(self.horizontalLayout_3)
        self.verticalLayout_5.addWidget(self.WidgetButtom)
        self.horizontalLayout_4.addWidget(self.mainWidget)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 904, 22))
        self.menubar.setObjectName("menubar")
        self.menu_File = QtWidgets.QMenu(parent=self.menubar)
        self.menu_File.setObjectName("menu_File")
        self.menuSettings = QtWidgets.QMenu(parent=self.menubar)
        self.menuSettings.setObjectName("menuSettings")
        self.menu_Help = QtWidgets.QMenu(parent=self.menubar)
        self.menu_Help.setObjectName("menu_Help")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setStatusTip("")
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.toolBar = QtWidgets.QToolBar(parent=MainWindow)
        self.toolBar.setMouseTracking(False)
        self.toolBar.setMovable(True)
        self.toolBar.setIconSize(QtCore.QSize(30, 30))
        self.toolBar.setObjectName("toolBar")
        MainWindow.addToolBar(QtCore.Qt.ToolBarArea.TopToolBarArea, self.toolBar)
        self.toolBar_2 = QtWidgets.QToolBar(parent=MainWindow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.toolBar_2.sizePolicy().hasHeightForWidth())
        self.toolBar_2.setSizePolicy(sizePolicy)
        self.toolBar_2.setAutoFillBackground(False)
        self.toolBar_2.setMovable(True)
        self.toolBar_2.setIconSize(QtCore.QSize(30, 30))
        self.toolBar_2.setObjectName("toolBar_2")
        MainWindow.addToolBar(QtCore.Qt.ToolBarArea.TopToolBarArea, self.toolBar_2)
        self.actionSelectFile = QtGui.QAction(parent=MainWindow)
        icon12 = QtGui.QIcon()
        icon12.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/icons-select.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.actionSelectFile.setIcon(icon12)
        self.actionSelectFile.setObjectName("actionSelectFile")
        self.actionScan_File = QtGui.QAction(parent=MainWindow)
        self.actionScan_File.setIcon(icon3)
        self.actionScan_File.setObjectName("actionScan_File")
        self.actionExit = QtGui.QAction(parent=MainWindow)
        self.actionExit.setIcon(icon10)
        self.actionExit.setObjectName("actionExit")
        self.actionPreference = QtGui.QAction(parent=MainWindow)
        self.actionPreference.setIcon(icon9)
        self.actionPreference.setObjectName("actionPreference")
        self.action_View_Help = QtGui.QAction(parent=MainWindow)
        icon13 = QtGui.QIcon()
        icon13.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/icons8-help-96.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.action_View_Help.setIcon(icon13)
        self.action_View_Help.setObjectName("action_View_Help")
        self.actionSend_Feedback = QtGui.QAction(parent=MainWindow)
        self.actionSend_Feedback.setIcon(icon8)
        self.actionSend_Feedback.setObjectName("actionSend_Feedback")
        self.actionAbout_Antivirus = QtGui.QAction(parent=MainWindow)
        icon14 = QtGui.QIcon()
        icon14.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/info.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.actionAbout_Antivirus.setIcon(icon14)
        self.actionAbout_Antivirus.setObjectName("actionAbout_Antivirus")
        self.actionScan_With_Total_Api = QtGui.QAction(parent=MainWindow)
        self.actionScan_With_Total_Api.setIcon(icon4)
        self.actionScan_With_Total_Api.setObjectName("actionScan_With_Total_Api")
        self.actionScan_With_Meta_Api = QtGui.QAction(parent=MainWindow)
        self.actionScan_With_Meta_Api.setIcon(icon5)
        self.actionScan_With_Meta_Api.setObjectName("actionScan_With_Meta_Api")
        self.actionLoad = QtGui.QAction(parent=MainWindow)
        self.actionLoad.setIcon(icon1)
        self.actionLoad.setObjectName("actionLoad")
        self.actionVT_Api_Url_Checker = QtGui.QAction(parent=MainWindow)
        self.actionVT_Api_Url_Checker.setIcon(icon11)
        self.actionVT_Api_Url_Checker.setObjectName("actionVT_Api_Url_Checker")
        self.actionMeta_Api_Url_Checker = QtGui.QAction(parent=MainWindow)
        self.actionMeta_Api_Url_Checker.setIcon(icon7)
        self.actionMeta_Api_Url_Checker.setObjectName("actionMeta_Api_Url_Checker")
        self.actionHide_SideBar = QtGui.QAction(parent=MainWindow)
        icon15 = QtGui.QIcon()
        icon15.addPixmap(QtGui.QPixmap(".\\src\\ui\\../../res/ico/menu-bar.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.actionHide_SideBar.setIcon(icon15)
        self.actionHide_SideBar.setObjectName("actionHide_SideBar")
        self.actionSelect_Folder = QtGui.QAction(parent=MainWindow)
        self.actionSelect_Folder.setIcon(icon2)
        self.actionSelect_Folder.setObjectName("actionSelect_Folder")
        self.menu_File.addAction(self.actionLoad)
        self.menu_File.addAction(self.actionSelect_Folder)
        self.menu_File.addAction(self.actionScan_File)
        self.menu_File.addSeparator()
        self.menu_File.addAction(self.actionScan_With_Total_Api)
        self.menu_File.addAction(self.actionScan_With_Meta_Api)
        self.menu_File.addSeparator()
        self.menu_File.addAction(self.actionVT_Api_Url_Checker)
        self.menu_File.addAction(self.actionMeta_Api_Url_Checker)
        self.menu_File.addSeparator()
        self.menu_File.addAction(self.actionHide_SideBar)
        self.menu_File.addAction(self.actionExit)
        self.menuSettings.addAction(self.actionPreference)
        self.menu_Help.addAction(self.action_View_Help)
        self.menu_Help.addAction(self.actionSend_Feedback)
        self.menu_Help.addSeparator()
        self.menu_Help.addAction(self.actionAbout_Antivirus)
        self.menubar.addAction(self.menu_File.menuAction())
        self.menubar.addAction(self.menuSettings.menuAction())
        self.menubar.addAction(self.menu_Help.menuAction())
        self.toolBar.addAction(self.actionHide_SideBar)
        self.toolBar.addAction(self.actionLoad)
        self.toolBar.addAction(self.actionSelect_Folder)
        self.toolBar.addAction(self.actionScan_File)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.actionScan_With_Total_Api)
        self.toolBar.addAction(self.actionScan_With_Meta_Api)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.actionVT_Api_Url_Checker)
        self.toolBar.addAction(self.actionMeta_Api_Url_Checker)
        self.toolBar_2.addAction(self.actionPreference)
        self.toolBar_2.addSeparator()
        self.toolBar_2.addAction(self.action_View_Help)
        self.toolBar_2.addAction(self.actionSend_Feedback)
        self.toolBar_2.addAction(self.actionAbout_Antivirus)
        self.toolBar_2.addSeparator()
        self.toolBar_2.addAction(self.actionExit)
        self.toolBar_2.addSeparator()

        self.retranslateUi(MainWindow)
        self.lineEdit_select_file.returnPressed.connect(self.pushButton_load_file.click) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Q AntiVirus [Dev; Ebrahim Sadiqi]"))
        self.sidebar_load.setToolTip(_translate("MainWindow", "Load files"))
        self.sidebar_load.setStatusTip(_translate("MainWindow", "Load files from drive"))
        self.sidebar_load.setText(_translate("MainWindow", "Load "))
        self.sidebar_load_folder.setToolTip(_translate("MainWindow", "Select Folder and sub folder for scan"))
        self.sidebar_load_folder.setStatusTip(_translate("MainWindow", "Select folder and sub folder for scan"))
        self.sidebar_load_folder.setText(_translate("MainWindow", "Select Folder "))
        self.sidebar_scan.setToolTip(_translate("MainWindow", "Scan files directly"))
        self.sidebar_scan.setStatusTip(_translate("MainWindow", "Scan file directly"))
        self.sidebar_scan.setText(_translate("MainWindow", "Scan File"))
        self.sidebar_totalApi.setToolTip(_translate("MainWindow", "Scan file with total api"))
        self.sidebar_totalApi.setStatusTip(_translate("MainWindow", "Scan file with total api"))
        self.sidebar_totalApi.setText(_translate("MainWindow", "Scan With Total Api"))
        self.sidebar_metaApi.setToolTip(_translate("MainWindow", "Scan file wit Meta api"))
        self.sidebar_metaApi.setStatusTip(_translate("MainWindow", "Scan file with Meta api"))
        self.sidebar_metaApi.setText(_translate("MainWindow", "Scan With Meta Api"))
        self.sidebar_vt_url.setToolTip(_translate("MainWindow", "Scan file wit Meta api"))
        self.sidebar_vt_url.setStatusTip(_translate("MainWindow", "Scan url with Meta api"))
        self.sidebar_vt_url.setText(_translate("MainWindow", "VT Api Url Checker"))
        self.sidebar_meta_url.setToolTip(_translate("MainWindow", "Scan file wit Meta api"))
        self.sidebar_meta_url.setStatusTip(_translate("MainWindow", "Scan url with Meta api"))
        self.sidebar_meta_url.setText(_translate("MainWindow", "Meta Api Url Checker"))
        self.sidebar_feedback.setToolTip(_translate("MainWindow", "Send feedback"))
        self.sidebar_feedback.setStatusTip(_translate("MainWindow", "Send feedback"))
        self.sidebar_feedback.setText(_translate("MainWindow", "Feedback"))
        self.sidebar_setting.setToolTip(_translate("MainWindow", "settings"))
        self.sidebar_setting.setStatusTip(_translate("MainWindow", "settings"))
        self.sidebar_setting.setText(_translate("MainWindow", "Setting"))
        self.side_exit.setToolTip(_translate("MainWindow", "For close program"))
        self.side_exit.setStatusTip(_translate("MainWindow", "For close program"))
        self.side_exit.setText(_translate("MainWindow", "Exit"))
        self.sidebar_version.setToolTip(_translate("MainWindow", "Its version of program"))
        self.sidebar_version.setStatusTip(_translate("MainWindow", "Its version of program"))
        self.label.setText(_translate("MainWindow", "Home"))
        self.pushButton_load_file.setStatusTip(_translate("MainWindow", "Load files from drive"))
        self.pushButton_load_file.setText(_translate("MainWindow", "Load Files"))
        self.label_2.setText(_translate("MainWindow", "Files to Scan"))
        self.label_3.setText(_translate("MainWindow", "Scanned Files"))
        self.pushButton_scan.setStatusTip(_translate("MainWindow", "scan file local without internet"))
        self.pushButton_scan.setText(_translate("MainWindow", "Scan"))
        self.pushButton_scan_total_api.setStatusTip(_translate("MainWindow", "scan file with total virus api it\'s work with internet connection"))
        self.pushButton_scan_total_api.setText(_translate("MainWindow", "Scan With Virus Total API"))
        self.pushButton_scan_meta_api.setStatusTip(_translate("MainWindow", "scan file with meta virus api it\'s work with internet connection"))
        self.pushButton_scan_meta_api.setText(_translate("MainWindow", "Scan With Meta Defender API"))
        self.label_count.setText(_translate("MainWindow", "0"))
        self.pushButton_cancel.setText(_translate("MainWindow", "Cancel"))
        self.pushButton_cancel.setShortcut(_translate("MainWindow", "Ctrl+C"))
        self.menu_File.setTitle(_translate("MainWindow", "&File"))
        self.menuSettings.setTitle(_translate("MainWindow", "Settings"))
        self.menu_Help.setStatusTip(_translate("MainWindow", "Help options"))
        self.menu_Help.setTitle(_translate("MainWindow", "&Help"))
        self.toolBar.setWindowTitle(_translate("MainWindow", "toolBar"))
        self.toolBar.setToolTip(_translate("MainWindow", "Hide and Show Menu Bar"))
        self.toolBar_2.setWindowTitle(_translate("MainWindow", "toolBar_2"))
        self.actionSelectFile.setText(_translate("MainWindow", "&Select File"))
        self.actionSelectFile.setStatusTip(_translate("MainWindow", "Select the file from drive"))
        self.actionSelectFile.setShortcut(_translate("MainWindow", "Ctrl+O"))
        self.actionScan_File.setText(_translate("MainWindow", "Scan &File"))
        self.actionScan_File.setStatusTip(_translate("MainWindow", "Scan direct files"))
        self.actionScan_File.setShortcut(_translate("MainWindow", "Ctrl+S"))
        self.actionExit.setText(_translate("MainWindow", "Exit"))
        self.actionExit.setStatusTip(_translate("MainWindow", "Exit app..."))
        self.actionPreference.setText(_translate("MainWindow", "Preferences"))
        self.actionPreference.setToolTip(_translate("MainWindow", "Setting Configuraitons"))
        self.actionPreference.setStatusTip(_translate("MainWindow", "conifguration settings"))
        self.action_View_Help.setText(_translate("MainWindow", "&View Help"))
        self.action_View_Help.setStatusTip(_translate("MainWindow", "View help"))
        self.actionSend_Feedback.setText(_translate("MainWindow", "Send Feedback"))
        self.actionSend_Feedback.setStatusTip(_translate("MainWindow", "If any problem you can report here"))
        self.actionAbout_Antivirus.setText(_translate("MainWindow", "About Q AntiVirus"))
        self.actionAbout_Antivirus.setStatusTip(_translate("MainWindow", "About anti virus"))
        self.actionScan_With_Total_Api.setText(_translate("MainWindow", "Scan With Total Api"))
        self.actionScan_With_Total_Api.setStatusTip(_translate("MainWindow", "Scan wtih virus total api key"))
        self.actionScan_With_Total_Api.setShortcut(_translate("MainWindow", "Ctrl+T"))
        self.actionScan_With_Meta_Api.setText(_translate("MainWindow", "Scan With Meta Api"))
        self.actionScan_With_Meta_Api.setStatusTip(_translate("MainWindow", "Scan with meta defender api key"))
        self.actionScan_With_Meta_Api.setShortcut(_translate("MainWindow", "Ctrl+M"))
        self.actionLoad.setText(_translate("MainWindow", "&Load..."))
        self.actionLoad.setStatusTip(_translate("MainWindow", "Load files"))
        self.actionLoad.setShortcut(_translate("MainWindow", "Ctrl+L"))
        self.actionVT_Api_Url_Checker.setText(_translate("MainWindow", "VT Api Url Checker"))
        self.actionVT_Api_Url_Checker.setStatusTip(_translate("MainWindow", "Scan url with Virus Total Api"))
        self.actionVT_Api_Url_Checker.setShortcut(_translate("MainWindow", "Ctrl+Shift+T"))
        self.actionMeta_Api_Url_Checker.setText(_translate("MainWindow", "Meta Api Url Checker"))
        self.actionMeta_Api_Url_Checker.setStatusTip(_translate("MainWindow", "Scan Url with Meta defender Api"))
        self.actionMeta_Api_Url_Checker.setShortcut(_translate("MainWindow", "Ctrl+Shift+M"))
        self.actionHide_SideBar.setText(_translate("MainWindow", "Hide SideBar"))
        self.actionSelect_Folder.setText(_translate("MainWindow", "Select Folder"))
        self.actionSelect_Folder.setToolTip(_translate("MainWindow", "Select Folder and subfolder for scan"))
        self.actionSelect_Folder.setStatusTip(_translate("MainWindow", "select folder and subfolder for scan"))
        self.actionSelect_Folder.setShortcut(_translate("MainWindow", "Ctrl+O"))
