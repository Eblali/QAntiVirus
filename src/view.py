import typing
from PyQt6.QtGui import QColor, QIcon
from PyQt6.QtCore import QThread, QObject, pyqtSignal
from PyQt6.QtWidgets import (
    QMainWindow, QFileDialog, QMessageBox, QDialog,
    QListWidgetItem, QVBoxLayout, QLabel, QFormLayout, QHBoxLayout, QPushButton
)
from pathlib import Path
import os
import hashlib
from collections import deque
from .ui.gui import Ui_MainWindow
from .scan import Scanner, ResultScanner, VirusTotalScan, MetaDefenderScan, UrlChecker, DialogWait
from .ui.settings import Ui_DialogSettings
import configparser
from threading import Thread

# It's read file configuration of setting
try:
    with open('extensions\list-of-blocked-file-extensions.txt', 'r') as file:
        EXTENSIONS = sorted(file.read().splitlines())
    config = configparser.ConfigParser()
    config.read('settings/settings.ini')
except Exception as ex:
    print("Error", ex)

FILTERS = ";;".join(
    ("All Files()",
     "Js Files (*.js)",
     "Exe Files (*.exe)",
     "Cmd Files (*.cmd)",
     "Dll Files (*.dll)",
     "Python Files (*.py)",
     "Bat Files (*.bat)",
     "Gz Files (*.gz)",
     "Doc Files (*.doc)"
     )
)


# This class create object for main window
class MainWindow(QMainWindow, Ui_MainWindow):
    """
    It's main window of program
    :param:
    """

    def __init__(self) -> None:
        """
        This is initial method for main window
        :parameter: self
        :rtype: object
        """
        try:
            super().__init__()
            self.virus = False
            self.rowVirus = []
            self.counter = 0

            self._files = deque()
            self._files_count = len(self._files)
            self.setupUi(self)
            self.wait = DialogWait(self)
            self.wait.setWindowTitle("Files Loading")

            # this method apply dark theme if dark them select in setting
            self.apply_dark()
            self.sideBar_signals()
            self.statusbar.showMessage("Welcome Dear User!")
            self._update_state_when_no_file()
            self.pushButton_load_file.clicked.connect(self.load_files)
            self.actionLoad.triggered.connect(self.load_files)
            self.pushButton_scan.clicked.connect(self.scan_files)
            self.actionPreference.triggered.connect(self.settings)
            self.actionSelectFile.triggered.connect(self.load_files)
            self.actionSelect_Folder.triggered.connect(self.load_folder)
            self.actionScan_File.triggered.connect(self.direct_scan)
            self.actionExit.triggered.connect(self.close)
            self.pushButton_scan_total_api.clicked.connect(lambda: self.vst(self._files))
            self.listWidget_scanned_file.itemClicked.connect(self.file_info)
            self.actionScan_With_Total_Api.triggered.connect(lambda: self.on_direct(self.vst))
            self.actionScan_With_Meta_Api.triggered.connect(lambda: self.on_direct(self.vmd))
            self.actionVT_Api_Url_Checker.triggered.connect(self.vt_url_checker)
            self.actionMeta_Api_Url_Checker.triggered.connect(self.meta_url_checker)
            self.pushButton_scan_meta_api.clicked.connect(lambda: self.vmd(self._files))
            self.actionAbout_Antivirus.triggered.connect(self.about)
            self.action_View_Help.triggered.connect(self.help)
            self.actionSend_Feedback.triggered.connect(self.feedback)

            self.actionHide_SideBar.triggered.connect(self.side_bar)

            self.setAcceptDrops(True)

        except Exception as ex:
            QMessageBox.critical(self, "Error", f"Oops something wrong!\nDetail: {ex}")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        self.progressBar.setValue(0)
        self.statusbar.showMessage("Loading...")

        if len(self._files) == 0:
            self.listWidget_load_file.clear()

        self.listWidget_scanned_file.clear()
        self.progressBar.setStyleSheet('color: blue')
        for file in files:
            self._files.append(Path(file))
            self.listWidget_load_file.addItem(file)
        self._files_count = len(self._files)
        self._update_state_when_files_load()

    def side_bar(self):
        if self.widget_sidbar.isHidden():
            self.widget_sidbar.show()
        else:
            self.widget_sidbar.hide()

    # This method is sideBar_signals its handle Side bar buttons
    def sideBar_signals(self):
        self.sidebar_load.clicked.connect(self.load_files)
        self.sidebar_load_folder.clicked.connect(self.load_folder)
        self.sidebar_scan.clicked.connect(self.direct_scan)
        self.sidebar_totalApi.clicked.connect(lambda: self.on_direct(self.vst))
        self.sidebar_metaApi.clicked.connect(lambda: self.on_direct(self.vmd))
        self.sidebar_vt_url.clicked.connect(self.vt_url_checker)
        self.sidebar_meta_url.clicked.connect(self.meta_url_checker)
        self.sidebar_feedback.clicked.connect(self.feedback)
        self.sidebar_setting.clicked.connect(self.settings)
        self.side_exit.clicked.connect(self.close)

    def vt_url_checker(self):

        try:
            vt_checked = Settings()
            if vt_checked.setting.checkBox_total_api.isChecked() and vt_checked.setting.lineEdit_total_api_key.text() != '':
                vt_url = UrlChecker(self)
                vt_url.virus_total()
            else:
                QMessageBox.information(self, "Settings Configuration", f"Please check your setting configuration!")
        except Exception as ex:
            QMessageBox.critical(self, "Error", f"Oops something wrong\nDetail: {ex}")

    def meta_url_checker(self):
        try:
            md_checked = Settings()
            if md_checked.setting.checkBox_meta_api.isChecked() and md_checked.setting.lineEdit_meta_api_key.text() != '':
                meta_url = UrlChecker(self)
                meta_url.meta_defender()
            else:
                QMessageBox.information(self, "Settings Configuration", f"Please check your setting configuration!")

        except Exception as ex:
            QMessageBox.critical(self, "Error", f"Oops something wrong\nDetail: {ex}")

    # This method apply dark theme
    def apply_dark(self):
        try:
            self.style = config.get('-settings-', 'Style')
            if self.style == "Dark":
                # save sideBar buttons
                sidbarButtons = {
                    self.sidebar_load: 'Load Files',
                    self.sidebar_load_folder: 'Load files from folder and subfolder',
                    self.sidebar_scan: 'Scan Selected file',
                    self.sidebar_totalApi: 'Scan file with virus total api',
                    self.sidebar_metaApi: 'Scan file with virus meta defender api',
                    self.sidebar_vt_url: 'Scan url with Virus Total api',
                    self.sidebar_meta_url: 'Scan url with Meda Defender api',
                    self.sidebar_feedback: 'send feedback',
                    self.sidebar_setting: 'Go to settings',
                    self.side_exit: 'Exit program'
                }

                # Applying color for sideBar buttons
                for button, toolTip in sidbarButtons.items():
                    button.setToolTip(
                        f'<html><head/><body><p><span style=\" color:black;\">{toolTip} </span></p></body></html>')

                # save action buttons
                actionButton = {
                    self.actionHide_SideBar: 'Hide and show left menu bar',
                    self.actionLoad: 'Load Files',
                    self.actionSelect_Folder: 'Load files from folder and subfolder',
                    self.actionSelectFile: 'Select File from dir',
                    self.actionScan_File: 'Scan selected file',
                    self.actionScan_With_Total_Api: 'Scan file with Virus Total api',
                    self.actionScan_With_Meta_Api: 'Scan file with Meta Defender api',
                    self.actionVT_Api_Url_Checker: 'Scan url with Virus Total api',
                    self.actionMeta_Api_Url_Checker: 'Scan url with Meta Defender api',
                    self.actionExit: 'Close program',
                    self.actionPreference: 'Go to setting',
                    self.action_View_Help: 'View help content',
                    self.actionSend_Feedback: 'Send feedback',
                    self.actionAbout_Antivirus: 'About Q AntiVirus'
                }

                # applying black color for toolTip
                for action, toolTip in actionButton.items():
                    action.setToolTip(
                        f'<html><head/><body><p><span style=\" color:black;\">{toolTip} </span></p></body></html>')

                self.lineEdit_select_file.setStyleSheet("background-color:rgb(60, 60, 60)")
                self.progressBar.setStyleSheet('background-color:gray')
                self.setStyleSheet("background-color: rgb(40, 40, 40);\ncolor:white")

                self.WidgetTop.setStyleSheet("background-color: rgb(30, 30, 30);")
                self.WidgetButtom.setStyleSheet("background-color: rgb(30, 30, 30);")
                self.listWidget_load_file.setStyleSheet("background-color: black;\n color:white")
                self.listWidget_scanned_file.setStyleSheet("background-color: black;\ncolor:green")
                self.mainWidget.setStyleSheet('background-color: rgb(60, 60, 60);')
                self.widget_sidbar.setStyleSheet(
                    'background-color: black; \n color:white'
                )
        except Exception as ex:
            QMessageBox.critical(self, "Error", "Something wrong")

    # Show information about programs
    def about(self):
        try:
            with open('res/info/about.html') as file:
                text = file.read()
                QMessageBox.about(self, "About Q AntiVirus", f"{text}")
        except:
            pass

    # show help content
    def help(self):
        try:
            with open('res/info/help.html') as file:
                text = file.read()
                QMessageBox.about(self, "Help", f"{text}")
        except:
            pass

    # send feedback
    def feedback(self):
        try:
            with open('res/info/feedback.html') as file:
                text = file.read()
                rep = QMessageBox.information(
                    self,
                    "feedback",
                    f"{text}",
                    QMessageBox.StandardButton.Open | QMessageBox.StandardButton.Close
                )

                if rep == QMessageBox.StandardButton.Open:
                    import subprocess
                    subprocess.Popen('C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE')
        except FileNotFoundError as err:
            QMessageBox.warning(self, "Open App", "Program not found!")

    # Its direct scan files without showing in list widget
    def on_direct(self, func):
        init_dir = str(Path.home())
        file, _ = QFileDialog.getOpenFileName(self, "Choose file to scan", init_dir)
        func([file])

    # This show information about file if click on list widget item
    def file_info(self):

        item = self.listWidget_scanned_file.item(self.listWidget_scanned_file.currentRow())
        path = item.text()
        self._files.append(path)
        self.info = InfoFile(self)
        try:
            self.info.show()
            _, name = os.path.split(path)
            self.info.name.setText(name)
            self.info.path.setText(path)

            with open(path, "rb") as f:
                _bytes = f.read()
                readable_hash = hashlib.sha256(_bytes).hexdigest()

            self.info.hash.setText(readable_hash)

            self.info.label_result.setText("For more scanning use the following options.")
            self.info.remove.clicked.connect(lambda: self.remove(path))
            self.info.total_scan.clicked.connect(lambda: self.vst([path]))
            self.info.meta_scan.clicked.connect(lambda: self.vmd([path]))

        except Exception as ex:
            QMessageBox.critical(self, "Error", f"Oops !! {ex}")

    # Remove file from directory
    def remove(self, file):
        rep = QMessageBox.question(
            self,
            "Remove File",
            "Do you want remove file?",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No
        )
        if rep == QMessageBox.StandardButton.Ok:
            try:
                os.remove(file)
            except Exception as ex:
                QMessageBox.critical(self, "Removing ", f"Something wrong: {ex}")
            else:
                QMessageBox.critical(self, "Removing ", "File successfully removed")
        else:
            return

    # This method direct scan selected file through local scan
    def direct_scan(self):
        self.load_files()
        self.scan_files()

    # Go to setting dialog
    def settings(self):
        setting = Settings()
        setting.show()

    # closing window event
    def closeEvent(self, event) -> None:
        rep = QMessageBox.question(
            self,
            "Closing!",
            "Do you want close ?",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No
        )

        if rep == QMessageBox.StandardButton.Ok:
            event.accept()
        else:
            event.ignore()

    def _update_state_when_no_file(self):
        # When program start if no files load it's disable some buttons
        self.sidebar_load.setEnabled(True)
        self.sidebar_load_folder.setEnabled(True)
        self.sidebar_scan.setEnabled(True)
        self.actionLoad.setEnabled(True)
        self.actionScan_File.setEnabled(True)
        self.actionSelect_Folder.setEnabled(True)
        self.pushButton_load_file.setEnabled(True)
        self.pushButton_cancel.setEnabled(False)
        self.pushButton_load_file.setFocus()
        self.pushButton_scan.setEnabled(False)
        self.pushButton_scan_meta_api.setEnabled(False)
        self.pushButton_scan_total_api.setEnabled(False)

    def _update_state_when_files_load(self):
        # When files load enable and disable some buttons
        self.statusbar.showMessage("Loaded")
        self.sidebar_load.setEnabled(True)
        self.sidebar_load_folder.setEnabled(True)
        self.sidebar_scan.setEnabled(True)
        self.actionLoad.setEnabled(True)
        self.actionScan_File.setEnabled(True)
        self.actionSelect_Folder.setEnabled(True)
        self.pushButton_load_file.setEnabled(True)
        self.pushButton_scan.setEnabled(True)
        self.pushButton_cancel.setEnabled(False)
        if self._files_count > 1:
            self.pushButton_scan_meta_api.setStyleSheet('background-color:gray')
            self.pushButton_scan_total_api.setStyleSheet('background-color:gray')
            self.pushButton_scan_meta_api.setEnabled(False)
            self.pushButton_scan_total_api.setEnabled(False)
        else:
            self.pushButton_scan_meta_api.setStyleSheet(
                'background-color: rgb(217, 145, 0);\ncolor: rgb(0, 0, 0);\nborder-color: rgb(255, 0, 0);')
            self.pushButton_scan_meta_api.setEnabled(True)
            self.pushButton_scan_total_api.setStyleSheet(
                'background-color: rgb(217, 145, 0);\ncolor: rgb(0, 0, 0);\nborder-color: rgb(255, 0, 0);')
            self.pushButton_scan_total_api.setEnabled(True)

    def _update_state_while_scanning(self):
        # When scanning files it's disable some buttons
        self.statusbar.showMessage("Scanning...")
        self.sidebar_load.setEnabled(False)
        self.sidebar_load_folder.setEnabled(False)
        self.sidebar_scan.setEnabled(False)
        self.actionLoad.setEnabled(False)
        self.actionScan_File.setEnabled(False)
        self.actionSelect_Folder.setEnabled(False)
        self.pushButton_load_file.setEnabled(False)
        self.pushButton_scan.setEnabled(False)
        self.pushButton_cancel.setEnabled(True)

    def _update_state_when_file_scanned(self, file):
        # When file had scanned this change the color if file was virus
        self._files.popleft()
        self.listWidget_load_file.takeItem(0)
        if self.virus:
            i = QListWidgetItem(str(file))
            i.setForeground(QColor('red'))
            self.listWidget_scanned_file.addItem(i)
            self.rowVirus.append(self.counter)
            self.counter += 1
        else:
            self.listWidget_scanned_file.addItem(str(file))
            self.counter += 1

    # Color list change to red if virus find
    def isVirus(self, bool):
        if bool:
            self.progressBar.setStyleSheet("QProgressBar::chunk {background-color: red;}")
            self.virus = True
        else:
            self.virus = False

    # Update progress bar
    def _update_progress_bar(self, file_number):
        self.label_count.setText(str(file_number))
        progress_percent = int(file_number / self._files_count * 100)
        self.progressBar.setValue(progress_percent)

    def loading(self, files):
        try:
            if len(files) != 0:
                src_dir = str(Path(files[0]).parent)
                self.lineEdit_select_file.setText(src_dir)
                # This load files to list widget
                for file in files:
                    if file.is_file():
                        p = Path(file)
                        self._files.append(p)
                        self.listWidget_load_file.addItem(str(p))
                self._files_count = len(self._files)
            else:
                QMessageBox.information(self, "Load Files", "Not file found with this filter!")
        except Exception:
            QMessageBox.warning(self, "Load Files", "Oops something wrong!")
        finally:
            self._update_state_when_files_load()
            self.wait.hide()

    def load_folder(self):
        self.update_while_loading_files()
        try:
            self.check_list()
            dir_path = QFileDialog.getExistingDirectory(parent=self, caption="Select directory",
                                                        directory=self.init_dir,
                                                        options=QFileDialog.Option.ShowDirsOnly,
                                                        )
            if dir_path != '':
                self.wait.show()
                self.thread_load = QThread()
                self.load = LoadFolder(dir_path)
                self.load.moveToThread(self.thread_load)
                self.thread_load.started.connect(self.load.run)
                self.load.result.connect(self.loading)
                self.load.errored.connect(self.notification)
                self.load.finished.connect(self.thread_load.quit)
                self.load.finished.connect(self.load.deleteLater)
                self.thread_load.finished.connect(self.thread_load.deleteLater)
                self.thread_load.start()
            else:
                raise ValueError("You didn't select any folder!")
        except ValueError as ex:
            QMessageBox.warning(self, "Load Files", f"{ex}")
        except Exception as ex:
            QMessageBox.critical(self, "Load Files", "Oops something wrong!")
        finally:
            self._update_state_when_files_load()

    def check_list(self):

        self.wait.label.setText("Loading...")
        self.progressBar.setValue(0)
        self.statusbar.showMessage("Loading...")

        self.progressBar.setStyleSheet('color: blue')
        if len(self._files) != 0:
            rep = QMessageBox.information(
                self,
                "Load Files",
                "Are you want clear current list?",
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No
            )
            if rep == QMessageBox.StandardButton.Ok:
                self._files.clear()
                self.listWidget_load_file.clear()

        self.listWidget_scanned_file.clear()
        if self.lineEdit_select_file.text():
            self.init_dir = self.lineEdit_select_file.text()
        else:
            self.init_dir = str(Path.home())

    def update_while_loading_files(self):
        self.sidebar_load.setEnabled(False)
        self.sidebar_load_folder.setEnabled(False)
        self.sidebar_scan.setEnabled(False)
        self.actionLoad.setEnabled(False)
        self.actionScan_File.setEnabled(False)
        self.actionSelect_Folder.setEnabled(False)
        self.pushButton_load_file.setEnabled(False)
        self.pushButton_scan.setEnabled(False)

    def load_files(self):
        # If click load buttons this method will call and load files
        self.update_while_loading_files()
        try:

            self.check_list()

            files, _ = QFileDialog.getOpenFileNames(self, "Choose file to scan", self.init_dir, filter=FILTERS)
            if len(files) > 0:
                self.wait.show()
                src_dir = str(Path(files[0]).parent)
                self.lineEdit_select_file.setText(src_dir)
                # This load files to list widget
                for file in files:
                    self._files.append(Path(file))
                    self.listWidget_load_file.addItem(file)
                self._files_count = len(self._files)
            else:
                raise ValueError("You didn't select any files!")
        except ValueError as ex:
            QMessageBox.warning(self, "Load Files", f"{ex}")
        except Exception as ex:
            QMessageBox.critical(self, "Load Files", f"Oops something wrong! {ex}")
        # For enable scan batton
        finally:
            self.wait.hide()
            self._update_state_when_files_load()

    # Its start scan files
    def scan_files(self):
        self._run_scanner_thread()
        self._update_state_while_scanning()

    # Its run thread for each file for scanning
    def _run_scanner_thread(self):
        # This method create thread run scan file
        self.scan_thread = QThread()
        self._scanner = Scanner(self, files=tuple(self._files))
        self._scanner.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self._scanner.run)
        self._scanner.signals.scannad_file.connect(self._update_state_when_file_scanned)
        self._scanner.signals.virus_found.connect(self.isVirus)
        self._scanner.signals.progressed.connect(self._update_progress_bar)
        self._scanner.signals.finished.connect(self._update_state_when_no_file)
        self._scanner.signals.finished.connect(self.show_virus)
        self.pushButton_cancel.clicked.connect(lambda: self._scanner.check_break(1))
        self._scanner.signals.finished.connect(self.scan_thread.quit)
        self._scanner.signals.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.start()

    def show_virus(self):
        # This function show result of scan process
        self.statusbar.showMessage("Scanned")
        virus = self._scanner.virus
        self.virus = ResultScanner(self, virus)

    def vst(self, file):
        # This method scan file with virus total api
        vt_checked = Settings()
        if vt_checked.setting.checkBox_total_api.isChecked() and vt_checked.setting.lineEdit_total_api_key.text() != '':
            self.online_scan(VirusTotalScan, file, 'Virus Total Api Key')
        else:
            QMessageBox.information(self, "Settings Configuration", f"Please check your setting configuration!")

    def vmd(self, file):
        # This method scan file with meta defender api
        md_checked = Settings()
        if md_checked.setting.checkBox_meta_api.isChecked() and md_checked.setting.lineEdit_meta_api_key.text() != '':
            self.online_scan(MetaDefenderScan, file, 'Meta Defender Api Key')
        else:
            QMessageBox.information(self, "Settings Configuration", f"Please check your setting configuration!")

    # Show notifaction
    def notification(self, header, msg):
        self.wait.hide()
        QMessageBox.warning(self, header, msg)

    # It's scan from total virus
    def online_scan(self, obj, file, type):
        try:
            path = file.pop()
            if os.path.getsize(path) < 32000000:
                self.online_thread = QThread()
                self.api_scan = obj(self, path)
                # result = self.vstscan.result()
                self.api_scan.moveToThread(self.online_thread)
                self.online_thread.started.connect(self.api_scan.run)
                self.api_scan.signals.errored.connect(self.notification)
                self.api_scan.signals.started.connect(self.api_scan.wait.show)
                self.api_scan.signals.errored.connect(self.online_thread.quit)
                self.api_scan.signals.errored.connect(self.api_scan.wait.hide)

                self.api_scan.signals.result.connect(self.api_scan.result.show)
                self.api_scan.signals.finished.connect(self.api_scan.wait.hide)
                self.api_scan.signals.finished.connect(self.online_thread.quit)
                self.api_scan.signals.finished.connect(self.online_thread.deleteLater)
                self.online_thread.finished.connect(self.online_thread.deleteLater)
                self.api_scan.signals.finished.connect(self.api_scan.wait.hide)

                self.online_thread.start()
            else:
                QMessageBox.information(self, "Size File", "Your file size larger than 32 MB")
        except Exception as ex:
            QMessageBox.information(self, "Error", f"Something wrong\n Detail:{ex}")


class LoadFolder(QObject):
    result = pyqtSignal(list)
    finished = pyqtSignal()
    errored = pyqtSignal(str, str)

    def __init__(self, path) -> None:
        super().__init__()
        self.path = path
        self.__files = []

    def run(self):
        try:
            path = Path(self.path)
            ex = Settings()
            if ex.setting.radioButton_all_ext.isChecked():
                for ext in EXTENSIONS:
                    self.__files.extend(path.rglob(f'*.{ext}'))
            elif ex.setting.radioButton_give_ext.isChecked() and ex.setting.lineEdit_give_ext.text() != '':
                exten = ex.setting.lineEdit_give_ext.text()
                self.__files += list(path.rglob(f'{exten}'))
            else:
                self.__files += list(path.rglob('*'))

            self.result.emit(self.__files)
            self.finished.emit()

        except Exception as ex:
            self.errored.emit("Error", f"Oops something wrong\nDetail: {ex}")


# Its create a dialog widget result of file and show file information
class InfoFile(QDialog):
    # Its show information about file
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("File Information")
        self.setMinimumSize(400, 200)
        self.setWindowIcon(QIcon("res/ico/analysis.png"))
        vb = QVBoxLayout()
        form_layout = QFormLayout()
        self.name = QLabel()
        self.path = QLabel()
        self.hash = QLabel()
        form_layout.addRow('Name:', self.name)
        form_layout.addRow('Path:', self.path)
        form_layout.addRow('Hash:', self.hash)
        hb1 = QHBoxLayout()
        hb1.addLayout(form_layout)
        vb.addLayout(hb1)

        hb2 = QHBoxLayout()
        self.label_result = QLabel()
        hb2.addWidget(self.label_result)
        vb.addLayout(hb2)

        hb3 = QHBoxLayout()
        self.total_scan = QPushButton("Scan Total Api")
        self.total_scan.setIcon(QIcon('res/ico/virustotal-svgrepo-com.svg'))
        self.meta_scan = QPushButton("Scan meta Api")
        self.meta_scan.setIcon(QIcon('res/ico/safe-and-stable-svgrepo-com.svg'))
        self.remove = QPushButton("Remove")
        self.remove.setIcon(QIcon('res/ico/remove.png'))

        hb3.addWidget(self.total_scan)
        hb3.addWidget(self.meta_scan)
        hb3.addWidget(self.remove)
        vb.addLayout(hb3)
        self.setLayout(vb)


# This class for configuration settings
class Settings():
    def __init__(self) -> None:
        self.parent = MainWindow()
        self.dialog = QDialog(self.parent)
        self.setting = Ui_DialogSettings()
        self.setting.setupUi(self.dialog)
        self.set_config()
        self.setting.pushButton_save_config.clicked.connect(self.save_setting)
        self.setting.pushButton_home.clicked.connect(self.dialog.close)
        self.key = self.setting.lineEdit_total_api_key.text()

    def show(self):
        # execute dialog
        self.dialog.exec()

    def set_config(self):
        # Set configuration
        try:
            is_all_ext = config.get('-settings-', 'all_block_extensions')
            is_one_ext = config.get('-settings-', 'select_extenstion')
            extention = config.get('-settings-', 'extenstion')
            total_check = config.get('-settings-', 'VirusTotalScan')
            total_api_key = config.get('-settings-', 'VirusTotalApiKey')
            meta_check = config.get('-settings-', 'MetaDefenderScan')
            meta_api_key = config.get('-settings-', 'MetaDefenderApiKey')
            style = config.get('-settings-', 'Style')

            if is_all_ext == "True":
                self.setting.radioButton_all_ext.setChecked(True)
            else:
                self.setting.radioButton_all_ext.setChecked(False)

            if is_one_ext == "True":
                self.setting.radioButton_give_ext.setChecked(True)
            else:
                self.setting.radioButton_give_ext.setChecked(False)

            if total_check == "True":
                self.setting.checkBox_total_api.setChecked(True)
            else:
                self.setting.checkBox_total_api.setChecked(False)

            if meta_check == "True":
                self.setting.checkBox_meta_api.setChecked(True)
            else:
                self.setting.checkBox_meta_api.setChecked(False)

            self.setting.lineEdit_give_ext.setText(extention)
            self.setting.lineEdit_total_api_key.setText(total_api_key)
            self.setting.lineEdit_meta_api_key.setText(meta_api_key)

            if style == 'Dark':
                self.setting.radioButton_dark.setChecked(True)
            if style == 'Light':
                self.setting.radioButton_light.setChecked(True)

        except Exception as ex:
            QMessageBox.critical(self.parent, "Error", f"Something Wrong {ex}")

    def save_setting(self):
        is_all_ext = self.setting.radioButton_all_ext.isChecked()
        is_one_ext = self.setting.radioButton_give_ext.isChecked()
        ext = self.setting.lineEdit_give_ext.text()
        # get VirusTotal scan checkbox status and meta defender scan checkbox status
        virus_total_scan = self.setting.checkBox_total_api.isChecked()
        virus_meta_scan = self.setting.checkBox_meta_api.isChecked()
        # get api keys
        api_key = self.setting.lineEdit_total_api_key.text()
        MetaDefenderApiKey = self.setting.lineEdit_meta_api_key.text()

        try:
            config['-settings-']['VirusTotalScan'] = str(virus_total_scan)
            config['-settings-']['VirusTotalApiKey'] = str(api_key)
            config["-settings-"]["MetaDefenderScan"] = str(virus_meta_scan)
            config["-settings-"]["MetaDefenderApiKey"] = str(MetaDefenderApiKey)
            config['-settings-']['all_block_extensions'] = str(is_all_ext)
            config["-settings-"]["select_extenstion"] = str(is_one_ext)
            config["-settings-"]["extenstion"] = str(ext)
            if self.setting.radioButton_dark.isChecked():
                config["-settings-"]["Style"] = "Dark"
            if self.setting.radioButton_light.isChecked():
                config["-settings-"]["Style"] = "Light"

            with open('settings/settings.ini', 'w') as configfile:  # save
                config.write(configfile)

        except Exception as ex:
            QMessageBox.critical(self.parent, 'Save configration',
                                 f"Oops you don't have permision, rus as administrator.")
        else:
            rep = QMessageBox.information(
                self.parent, 'Save configration',
                f'Configuration successfully saved!\nFor apply setting relaunch ?',
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No
            )
            if rep == QMessageBox.StandardButton.Ok:
                from .app import restart
                restart()
            else:
                pass
