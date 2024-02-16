from pathlib import Path
import hashlib
import os
from PyQt6.QtGui import QIcon, QFont, QColor
from PyQt6.QtCore import QObject, pyqtSignal, Qt, QThread
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QLineEdit, QPushButton, QGridLayout

from PyQt6.QtCharts import (
    QChart, QChartView, QPieSeries
)

from PyQt6.QtWidgets import QTableWidgetItem, QMessageBox, QDialog, QVBoxLayout, QLabel
from .ui.scanResult import Ui_DialogScanResult
from .ui.onlineResult import Ui_DialogApiResult
import requests
import configparser
from random import randrange
from threading import Thread

try:
    with open('hard_signatures\SHA256-Hashes_pack1.txt', 'r') as file:
        PACK1 = sorted(file.read().splitlines())

    with open('hard_signatures\SHA256-Hashes_pack2.txt', 'r') as file:
        PACK2 = sorted(file.read().splitlines())

    with open('hard_signatures\SHA256-Hashes_pack3.txt', 'r') as file:
        PACK3 = sorted(file.read().splitlines())
    config = configparser.ConfigParser()
    config.read('settings/settings.ini')
except Exception as ex:
    QMessageBox.critical(None, "Error", "Something wrong!")


# Dialog while scanning
class DialogWait(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Online Scanning ")
        self.setWindowIcon(QIcon('res/ico/icons8-virus-scan-64.png'))
        self.setMinimumSize(200, 50)
        self.vb = QVBoxLayout()
        self.label = QLabel("Please wait a moment...")
        self.vb.addWidget(self.label)
        self.setLayout(self.vb)


class ScannerSignals(QObject):
    # Define custom signals
    result = pyqtSignal(dict)
    progressed = pyqtSignal(int)
    progress = pyqtSignal(str)
    started = pyqtSignal()
    scannad_file = pyqtSignal(Path)
    finished = pyqtSignal()
    virus_found = pyqtSignal(bool)
    errored = pyqtSignal(str, str)
    canceled = pyqtSignal()


#######################
#
#
# This class scan method local with hard signature of virus
#
###################################

class Scanner(QObject):
    """
    This class scan file
    """

    def __init__(self, parent=None, files: tuple = None):
        super().__init__()
        self.parent = parent
        self._files = files
        self.stillrunning = True
        self.virus = []
        self.signals = ScannerSignals()

    def run(self):

        self.stillrunning = True
        try:
            for fileNumber, file in enumerate(self._files, 1):
                if self.stillrunning:
                    self._scanning(file)
                    self.signals.progressed.emit(fileNumber)
                    self.signals.scannad_file.emit(file)
                else:
                    break  # if cancel button clicked loop terminate

            # self.progressed.emit(0)  # Reset the progress
            self.signals.finished.emit()  # After file scanned this signal finished thread

        except Exception as ex:
            self.signals.errored.emit("Scanning File", f"Oops Something wrong {ex}")

    def check_break(self, val):
        # This function check cancel button
        if val:
            self.stillrunning = False
        else:
            self.stillrunning = True

    def _scanning(self, file):  # Scan file with virus hash value
        try:
            # open file and get hash
            with open(file, "rb") as f:
                _bytes = f.read()
                readable_hash = hashlib.sha256(_bytes).hexdigest()
            # print(readable_hash)
            _, name = os.path.split(file)
            if self._check(PACK1, readable_hash):
                self.virus.append(tuple((name, file, readable_hash)))
                return

            if self._check(PACK2, readable_hash):
                self.virus.append(tuple((name, file, readable_hash)))
                return

            if self._check(PACK3, readable_hash):
                self.virus.append(tuple((name, file, readable_hash)))
                return
            self.signals.virus_found.emit(False)
        except Exception as ex:
            self.signals.errored.emit("Error", f"Detail: {ex}")

    # For check file is virus i use binary search for fasting ckeck files
    def _check(self, lst: list, seek):
        first = 0
        last = len(lst) - 1

        while first <= last:
            mid = first + (last - first + 1) // 2
            if str(lst[mid].split(";")[0]) == seek:
                self.signals.virus_found.emit(True)
                return True
            elif str(lst[mid].split(";")[0]) < seek:
                first = mid + 1

            elif str(lst[mid].split(";")[0]) > seek:
                last = mid - 1
        return False


###############################
# Class for show local scan result to screen
#
#
#
#
#
#
#################################################
class ResultScanner:
    # Show result of scanned file
    def __init__(self, parent=None, virus=list) -> None:
        self.parent = parent
        dialog = QDialog(self.parent)
        self.result = Ui_DialogScanResult()
        self.result.setupUi(dialog)
        self.virus = virus
        self.__show()
        self.result.pushButton_return.clicked.connect(dialog.close)

        if len(self.virus) == 0:
            self.result.pushButton_delete_files.setEnabled(False)
            self.result.pushButton_delete_files.setStyleSheet('background-color:gray; \ncolor:white')
        self.result.pushButton_delete_files.clicked.connect(self.removeFile)
        dialog.exec()

    def __show(self):
        try:
            if len(self.virus) != 0:

                self.result.tableWidget_scaned_virus.setRowCount(0)
                # list all founded virus in table         
                for number_row, row_data in enumerate(self.virus):
                    self.result.tableWidget_scaned_virus.insertRow(number_row)
                    for column_number, data in enumerate(row_data):
                        self.result.tableWidget_scaned_virus.setItem(number_row, column_number,
                                                                     QTableWidgetItem(str(data)))
                self.result.label_virus_scan.setStyleSheet('color:red')
                self.result.label_virus_scan.setText(f"Warning {str(number_row + 1)} files are virus")
            else:
                self.result.label_virus_scan.setStyleSheet('color:green')
                self.result.label_virus_scan.setText(f"Probably files are clean")

        except Exception as ex:
            QMessageBox.critical(self.parent, "Virus", f"Oops someting happend!\n{ex}")

    def removeFile(self):
        # Its remove file
        rep = QMessageBox.question(
            self.parent,
            "Remove File",
            "Do you want remove file?",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No
        )
        if rep == QMessageBox.StandardButton.Ok:
            try:
                if len(self.virus) != 0:
                    for file in self.virus:
                        os.remove(file[1])
                    self.virus.clear()
                else:
                    raise FileExistsError("File not exist")
            except Exception as ex:
                QMessageBox.critical(
                    self.parent,
                    "Remove Virus",
                    f"Oops something happened! {ex}"
                )

            else:
                QMessageBox.information(
                    self.parent,
                    "Remove Virus",
                    "Virus successfully removed"
                )
                self.result.tableWidget_scaned_virus.clearContents()
            finally:
                self.__show()
        else:
            return


#####################################
#
#
#
# Its show online result
#######################################
class OnlineResult:
    # Its show online scanned result
    def __init__(self, parent=None, path=Path, _hash='') -> None:
        self.parent = parent
        self.path = path
        self.hash = str(_hash) + ';'

        p1 = randrange(100, 600)
        p2 = randrange(100, 200)
        self.dialog = QDialog(self.parent)
        self.dialog.setGeometry(p1, p2, 565, 519)
        self.dialog.setMinimumSize(565, 519)

        self.ui = Ui_DialogApiResult()
        self.ui.setupUi(self.dialog)

        self.ui.pushButton_return.clicked.connect(self.dialog.close)
        self.ui.pushButton_remove.clicked.connect(self.remove)
        self.ui.pushButton_add.clicked.connect(self.add)
        self.ui.pushButton_add.setEnabled(False)
        self.ui.pushButton_remove.setEnabled(False)

    def add(self):
        try:
            with open('hard_signatures\SHA256-Hashes_pack1.txt', 'a') as _file:
                _file.write('\n' + self.hash)
        except Exception:
            QMessageBox.critical(self.parent, "Adding Virus", 'Oops something happened!')
        else:
            QMessageBox.information(self.parent, "Adding Virus", "Successfully added!")

    def show(self, result) -> None:
        results = result['results']
        unde = result['undetected']
        detected = result['detected']
        chart = ChartResult(unde, detected)
        self.ui.gridLayout.addWidget(chart.chart_view, 2, 0, 1, 1)
        for res in results:
            self.ui.listWidget.addItem(res)
        self.dialog.show()

    def remove(self):
        rep = QMessageBox.question(
            self.parent,
            "Remove File",
            "Do you want remove file?",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No
        )
        if rep == QMessageBox.StandardButton.Ok:
            try:
                os.remove(self.path)
            except Exception as ex:
                QMessageBox.critical(None, "Removing ", f"Something wrong: {ex}")
            else:
                QMessageBox.information(None, "Removing ", "File successfully removed")
        else:
            return


##################################################
#
try:
    VT_API_KEY = config.get('-settings-', 'VirusTotalApiKey')
    # VirusTotal API v3 URL
except:
    pass
VT_API_URL = "https://www.virustotal.com/api/v3/"

# URL for getting the report of a scanned file
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'


#
#######################################################
# This class scan file online with virus total api
#
class VirusTotalScan(QObject):
    """
    This class scan files with virus total api
    :param: upload   this function upload file to virus total sever
    :param: analyse  this function get the analysed value of file from
    :param: info     this function show information
    """

    def __init__(self, parent, path):
        super().__init__()
        self.parent = parent
        self.scan_result = []
        self.detected = 0
        self.undetected = 0
        self.malware_path = str(path)
        self.wait = DialogWait(self.parent)
        self.signals = ScannerSignals()

        # Open the file in binary mode
        with open(path, 'rb') as f:
            # Read the contents of the file
            file_content = f.read()
            readable_hash = hashlib.sha256(file_content).hexdigest()

        self.result = OnlineResult(self.parent, self.malware_path, readable_hash)
        self.result.ui.label_scanMethod.setText("Scan With Virus Total Api")

        # get name file
        _, name = os.path.split(path)
        self.scan_result += [60 * "-"]
        self.scan_result += [f"Name : {name}"]
        self.scan_result += [f"Hash: {readable_hash}"]
        self.scan_result += [f"Path: {path}"]
        self.scan_result += [60 * "-"]

        self.headers = {
            "x-apikey": VT_API_KEY,
            "User-Agent": "vtscan v.1.0",
            "Accept-Encoding": "gzip, deflate",
        }

    def run(self):
        try:
            self.signals.started.emit()
            self.wait.label.setText("Uploading....")
            self.upload()
            self.wait.label.setText("Anlayzing....")
            self.analyse()

            self.signals.result.emit(
                {'results': self.scan_result, 'detected': self.detected, 'undetected': self.undetected})
            self.signals.finished.emit()

        except requests.ConnectionError as ex:
            self.signals.errored.emit("Connection Error", f"Please check your connection\nError Detail:{ex}")
        except requests.ConnectTimeout as ex:
            self.signals.errored.emit("Connection Error", f"Your connection time out\nError Detail:{ex}")
        except requests.FileModeWarning as ex:
            self.signals.errored.emit("File MOde Error", f"Please check you file\nError Detail:{ex}")
        except Exception as ex:
            self.signals.errored.emit("Upload Error ", f"\nError Detail:{ex}")

    def upload(self):
        self.scan_result += [f"upload file:  {self.malware_path} ...."]

        upload_url = VT_API_URL + "files"

        files = {"file": (
            os.path.basename(self.malware_path),
            open(os.path.abspath(self.malware_path), "rb"))
        }

        self.scan_result += [f"upload to  {upload_url}"]
        res = requests.post(upload_url, headers=self.headers, files=files)
        if res.status_code == 200:
            result = res.json()
            self.file_id = result.get("data").get("id")
            self.scan_result += [self.file_id]
            self.scan_result += ["successfully upload PE file: OK"]
        else:
            self.scan_result += ["failed to upload PE file :("]
            self.scan_result += [f"status code: {str(res.status_code)}"]

    def analyse(self):
        self.scan_result += ["get info about the results of analysis..."]
        analysis_url = VT_API_URL + "analyses/" + self.file_id
        res = requests.get(analysis_url, headers=self.headers)

        if res.status_code == 200:
            result = res.json()

            status = result.get("data").get("attributes").get("status")
            if status == "completed":
                stats = result.get("data").get("attributes").get("stats")
                results = result.get("data").get("attributes").get("results")
                self.scan_result += [f'malicious:  {str(stats.get("malicious"))}']
                self.scan_result += [f'undetected : {str(stats.get("undetected"))}']

                for k in results:
                    if results[k].get("category") == "malicious":
                        self.result.ui.pushButton_remove.setEnabled(True)
                        self.result.ui.pushButton_add.setEnabled(True)
                        self.scan_result += ["=================================================="]
                        self.scan_result += [results[k].get("engine_name")]
                        self.scan_result += [f'version :   {results[k].get("engine_version")}']
                        self.scan_result += [f'category : {results[k].get("category")}']
                        self.scan_result += [f'result :  {results[k].get("result")}']
                        self.scan_result += [f'method : {results[k].get("method")}']
                        self.scan_result += [f'update :  {results[k].get("engine_update")}']
                        self.scan_result += ["=================================================="]

                self.scan_result += ["successfully analyse: OK"]
                self.result.ui.label_isScanned.setText("Successfully analyese: OK")
                self.result.ui.label_isScanned.setStyleSheet('color:green')

                self.detected = stats.get("malicious")
                self.undetected = stats.get("undetected")
                if self.detected > 0:
                    self.result.ui.label_is_virus.setStyleSheet('color:red')
                    self.result.ui.label_is_virus.setText(
                        f'{self.detected} security vendors flagged this file as malicious')
                else:
                    self.result.ui.label_is_virus.setStyleSheet('color:green')
                    self.result.ui.label_is_virus.setText('No security vendors flagged this file as malicious')

            elif status == "queued":
                self.scan_result += ["status QUEUED..."]
                with open(os.path.abspath(self.malware_path), "rb") as malware_path:
                    b = malware_path.read()
                    hashsum = hashlib.sha256(b).hexdigest()
                    self.info(hashsum)
        else:

            self.scan_result += ["failed to get results of analysis :("]
            self.scan_result += [f"status code: {str(res.status_code)}"]
            self.signals.errored.emit("Connection Error",
                                      f"Failed to get results of analysis\nStatus Code: {str(res.status_code)}")

    def info(self, file_hash):

        self.scan_result += [f"get file info by ID: {file_hash}"]
        info_url = VT_API_URL + "files/" + file_hash
        res = requests.get(info_url, headers=self.headers)
        if res.status_code == 200:

            result = res.json()
            if result.get("data").get("attributes").get("last_analysis_results"):
                stats = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                self.scan_result += [f'malicious: {str(stats.get("malicious"))}']
                self.scan_result += [f'undetected : {str(stats.get("undetected"))}']

                for k in results:
                    if results[k].get("category") == "malicious":
                        self.result.ui.pushButton_remove.setEnabled(True)
                        self.result.ui.pushButton_add.setEnabled(True)
                        self.result.ui.label_is_virus.setStyleSheet('color:red')

                        self.scan_result += ["=================================================="]
                        self.scan_result += [results[k].get("engine_name")]
                        self.scan_result += [f'version : {results[k].get("engine_version")}']
                        self.scan_result += [f'category : {results[k].get("category")}']
                        self.scan_result += [f'result : {results[k].get("result")}']
                        self.scan_result += [f'method : {results[k].get("method")}']
                        self.scan_result += [f'update :  {results[k].get("engine_update")}']
                        self.scan_result += ["=================================================="]

                self.scan_result += ["successfully analyse: OK"]
                self.result.ui.label_isScanned.setText("Successfully analyese: OK")
                self.result.ui.label_isScanned.setStyleSheet('color:green')

                self.detected = stats.get("malicious")
                self.undetected = stats.get("undetected")
                if self.detected > 0:
                    self.result.ui.label_is_virus.setStyleSheet('color:red')
                    self.result.ui.label_is_virus.setText(
                        f'{self.detected} security vendors flagged this file as malicious')
                else:
                    self.result.ui.label_is_virus.setStyleSheet('color:green')
                    self.result.ui.label_is_virus.setText('No security vendors flagged this file as malicious')
            else:
                self.scan_result += ["failed to analyse :(..."]
                self.result.ui.label_isScanned.setText(
                    f"Failed to get results of analysis! Error code :{str(res.status_code)}")
                self.result.ui.label_isScanned.setStyleSheet('color:red')
        else:
            self.scan_result += ["failed to get information :("]
            self.scan_result += [f'status code: {str(res.status_code)}']


#################################
#
#
try:
    META_API_KEY = config.get('-settings-', 'MetaDefenderApiKey')
except:
    pass

URL = "https://api.metadefender.com/v4/file/"


# Meta Defender Online scan
#
##########################
class MetaDefenderScan(QObject):
    """
    This use meta defender api for scanning file
    :param: upload file to meta defender server for scanning
    :param: analyse get result of scanned file
    """

    def __init__(self, parent, path, filepwd: str = "", archivepwd: str = "") -> None:
        super().__init__()
        self.parent = parent
        self.scan_result = []
        self.detected = 0
        self.undetected = 0
        self.malware_path = path
        self.filepwd = filepwd
        self.archivepwd = archivepwd
        self.file_id = ''
        self.signals = ScannerSignals()
        self.wait = DialogWait(self.parent)

        # Open the file in binary mode
        with open(path, 'rb') as f:
            # Read the contents of the file
            file_content = f.read()
            readable_hash = hashlib.sha256(file_content).hexdigest()
        self.filename = file_content

        self.result = OnlineResult(self.parent, self.malware_path, readable_hash)
        self.result.ui.label_scanMethod.setText("Scan With Meta Defender  Api")

        _, name = os.path.split(path)
        self.scan_result += [60 * "-"]
        self.scan_result += [f"Name : {name}"]
        self.scan_result += [f"Hash: {readable_hash}"]
        self.scan_result += [f"Path: {path}"]
        self.scan_result += [60 * "-"]

        # self.headers = {'apikey': META_API_KEY, 'archivepwd':self.archivepwd, 'privateprocessing':'1',
        #           'filepassword':self.filepwd}
        self.headers = {'apikey': META_API_KEY}

    def run(self):
        try:
            self.signals.started.emit()
            self.wait.label.setText("Uploading....")
            self.upload()
            self.wait.label.setText("Anlayzing....")
            self.analyse()
            self.signals.result.emit(
                {'results': self.scan_result, 'detected': self.detected, 'undetected': self.undetected})
            self.signals.finished.emit()

        except requests.ConnectionError as ex:
            self.signals.errored.emit("Connection Error", f"Please check your connection\nError Detail:{ex}")
        except requests.ConnectTimeout as ex:
            self.signals.errored.emit("Connection Error", f"Your connection time out\nError Detail:{ex}")
        except requests.FileModeWarning as ex:
            self.signals.errored.emit("File MOde Error", f"Please check you file\nError Detail:{ex}")
        except Exception as ex:
            self.signals.errored.emit("Upload Error ", f"\nError Detail:{ex}")

    def upload(self):
        self.scan_result += [f"upload file:  {self.malware_path} ...."]

        with open(self.malware_path, 'rb') as f:
            file_data = f.read()

        files = {
            'file': file_data
        }

        res = requests.post(url=URL, headers=self.headers, files=files)

        if res.status_code == 200:
            result = res.json()

        self.scan_result += [f"upload to  {URL}"]

        if res.status_code == 200:

            result = res.json()
            self.file_id = result['data_id']
            self.scan_result += [self.file_id]
            self.scan_result += ["successfully upload PE file: OK"]
        else:
            self.signals.errored.emit("Upload Error", f"Status code: {str(res.status_code)}")
            self.scan_result += ["failed to upload PE file :("]
            self.scan_result += [f"status code: {str(res.status_code)}"]

    def analyse(self):

        is_virus = False
        url = URL + self.file_id
        headers = {'apikey': META_API_KEY, 'x-file-metadata': '1'}

        self.scan_result += ["get info about the results of analysis..."]
        res = requests.get(url, headers=headers)

        if res.status_code == 200:
            results = res.json()
            self.scan_result += [80 * "="]
            self.scan_result += ["overall_status: {status}".format(status=results['scan_results']['scan_all_result_a'])]
            self.scan_result += [80 * "="]

            for k, v in results['scan_results']['scan_details'].items():
                if v['threat_found'] != "":
                    self.detected += 1
                    is_virus = True

                self.scan_result += [80 * "-"]
                self.scan_result.append("Engine Name: {engine}".format(engine=k))
                self.scan_result.append(
                    "Thread found: {thread}".format(thread=v['threat_found'] if v['threat_found'] else 'clean'))
                self.scan_result.append("Scan Result: {result}".format(result=v['scan_result_i']))
                self.scan_result.append("Def_time: {time}".format(time=v['def_time']))
                self.scan_result += [80 * "-"]

            if results["scan_results"]["total_avs"] != 0:
                self.scan_result += ["successfully analyse: OK"]
                self.result.ui.label_isScanned.setText("Successfully analyese: OK")
                self.result.ui.label_isScanned.setStyleSheet('color:green')
                if is_virus:
                    self.result.ui.pushButton_remove.setEnabled(True)
                    self.result.ui.pushButton_add.setEnabled(True)
                    self.result.ui.label_is_virus.setText(
                        f"{self.detected} security vendors flagged this file as malicious")
                    self.result.ui.label_is_virus.setStyleSheet('color:red')
                else:
                    self.result.ui.label_is_virus.setText("No security vendors flagged this file as malicious")
                    self.result.ui.label_is_virus.setStyleSheet('color:green')

            else:
                self.scan_result += ["successfully analyse: No"]
                self.result.ui.label_isScanned.setText("Successfully analyese: NO")
                self.result.ui.label_isScanned.setStyleSheet('color:red')

            self.scan_result += [80 * "*"]
            self.scan_result += ["Detected Engine: {}".format(self.detected)]
            self.scan_result += ["Total Scanned Engine: {}".format(results["scan_results"]["total_avs"])]
            self.scan_result += [80 * "*"]
            self.undetected = results["scan_results"]["total_avs"] - self.detected

        else:
            self.scan_result += ["failed to get results of analysis :("]
            self.scan_result += [f"status code: {str(res.status_code)}"]
            self.signals.errored.emit("Connection Error",
                                      f"Failed to get results of analysis\nStatus Code: {str(res.status_code)}")


class ChartResult(QChart):
    def __init__(self, undetected: int = 0, detected: int = 0) -> None:
        super().__init__()

        self.undetected = undetected
        self.detected = detected
        self.font = QFont()
        self.font.setPointSize(12)

        self.setTitle('Community Score')
        self.setAnimationOptions(QChart.AnimationOption.AllAnimations)
        self.createDefaultAxes()
        self.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)

        self.series = QPieSeries()
        self.setTheme(QChart().ChartTheme.ChartThemeBlueCerulean)
        self.series.setHoleSize(0.50)

        self.setDropShadowEnabled(True)
        self.setFont(self.font)

        undetected = self.series.append(f'Undetected Vendors {self.undetected}', self.undetected)
        undetected.setColor(QColor(0x00FF00))

        detected = self.series.append(f'Detected Vendors {self.detected} ', self.detected)
        detected.setColor(QColor(0xFF0000))
        detected.setExploded(True)
        self.addSeries(self.series)

        self.chart_view = QChartView(self)


class UrlChecker(QDialog):
    def __init__(self, parent) -> None:
        super().__init__(parent)
        self.vendors = 0
        self.detected = 0
        self.parent = parent

        p1 = randrange(100, 600)
        p2 = randrange(100, 200)

        self.setWindowTitle("Url Checker")
        self.setGeometry(p1, p2, 600, 400)
        self.setMinimumSize(600, 400)

        self.grid = QGridLayout()

        self.method = QLabel()
        self.font = QFont()
        self.font.setPointSize(12)

        lfont = QFont()
        lfont.setBold(True)
        lfont.setPointSize(14)
        self.method.setFont(lfont)
        self.method.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        self.grid.addWidget(self.method, 0, 0)

        self.hbox1 = QHBoxLayout()
        self.url = QLineEdit()
        self.url.setFont(self.font)
        self.url.setPlaceholderText('Enter the url here.')
        self.hbox1.addWidget(self.url)

        self.check_button = QPushButton("Check")
        self.check_button.setIcon(QIcon("res/ico/scan-svgrepo-com.svg"))
        self.check_button.setFont(self.font)
        self.hbox1.addWidget(self.check_button)

        self.grid.addLayout(self.hbox1, 1, 0)

        self.label_result = QLabel()
        self.label_result.setFont(self.font)

        self.category = QLabel()
        self.category.setFont(self.font)
        self.grid.addWidget(self.category, 3, 0)

        self.home = QPushButton("Home")
        self.home.setFont(self.font)
        self.home.setIcon(QIcon('res/ico/home.svg'))

        self.result()
        self.grid.addWidget(self.label_result, 4, 0)

        self.grid.addWidget(self.home, 5, 0)

        self.setLayout(self.grid)

        self.home.clicked.connect(self.close)

    def result_assign(self, result):
        self.vendors = result['vendors']
        self.detected = result['detected']
        tag = result['category']
        self.category.setText(f'<a href="{self.url.text()}">{self.url.text()}</a> "{tag}"')
        if result['detected'] > 0:
            self.label_result.setStyleSheet('color:red')
            self.label_result.setText(f'{self.detected} security vendors flagged this URL as malicious')
        else:
            self.label_result.setStyleSheet('color:green')
            self.label_result.setText(f'No security vendors flagged this URL as malicious')

    def result(self):
        try:
            chart = ChartResult(self.vendors - self.detected, self.detected)
            self.grid.addWidget(chart.chart_view, 2, 0)

        except Exception:
            QMessageBox.warning(self.parent, "Error", "Oops omething happened!")

    def virus_total(self):
        self.method.setText("Virus Total Api Url Scan")
        self.check_button.clicked.connect(self.vt)
        self.show()

    def notification(self, header, msg):
        QMessageBox.warning(self.parent, header, msg)

    def vt(self):
        try:
            url = self.url.text()
            self.vt_thread = QThread()
            self.url_scan = ApiConnecition(url)
            self.url_scan.moveToThread(self.vt_thread)
            self.vt_thread.started.connect(self.url_scan.vt_run)
            self.url_scan.signals.result.connect(self.result_assign)
            self.url_scan.signals.finished.connect(self.result)
            self.url_scan.signals.errored.connect(self.notification)
            self.url_scan.signals.errored.connect(self.vt_thread.quit)
            self.url_scan.signals.errored.connect(self.vt_thread.deleteLater)
            self.url_scan.signals.finished.connect(self.vt_thread.quit)
            self.url_scan.signals.finished.connect(self.url_scan.deleteLater)
            self.vt_thread.finished.connect(self.vt_thread.deleteLater)
            self.vt_thread.start()

        except Exception as ex:
            QMessageBox.warning(self.parent, "Error", "Oops omething happened!")

    def meta_defender(self):
        self.method.setText("Meta Defender Api Url Scan")
        self.check_button.clicked.connect(self.md)
        self.show()

    def md(self):
        try:
            url = self.url.text()
            self.md_thread = QThread()
            self.md_scan = ApiConnecition(url)
            self.md_scan.moveToThread(self.md_thread)
            self.md_thread.started.connect(self.md_scan.md_run)
            self.md_scan.signals.result.connect(self.result_assign)
            self.md_scan.signals.finished.connect(self.result)
            self.md_scan.signals.errored.connect(self.notification)
            self.md_scan.signals.errored.connect(self.md_thread.quit)
            self.md_scan.signals.errored.connect(self.md_thread.deleteLater)
            self.md_scan.signals.finished.connect(self.md_thread.quit)
            self.md_scan.signals.finished.connect(self.md_scan.deleteLater)
            self.md_thread.finished.connect(self.md_thread.deleteLater)
            self.md_thread.start()

        except Exception as ex:
            print(ex)
            QMessageBox.warning(self.parent, "Error", "Oops something happened!")


class ApiConnecition(QObject):
    def __init__(self, url) -> None:
        super().__init__()
        self.url = url
        self.signals = ScannerSignals()
        self.__results = {}

    def vt_run(self):
        try:
            api_url = f'https://www.virustotal.com/vtapi/v2/url/report?apikey={VT_API_KEY}&resource={self.url}'
            response = requests.get(api_url)

            if response.status_code == 200:
                result = response.json()
                print(result['positives'])
                self.__results['detected'] = result['positives']
                self.__results['vendors'] = result['total']
                self.__results['category'] = ''
                self.signals.result.emit(self.__results)
                self.signals.finished.emit()
                # Check if the URL is malicious or not
            else:
                self.signals.errored.emit('connection Error',
                                          f'Error occurred while checking the URL\nError code {response.status_code}.')
        except requests.ConnectionError as ex:
            self.signals.errored.emit("Connection Error", f"Please check your connection\nError Detail:{ex}")
        except requests.ConnectTimeout as ex:
            self.signals.errored.emit("Connection Error", f"Your connection time out\nError Detail:{ex}")
        except requests.FileModeWarning as ex:
            self.signals.errored.emit("File MOde Error", f"Please check you file\nError Detail:{ex}")
        except Exception as ex:
            self.signals.errored.emit("Connection Error", "Oops Something wrong! ")

    def md_run(self):
        try:
            api_url = f'https://api.metadefender.com/v4/url/{self.url}'
            headers = {
                'apikey': META_API_KEY,
                'content-type': 'application/json'
            }
            response = requests.get(api_url, headers=headers)

            if response.status_code == 200:
                result = response.json()
                count = 0
                for k in result['lookup_results']['sources']:
                    if k['provider'] == 'webroot.com':
                        self.__results['category'] = k['category']
                    count += 1

                self.__results['detected'] = result['lookup_results']['detected_by']
                self.__results['vendors'] = count

                self.signals.result.emit(self.__results)
                self.signals.finished.emit()

            else:
                self.signals.errored.emit('connection Error',
                                          f'Error occurred while checking the URL\nError code {response.status_code}.')
        except requests.ConnectionError as ex:
            self.signals.errored.emit("Connection Error", f"Please check your connection\nError Detail:{ex}")
        except requests.ConnectTimeout as ex:
            self.signals.errored.emit("Connection Error", f"Your connection time out\nError Detail:{ex}")
        except requests.FileModeWarning as ex:
            self.signals.errored.emit("File MOde Error", f"Please check you file\nError Detail:{ex}")
        except Exception as ex:
            self.signals.errored.emit("Connection Error", "Oops Something wrong! ")
