"""
Its first version of this program
"""
VERSION = "Version 0.1.0"

from PyQt6.QtCore import QProcess
from PyQt6.QtWidgets import QApplication
from .view import MainWindow
import sys

#this method relaunch program 
def restart():
    QApplication.quit()
    status = QProcess.startDetached(sys.executable, sys.argv)
    print(status)

#Its create main object of application and main Window
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.sidebar_version.setText(VERSION)
    window.show()
    sys.exit(app.exec())