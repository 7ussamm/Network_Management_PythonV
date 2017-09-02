#__author__="Hussam Ashraf"


from PyQt4.QtCore import *
from PyQt4.QtGui import *
import sys
import subprocess as sub
import os


# style file of the entire application
with open(r'dark.stylesheet.txt', 'r') as file:#ffaa00
    styleFile = file.read()
cwd = os.getcwd()
os.chdir(r'C:\Windows\System32')




class Gui(QMainWindow):

    def __init__(self, parent=None):
        super(QMainWindow, self).__init__(parent)

        self.setWindowTitle('Network Management')
        self.setMaximumWidth(500)
        self.setMinimumWidth(500)
        self.setMaximumHeight(500)
        self.setMinimumHeight(500)
        self.setWindowIcon(QIcon(cwd + r'\network.png'))
        self.setStyleSheet(styleFile)
        ##########################################################
        ## Help Choices
        self.about = QAction('About', self)
        self.about.triggered.connect(self.aboutMe)
        self.about.setStatusTip('About Network Management')

        self.statusBar()

        mMenue = self.menuBar()
        #mMenue.setStyleSheet('QWidget {background-color:#2F343F;}')
        helpMenue = mMenue.addMenu('Help')
        helpMenue.addAction(self.about)

        self.body()
        self.ipFind = IpFind()
        self.disCash = Cashe()
        self.disActive = NetStat()
        self.statIp = StatIP()
        self.disMac = DisMAc()

    def closeEvent(self, event):
        confirm = QMessageBox.question(self, 'Network Management', 'Do you really want to Exit !!!', QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.No:
            event.ignore()
        else:
            self.Close()
            pass

    def body(self):
        #self.choiceBtn = QPushButton('Use CMD ', self)
        #self.choiceBtn.clicked.connect(self.useCmd)



        self.ipBtn = QPushButton('IPV4 Address', self)
        self.ipBtn.setGeometry(198, 80, 100, 40)
        self.ipBtn.clicked.connect(self.disIP)
        self.ipBtn.setStatusTip('Display info about all interfaces IP.')
        self.ipBtn.setCursor(QCursor(Qt.PointingHandCursor))

        self.staticIp = QPushButton('Set Static IP', self)
        self.staticIp.setGeometry(100, 130, 100, 40)
        self.staticIp.clicked.connect(self.stIp)
        self.staticIp.setStatusTip('Set device IPV4 Statically.')
        self.staticIp.setCursor(QCursor(Qt.PointingHandCursor))

        self.dynamicIp = QPushButton('Set Dynamic IP', self)
        self.dynamicIp.setGeometry(300, 130, 100, 40)
        self.dynamicIp.clicked.connect(self.dyIP)
        self.dynamicIp.setStatusTip('Set device IPV4 Dynamically.')
        self.dynamicIp.setCursor(QCursor(Qt.PointingHandCursor))

        self.macBtn = QPushButton('Mac Address', self)
        self.macBtn.setGeometry(300, 200, 100, 40)
        self.macBtn.clicked.connect(self.disMc)
        self.macBtn.setStatusTip('Display info about all interfaces including MAC addresses.')
        self.macBtn.setCursor(QCursor(Qt.PointingHandCursor))

        self.restartNet = QPushButton('Restart Network', self)
        self.restartNet.setGeometry(100, 200, 100, 40)
        self.restartNet.clicked.connect(self.restartNetwork)
        self.restartNet.setStatusTip('Restart device dynamic ip, MUST NOT be set Static.')
        self.restartNet.setCursor(QCursor(Qt.PointingHandCursor))

        self.disConnect = QPushButton('Disconnect', self)
        self.disConnect.setGeometry(100, 270, 100, 40)
        self.disConnect.clicked.connect(self.disconnectNet)
        self.disConnect.setStatusTip('Release device ip, MUST NOT be set Static.')
        self.disConnect.setCursor(QCursor(Qt.PointingHandCursor))

        self.netStat = QPushButton('Display Netstat', self)
        self.netStat.setGeometry(300, 270, 100, 40)
        self.netStat.clicked.connect(self.disNet)
        self.netStat.setStatusTip('Display all active connections.')
        self.netStat.setCursor(QCursor(Qt.PointingHandCursor))

        self.dnsCashe = QPushButton('DNS Cashe', self)
        self.dnsCashe.setGeometry(100, 340, 100, 40)
        self.dnsCashe.clicked.connect(self.disCashe)
        self.dnsCashe.setStatusTip('Display DNS cashe.')
        self.dnsCashe.setCursor(QCursor(Qt.PointingHandCursor))

        self.clearCashe = QPushButton('Clear DNS Cashe', self)
        self.clearCashe.setGeometry(300, 340, 100, 40)
        self.clearCashe.clicked.connect(self.clrCash)
        self.clearCashe.setStatusTip('Clear DNS Cashe.')
        self.clearCashe.setCursor(QCursor(Qt.PointingHandCursor))

        self.startHot = QPushButton('Start HotSpot', self)
        self.startHot.setGeometry(100, 410, 100, 40)
        self.startHot.clicked.connect(self.srHotspot)
        self.startHot.setStatusTip('Configure HotSpot(Laptops Only).')
        self.startHot.setCursor(QCursor(Qt.PointingHandCursor))

        self.stopHot = QPushButton('Stop HotSpot', self)
        self.stopHot.setGeometry(300, 410, 100, 40)
        self.stopHot.clicked.connect(self.spHotspot)
        self.stopHot.setStatusTip('Stop HotSpot.')
        self.stopHot.setCursor(QCursor(Qt.PointingHandCursor))


    @pyqtSlot()
    #def useCmd(self):
       # mainCore()

    def disIP(self):
        self.ipFind.start()

    def stIp(self):
        self.statIp.start()
        self.info = StNetworkIp()
        self.info.show()

    def dyIP(self):
        self.dynip = DyNetworkIP()
        self.dynip.show()

    def restartNetwork(self):
        sub.Popen('ipconfig /release', shell=True)
        sub.Popen('ipconfig /renew', shell=True)

    def disMc(self):
        self.disMac.start()

    def disconnectNet(self):
        sub.Popen('ipconfig /release', shell=True)

    def disNet(self):
        self.disActive.start()

    def disCashe(self):
        self.disCash.start()

    def clrCash(self):
        sub.Popen('ipconfig /flushdns', shell=True)

    def srHotspot(self):
        self.hotD = Hotspot()
        self.hotD.show()

    def spHotspot(self):
        sub.Popen('netsh wlan stop hostednetwork', shell=True)


    def aboutMe(self):
        self.About = About()

        self.About.show()

    def Close(self):
        try:
            self.DyNetworkIP.close()
            self.StNetworkIp.close()
            self.Hotspot.close()
            self.About.close()
        except:
            pass
        sys.exit()

    #def msg(self):
      #  QMessageBox.information(self, 'hello there', QMessageBox.Ok|QMessageBox.No)

######################################
# Threading classes

class IpFind(QThread): # ipconfig thread
    def __init__(self, parent=None):
        super(IpFind, self).__init__(parent)
    def run(self):
        sub.Popen('start cmd.exe /k netsh interface ipv4 show config ', shell=True)

class Cashe(QThread): # display cashe thread
    def __init__(self, parent=None):
        super(Cashe, self).__init__(parent)
    def run(self):
        sub.Popen('start cmd.exe /k ipconfig /displaydns ', shell=True)

class NetStat(QThread): # display active connections
    def __init__(self, parent=None):
        super(NetStat, self).__init__(parent)
    def run(self):
        sub.Popen('start cmd.exe /k netstat -a', shell=True)

class StatIP(QThread): #display interface name
    def __init__(self, parent=None):
        super(StatIP, self).__init__(parent)
    def run(self):
        sub.Popen('start cmd.exe /k netsh interface ip show interfaces', shell=True)
class DynIP(QThread): # set dynamic ip
    def __init__(self):
        super(DynIP, self).__init__()
    def run(self):
        sub.Popen()
class DisMAc(QThread): # display mac
    def __init__(self):
        super(DisMAc, self).__init__()
    def run(self):
        sub.Popen('start cmd.exe /k ipconfig /all', shell=True)



# Network information

class StNetworkIp(QWidget):
    def __init__(self):
        super(StNetworkIp, self).__init__()
        self.setWindowFlags(Qt.Window)
        self.setWindowTitle('Setup a Static IP')
        self.setMaximumWidth(300)
        self.setMaximumHeight(200)
        self.setMinimumHeight(200)
        self.setMinimumWidth(300)
        self.setWindowIcon(QIcon(cwd + r'\network.png'))
        self.setStyleSheet(styleFile)

        self.thrd = StIP()

        self.body()
    def body(self):


        self.gridLayout = QGridLayout(self)

        self.ip = QLabel('IPV4')
        self.ip.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')
        self.gridLayout.addWidget(self.ip, 0, 0, 1, 1)

        self.ipT = QLineEdit()
        self.gridLayout.addWidget(self.ipT, 0, 1, 1, 1)
        self.ipT.textChanged.connect(self.Apply)

        self.subnet = QLabel('Subnet Mask')
        self.subnet.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')
        self.gridLayout.addWidget(self.subnet, 2, 0, 1, 1)

        self.subnetT= QLineEdit()
        self.subnetT.setPlaceholderText('255.255.255.0')
        self.subnetT.textChanged.connect(self.Apply)
        self.gridLayout.addWidget(self.subnetT, 2, 1, 1, 1)


        self.gateway = QLabel('Default gateway')
        self.gridLayout.addWidget(self.gateway, 3, 0, 1, 1)
        self.gateway.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')

        self.gatewayT = QLineEdit()
        self.gatewayT.textChanged.connect(self.Apply)
        self.gridLayout.addWidget(self.gatewayT, 3, 1, 1, 1)


        self.pdns = QLabel('Primary DNS')
        self.gridLayout.addWidget(self.pdns, 4, 0, 1, 1)
        self.pdns.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')

        self.pdnsT = QLineEdit()
        self.pdnsT.setText('8.8.8.8')
        self.pdnsT.textChanged.connect(self.Apply)
        self.gridLayout.addWidget(self.pdnsT, 4, 1, 1, 1)

        self.sdns = QLabel('Secondary DNS')
        self.gridLayout.addWidget(self.sdns, 5, 0, 1, 1)
        self.sdns.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')

        self.sdnsT = QLineEdit()
        self.sdnsT.setPlaceholderText('4.2.2.2')
        self.gridLayout.addWidget(self.sdnsT, 5, 1, 1, 1)


        self.interface = QLabel('Interface Name')
        self.gridLayout.addWidget(self.interface, 6, 0, 1, 1)
        self.interface.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')

        self.interfaceT = QLineEdit()
        self.interfaceT.textChanged.connect(self.Apply)
        self.gridLayout.addWidget(self.interfaceT, 6, 1, 1, 1)

        self.apply = QPushButton('Apply', self)
        self.apply.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')
        self.apply.setEnabled(False)
        self.apply.clicked.connect(self.readInfo)
        self.gridLayout.addWidget(self.apply, 7, 0, 2, 1)


    # enable button only if all fields are filled in

    def ipCheck(self):
        return str(self.ipT.text())
    def subnetCheck(self):
        return str(self.subnetT.text())
    def gatewayCheck(self):
        return str(self.gatewayT.text())
    def pdnstCheck(self):
        return str(self.pdnsT.text())
    def interfaceCheck(self):
        return str(self.interfaceT.text())
    def Apply(self):
        if self.ipCheck() != '' and self.subnetCheck() != '' and self.gatewayCheck() != '' and self.pdnstCheck() != '' and self.interfaceCheck() != '':
            self.apply.setEnabled(True)
        else:
            self.apply.setEnabled(False)


    def readInfo(self):
        self.thrd.IP = self.ipT.text()
        self.thrd.MASK = self.subnetT.text()
        self.thrd.GATE = self.gatewayT.text()
        self.thrd.PDNS = self.pdnsT.text()
        self.thrd.SDNS = self.sdnsT.text()
        self.thrd.NAME = self.interfaceT.text()

        self.thrd.start()

class StIP(QThread):
    def __init__(self):
        super(StIP, self).__init__()
    def run(self):

        sub.Popen('netsh interface ipv4 set address name="{}" static {} {} {}'.format(self.NAME, self.IP, self.MASK, self.GATE), shell=True)
        sub.Popen('netsh interface ipv4 set dns name="{}" static {} '.format(self.NAME, self.PDNS), shell=True)
        try:
            sub.Popen('netsh interface ipv4 add dns name="{}" {} '.format(self.NAME, self.SDNS), shell=True)
        except: # ignoring second DNS if user didn't use it
            pass

class DyNetworkIP(QWidget):
    def __init__(self):
        super(DyNetworkIP, self).__init__()
        self.setWindowFlags(Qt.Window)
        self.setWindowTitle('Setup a Dynamic IP')
        self.setMaximumWidth(300)
        self.setMaximumHeight(100)
        self.setMinimumHeight(100)
        self.setMinimumWidth(300)
        self.setWindowIcon(QIcon(cwd + r'\network.png'))
        self.setStyleSheet(styleFile)


        self.thrd = DyIP()

        self.body()
    def body(self):


        self.gridLayout = QGridLayout(self)


        self.interface = QLabel('Interface Name')
        self.gridLayout.addWidget(self.interface, 6, 0, 1, 1)
        self.interface.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')

        self.interfaceT = QLineEdit()
        self.gridLayout.addWidget(self.interfaceT, 6, 1, 1, 1)
        self.interfaceT.textChanged.connect(self.textChanged)

        self.apply = QPushButton('Apply', self)
        self.apply.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')
        self.apply.setEnabled(False)
        self.apply.clicked.connect(self.readInfo)
        self.gridLayout.addWidget(self.apply, 7, 0, 2, 1)

    def textChanged(self, text):
        if text:
            self.apply.setEnabled(True)
    def readInfo(self):
        self.thrd.NAME = self.interfaceT.text()
        self.thrd.start()
        self.close()


class DyIP(QThread):
    def __init__(self):
        super(DyIP, self).__init__()
    def run(self):

        sub.Popen('netsh interface ipv4 set address name={} source=dhcp'.format(self.NAME), shell=True)
        sub.Popen('netsh interface ipv4 set dns "{}" dhcp'.format(self.NAME), shell=True)

class Hotspot(QWidget):
    def __init__(self):
        super(Hotspot, self).__init__()
        self.setWindowFlags(Qt.Window)
        self.setWindowTitle('Setup the Device Hotspot')
        self.setMaximumWidth(300)
        self.setMaximumHeight(100)
        self.setMinimumHeight(100)
        self.setMinimumWidth(300)
        self.setWindowIcon(QIcon(cwd + r'\network.png'))
        self.setStyleSheet(styleFile)



        self.thrd = StartHot()

        self.body()

    def body(self):


        self.gridLayout = QGridLayout(self)


        self.netName = QLabel('Network Name')
        self.gridLayout.addWidget(self.netName, 1, 0, 1, 1)
        self.netName.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')

        self.netNameT = QLineEdit()
        self.gridLayout.addWidget(self.netNameT, 1, 1, 1, 1)
        self.netNameT.textChanged.connect(self.Apply)

        self.password = QLabel('Password')
        self.gridLayout.addWidget(self.password, 2, 0, 1, 1)
        self.password.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')

        self.passwordT = QLineEdit()
        self.gridLayout.addWidget(self.passwordT, 2, 1, 1, 1)
        self.passwordT.textChanged.connect(self.Apply)
        self.passwordT.setPlaceholderText('Must be more than 8 characters')

        self.ok = QPushButton('OK', self)
        self.gridLayout.addWidget(self.ok, 3, 0, 2, 1)
        self.ok.setEnabled(False)
        self.ok.setStyleSheet('QWidget {font-family:Segoe Script; font-size:12px; font-weight:bold}')
        self.ok.clicked.connect(self.readInfo)

    # enable button only if all fields are filled in
    def nameCheck(self):
        return str(self.netNameT.text())
    def passCheck(self):
        return str(self.passwordT.text())
    def Apply(self):
        if self.nameCheck() != '' and self.passCheck() != '':
            self.ok.setEnabled(True)
        else:
            self.ok.setEnabled(False)

    def readInfo(self):
        self.thrd.NAME = self.netNameT.text()
        self.thrd.PASS = self.passwordT.text()
        self.thrd.start()
        self.close()
        self.shareInfo = Share()
        self.shareInfo.show()

class StartHot(QThread):
    def __init__(self):
        super(StartHot, self).__init__()
    def run(self):
        sub.Popen('netsh wlan set hostednetwork  mode=allow  ssid={}  key = {}'.format(self.NAME, self.PASS), shell=True)
        sub.Popen('netsh wlan start hostednetwork', shell=True)


class Share(QWidget): #sharing internet info
    def __init__(self):
        super(Share, self).__init__()
        self.setWindowFlags(Qt.Popup)
        self.setStyleSheet('QWidget {background-color:gray; color:white; font-size:12px; font-weight:bold; font-family:MV Boli}')
        self.resize(640, 80)

        shr = QLabel(self)
        shr.setText(
            "Now go to Control Panel / Network and Internet / Network and Sharing Center \n"
            "and open change adapter settings and select the network(Ethernet) you want to share and \n"
            "click on it’s properties and select the sharing tab and enable the option to share your \n"
            "internet with Local Hotspot.\n")
        shr.move(10, 5)


class About(QWidget):
    def __init__(self):
        super(About, self).__init__()

        self.setWindowFlags(Qt.Window)
        self.setWindowTitle('About Network Management')
        self.setMaximumWidth(350)
        self.setMaximumHeight(300)
        self.setMinimumHeight(300)
        self.setMinimumWidth(350)
        self.setWindowIcon(QIcon(cwd + r'\network.png'))
        self.setStyleSheet(styleFile)

        titleLbl = QLabel('Network Management ', self)
        titleLbl.move(60, 20)
        titleLbl.setStyleSheet('QWidget {color:#D3DAE3; font-family:Segoe Script; font-size:20px; font-weight:bold}')
        textLbl = QLabel(
                         '1 - Showing your ip address.\n'
                         '2 - Showing full information about all interfaces.\n'
                         '3 - Restart DHCP process.\n'
                         '4 - Disconnect from the local network.\n'
                         '5 - Set device\'s ip statically.\n'
                         '6 - Set device\'s ip dynamically.\n'
                         '7 - Showing all active connections on your device.\n'
                         '8 - Showing the DNS cashe on your device and \n'
                         '     clear it if you want.\n'
                         '9 - The ability to configure a hotspot from your \n'
                         '     device directly without using a third party application.\n \n'
                         '                       === Enjoy trying it. ===', self)

        textLbl.setStyleSheet('QWidget {font-size:13px}')
        textLbl.move(10, 60)

        authorLbl = QLabel('Coded by:\nHussam El Husseiny', self)
        authorLbl.move(10, 270)

        extBtn = QPushButton(' Close ', self)
        extBtn.move(290, 270)
        extBtn.setCursor(QCursor(Qt.PointingHandCursor))
        extBtn.setStyleSheet('QWidget {font-weight:bold; font-size:13px}')
        extBtn.clicked.connect(self.close)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Gui()
    window.show()
    sys.exit(app.exec_())
