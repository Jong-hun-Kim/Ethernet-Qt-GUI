# Created: July 4, 2023.
# Author: Jonghun Kim advised by Sungbhin Oh

import sys
import wmi  # Windows Network Adaptor Setting Library

# PyQt GUI import
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QComboBox,
    QGroupBox
)

from PyQt5.QtCore import QThread, Qt

# scapy import
from scapy.all import *
from scapy.layers.inet import *
from scapy.contrib.automotive.someip import *
from scapy.contrib.automotive.doip import *
from scapy.contrib.automotive.uds import *

# eth_scapy_someip Open Source import
from eth_scapy_someip import eth_scapy_someip as someip

LINE_CONTROL_SIZE = 120


class FrameInfo():
    def __init__(self):
        self.mac = None
        self.netinfo = None
        self.ip = None
        self.trp = None

        self.someip = None
        self.serID = None
        self.methodID = None
        self.dtype = None
        self.srcAddr = None
        self.tarAddr = None

        self.doip = None


class ThreadInfo(QThread):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.ethFrame = FrameInfo()

    def split_data(self, packet):
        self.ethFrame.mac = packet.getlayer(Ether)

        if self.ethFrame.mac.src != self.parent.srcMAC.text():
            self.ethFrame.ip = packet.getlayer(IP)
            self.ethFrame.trp = packet.getlayer(UDP)
            self.ethFrame.someip = SOMEIP(packet.getlayer(Raw).load)
            payload = int.from_bytes(self.ethFrame.someip.payload.getlayer(Raw).load, byteorder='big')

            self.parent.recSrcMAC.setText(self.ethFrame.mac.src)
            self.parent.recDstMAC.setText(self.ethFrame.mac.dst)

            self.parent.recSrcIP.setText(self.ethFrame.ip.src)
            self.parent.recDstIP.setText(self.ethFrame.ip.dst)

            self.parent.recSrcPN.setText(str(self.ethFrame.trp.sport))
            self.parent.recDstPN.setText(str(self.ethFrame.trp.dport))

    def run(self):
        filter_rule = "udp and port " + self.parent.srcPORT.text() + " and udp[22] == 0x00"
        while True:
            sniff(iface=self.parent.setFrame.netinfo, count=1, filter=filter_rule, prn=self.split_data)


class Application(QWidget):
    def __init__(self):
        super().__init__()
        self.setFrame = FrameInfo()
        self.setWindowTitle('[SKKU Automation Lab] Ethernet Service GUI')
        self.setWindowFlags(Qt.WindowMinimizeButtonHint | Qt.WindowCloseButtonHint)
        self.mainframe = QVBoxLayout()  # Allocate new controls to vertical area (추가한 Control들이 세로로 나열됨)

        ###################################################
        # Groupbox (Ethernet Connection Setting [MAC/IP]) #
        ###################################################
        self.groupboxEC = QGroupBox('Ethernet Connection')  # First Group Box

        self.mainVboxEC = QVBoxLayout()

        # Ethernet Connection Status
        self.stateHboxEC = QHBoxLayout()

        self.sLabel = QLabel('Connection State')
        self.sLabel.setFixedWidth(160)

        self.stateE = QLineEdit()
        self.stateE.setText('Disconnected')
        self.stateE.setFixedWidth(100)
        self.stateE.setAlignment(Qt.AlignCenter)
        self.stateE.setStyleSheet('font-weight: bold; '
                                  'color: black; '
                                  'background-color: rgb(192, 192, 192)')
        self.stateE.setReadOnly(True)

        self.stateHboxEC.addWidget(self.sLabel)
        self.stateHboxEC.addWidget(self.stateE, 0, Qt.AlignLeft)

        # Network Interface Label & Select ComboBox
        self.netinfoHbox = QHBoxLayout()

        self.niLabel = QLabel('Ethernet Network Interface')
        self.niLabel.setFixedWidth(160)
        self.niBox = QComboBox(self)
        self.niBox.addItem('Select Network Interface')

        self.netinfoHbox.addWidget(self.niLabel)
        self.netinfoHbox.addWidget(self.niBox)

        # Source MAC and Destination MAC Label & LineEdit Control
        self.srcMACLabel = QLabel('Source MAC', self)
        self.srcMACLabel.setFixedWidth(100)
        self.srcMAC = QLineEdit(self)
        self.srcMAC.setFixedWidth(LINE_CONTROL_SIZE)
        self.srcMAC.setAlignment(Qt.AlignCenter)
        self.srcMAC.setText("00:e0:4c:68:08:6f")

        self.dstMACLabel = QLabel('Destination MAC', self)
        self.dstMACLabel.setFixedWidth(100)
        self.dstMAC = QLineEdit(self)
        self.dstMAC.setFixedWidth(LINE_CONTROL_SIZE)
        self.dstMAC.setAlignment(Qt.AlignCenter)
        self.dstMAC.setText("00:11:22:33:44:55")

        # Source IP Label & LineEdit
        self.srcIPLabel = QLabel('Source IP', self)
        self.srcIPLabel.setFixedWidth(100)
        self.srcIP = QLineEdit(self)
        self.srcIP.setFixedWidth(LINE_CONTROL_SIZE)
        self.srcIP.setAlignment(Qt.AlignCenter)
        self.srcIP.setText("192.168.1.0")

        # Destination IP Label & LineEdit
        self.dstIPLabel = QLabel('Destination IP', self)
        self.dstIPLabel.setFixedWidth(100)
        self.dstIP = QLineEdit(self)
        self.dstIP.setFixedWidth(LINE_CONTROL_SIZE)
        self.dstIP.setAlignment(Qt.AlignCenter)
        self.dstIP.setText("192.168.2.0")

        self.macVbox = QVBoxLayout()
        self.ipVbox = QVBoxLayout()

        self.srcMACHbox = QHBoxLayout()
        self.dstMACHbox = QHBoxLayout()
        self.srcIPHbox = QHBoxLayout()
        self.dstIPHbox = QHBoxLayout()

        self.srcMACHbox.addWidget(self.srcMACLabel)
        self.srcMACHbox.addWidget(self.srcMAC, 0, Qt.AlignLeft)
        self.dstMACHbox.addWidget(self.dstMACLabel)
        self.dstMACHbox.addWidget(self.dstMAC, 0, Qt.AlignLeft)

        self.srcIPHbox.addWidget(self.srcIPLabel)
        self.srcIPHbox.addWidget(self.srcIP, 0, Qt.AlignLeft)
        self.dstIPHbox.addWidget(self.dstIPLabel)
        self.dstIPHbox.addWidget(self.dstIP, 0, Qt.AlignLeft)

        self.macVbox.addLayout(self.srcMACHbox)
        self.macVbox.addLayout(self.dstMACHbox)
        self.ipVbox.addLayout(self.srcIPHbox)
        self.ipVbox.addLayout(self.dstIPHbox)

        self.addrHbox = QHBoxLayout()
        self.addrHbox.addLayout(self.macVbox)
        self.addrHbox.addLayout(self.ipVbox)

        # Address Setting Button
        self.setBtnEC = QPushButton('Setting', self)
        self.setBtnEC.setCheckable(True)

        self.mainVboxEC.addLayout(self.stateHboxEC)
        self.mainVboxEC.addLayout(self.netinfoHbox)
        self.mainVboxEC.addLayout(self.addrHbox)
        self.mainVboxEC.addWidget(self.setBtnEC)
        self.groupboxEC.setLayout(self.mainVboxEC)

        ##############################
        # Groupbox (TCP/UDP Setting) #
        ##############################
        self.groupboxIP = QGroupBox('Transfort Layer Setting')

        self.mainVboxT = QVBoxLayout()

        self.selectHboxT = QHBoxLayout()
        self.stateHboxT = QHBoxLayout()
        self.portHbox = QHBoxLayout()

        self.protocol = None
        self.selectLabel = QLabel('Protocol Type')
        self.selectLabel.setFixedWidth(100)
        self.selectTCP = QPushButton('TCP')
        self.selectTCP.setCheckable(True)
        self.selectTCP.setFixedWidth(57)
        self.selectUDP = QPushButton('UDP')
        self.selectUDP.setCheckable(True)
        self.selectUDP.setFixedWidth(57)

        self.sLabelT = QLabel('Protocol State')
        self.sLabelT.setFixedWidth(100)
        self.stateT = QLineEdit()
        self.stateT.setText('None')
        self.stateT.setFixedWidth(LINE_CONTROL_SIZE)
        self.stateT.setAlignment(Qt.AlignCenter)
        self.stateT.setStyleSheet('font-weight: bold; '
                                  'color: black; '
                                  'background-color: rgb(192, 192, 192)')
        self.stateT.setReadOnly(True)

        self.srcPORTLabel = QLabel('Source Port', self)
        self.srcPORTLabel.setFixedWidth(100)
        self.srcPORT = QLineEdit(self)
        self.srcPORT.setFixedWidth(LINE_CONTROL_SIZE)
        self.srcPORT.setAlignment(Qt.AlignCenter)
        self.srcPORT.setText('30509')
        self.dstPORTLabel = QLabel('Destination Port', self)
        self.dstPORTLabel.setFixedWidth(100)
        self.dstPORT = QLineEdit(self)
        self.dstPORT.setFixedWidth(LINE_CONTROL_SIZE)
        self.dstPORT.setAlignment(Qt.AlignCenter)
        self.dstPORT.setText('30509')
        self.setBtnTR = QPushButton('Setting', self)
        self.setBtnTR.setCheckable(True)

        self.setHboxT = QHBoxLayout()

        self.selectHboxT.addWidget(self.selectLabel)
        self.selectHboxT.addWidget(self.selectTCP)
        self.selectHboxT.addWidget(self.selectUDP)
        self.selectHboxT.setAlignment(Qt.AlignLeft)

        self.stateHboxT.addWidget(self.sLabelT)
        self.stateHboxT.addWidget(self.stateT)
        self.stateHboxT.setAlignment(Qt.AlignLeft)

        self.setHboxT.addLayout(self.selectHboxT)
        self.setHboxT.addLayout(self.stateHboxT)

        self.portHbox.addWidget(self.srcPORTLabel)
        self.portHbox.addWidget(self.srcPORT)
        self.portHbox.addWidget(self.dstPORTLabel)
        self.portHbox.addWidget(self.dstPORT)

        self.mainVboxT.addLayout(self.setHboxT)
        self.mainVboxT.addLayout(self.portHbox)
        self.mainVboxT.addWidget(self.setBtnTR)

        self.groupboxIP.setLayout(self.mainVboxT)

        ####################################
        # Groupbox (Session Layer Setting) #
        ####################################
        self.groupboxSS = QGroupBox('Session Layer Setting')

        self.mainVboxSS = QVBoxLayout()

        self.selectHboxSS = QHBoxLayout()
        self.stateHboxSS = QHBoxLayout()
        self.someipHbox = QHBoxLayout()
        self.doipHbox = QHBoxLayout()
        self.subdoipHbox = QHBoxLayout()

        self.service = None
        self.selectLabelS = QLabel('Protocol Type')
        self.selectLabelS.setFixedWidth(100)
        self.selectSIP = QPushButton('SOME/IP')
        self.selectSIP.setCheckable(True)
        self.selectSIP.setFixedWidth(68)
        self.selectDIP = QPushButton('DoIP')
        self.selectDIP.setCheckable(True)
        self.selectDIP.setFixedWidth(47)

        self.sLabelSS = QLabel('Protocol State')
        self.sLabelSS.setFixedWidth(100)
        self.stateSS = QLineEdit()
        self.stateSS.setText('None')
        self.stateSS.setFixedWidth(LINE_CONTROL_SIZE)
        self.stateSS.setAlignment(Qt.AlignCenter)
        self.stateSS.setStyleSheet('font-weight: bold; '
                                   'color: black; '
                                   'background-color: rgb(192, 192, 192)')
        self.stateT.setReadOnly(True)

        self.setHboxSS = QHBoxLayout()

        self.selectHboxSS.addWidget(self.selectLabelS)
        self.selectHboxSS.addWidget(self.selectSIP)
        self.selectHboxSS.addWidget(self.selectDIP)
        self.selectHboxSS.setAlignment(Qt.AlignLeft)

        self.stateHboxSS.addWidget(self.sLabelSS)
        self.stateHboxSS.addWidget(self.stateSS)
        self.stateHboxSS.setAlignment(Qt.AlignLeft)

        self.setHboxSS.addLayout(self.selectHboxSS)
        self.setHboxSS.addLayout(self.stateHboxSS)

        self.serIDLabel = QLabel('Service ID', self)
        self.serIDLabel.setFixedWidth(100)
        self.serID = QLineEdit(self)
        self.serID.setFixedWidth(LINE_CONTROL_SIZE)
        self.serID.setAlignment(Qt.AlignCenter)
        self.serID.setText('4660')
        self.serID.setDisabled(True)
        self.methodIDLabel = QLabel('Method ID', self)
        self.methodIDLabel.setFixedWidth(100)
        self.methodID = QLineEdit(self)
        self.methodID.setFixedWidth(LINE_CONTROL_SIZE)
        self.methodID.setAlignment(Qt.AlignCenter)
        self.methodID.setText('1')
        self.methodID.setDisabled(True)

        self.someipHbox.addWidget(self.serIDLabel)
        self.someipHbox.addWidget(self.serID)
        self.someipHbox.addWidget(self.methodIDLabel)
        self.someipHbox.addWidget(self.methodID)

        self.dtypeLabel = QLabel('Payload Type', self)
        self.dtypeLabel.setFixedWidth(100)
        self.dtype = QLineEdit(self)
        self.dtype.setFixedWidth(LINE_CONTROL_SIZE)
        self.dtype.setAlignment(Qt.AlignCenter)
        self.dtype.setText('32769')
        self.dtype.setDisabled(True)

        self.srcAddrLabel = QLabel('Source Address', self)
        self.srcAddrLabel.setFixedWidth(100)
        self.srcAddr = QLineEdit(self)
        self.srcAddr.setFixedWidth(LINE_CONTROL_SIZE)
        self.srcAddr.setAlignment(Qt.AlignCenter)
        self.srcAddr.setText('1')
        self.srcAddr.setDisabled(True)

        self.tarAddrLabel = QLabel('Target Address', self)
        self.tarAddrLabel.setFixedWidth(100)
        self.tarAddr = QLineEdit(self)
        self.tarAddr.setFixedWidth(LINE_CONTROL_SIZE)
        self.tarAddr.setAlignment(Qt.AlignCenter)
        self.tarAddr.setText('0')
        self.tarAddr.setDisabled(True)

        self.setBtnSS = QPushButton('Setting', self)
        self.setBtnSS.setCheckable(True)

        self.doipHbox.addWidget(self.dtypeLabel)
        self.doipHbox.addWidget(self.dtype)
        self.doipHbox.addWidget(self.srcAddrLabel)
        self.doipHbox.addWidget(self.srcAddr)

        self.subdoipHbox.addWidget(self.tarAddrLabel)
        self.subdoipHbox.addWidget(self.tarAddr)
        self.subdoipHbox.setAlignment(Qt.AlignRight)

        self.mainVboxSS.addLayout(self.setHboxSS)
        self.mainVboxSS.addLayout(self.someipHbox)
        self.mainVboxSS.addLayout(self.doipHbox)
        self.mainVboxSS.addLayout(self.subdoipHbox)
        self.mainVboxSS.addWidget(self.setBtnSS)

        self.groupboxSS.setLayout(self.mainVboxSS)

        # Message Send Groupbox
        self.groupboxMsg = QGroupBox('Message Transmit')
        self.sendMsgVbox = QVBoxLayout()
        self.inputHbox = QHBoxLayout()
        self.sendBtnHbox = QHBoxLayout()
        self.inputLabel = QLabel('Message', self)
        self.inputBox = QLineEdit(self)
        self.setBtnSend = QPushButton('Send', self)
        self.setBtnSend.setCheckable(True)

        self.inputHbox.addWidget(self.inputLabel)
        self.inputHbox.addWidget(self.inputBox)
        self.sendBtnHbox.addWidget(self.setBtnSend)
        self.sendMsgVbox.addLayout(self.inputHbox)
        self.sendMsgVbox.addLayout(self.sendBtnHbox)
        self.groupboxMsg.setLayout(self.sendMsgVbox)

        self.groupboxRX = QGroupBox('Message Receive (Read Only)')
        self.recMsgVbox = QVBoxLayout()
        self.recAddrHbox = QHBoxLayout()
        self.recIPHbox = QHBoxLayout()
        self.recTRHbox = QHBoxLayout()
        self.recSerHbox = QHBoxLayout()

        self.recSrcMACLabel = QLabel('Source MAC')
        self.recSrcMACLabel.setFixedWidth(100)
        self.recSrcMAC = QLineEdit(self)
        self.recSrcMAC.setFixedWidth(LINE_CONTROL_SIZE)
        self.recSrcMAC.setAlignment(Qt.AlignCenter)
        self.recSrcMAC.setReadOnly(True)

        self.recDstMACLabel = QLabel('Destination MAC')
        self.recDstMACLabel.setFixedWidth(100)
        self.recDstMAC = QLineEdit(self)
        self.recDstMAC.setFixedWidth(LINE_CONTROL_SIZE)
        self.recDstMAC.setAlignment(Qt.AlignCenter)
        self.recDstMAC.setReadOnly(True)

        self.recSrcIPLabel = QLabel('Source IP')
        self.recSrcIPLabel.setFixedWidth(100)
        self.recSrcIP = QLineEdit(self)
        self.recSrcIP.setFixedWidth(LINE_CONTROL_SIZE)
        self.recSrcIP.setAlignment(Qt.AlignCenter)
        self.recSrcIP.setReadOnly(True)

        self.recDstIPLabel = QLabel('Destination IP')
        self.recDstIPLabel.setFixedWidth(100)
        self.recDstIP = QLineEdit(self)
        self.recDstIP.setFixedWidth(LINE_CONTROL_SIZE)
        self.recDstIP.setAlignment(Qt.AlignCenter)
        self.recDstIP.setReadOnly(True)

        self.recSrcPNLabel = QLabel('Source Port')
        self.recSrcPNLabel.setFixedWidth(100)
        self.recSrcPN = QLineEdit(self)
        self.recSrcPN.setFixedWidth(LINE_CONTROL_SIZE)
        self.recSrcPN.setAlignment(Qt.AlignCenter)
        self.recSrcPN.setReadOnly(True)

        self.recDstPNLabel = QLabel('Destination Port')
        self.recDstPNLabel.setFixedWidth(100)
        self.recDstPN = QLineEdit(self)
        self.recDstPN.setFixedWidth(LINE_CONTROL_SIZE)
        self.recDstPN.setAlignment(Qt.AlignCenter)
        self.recDstPN.setReadOnly(True)

        self.recMACVbox = QVBoxLayout()
        self.recIPVbox = QVBoxLayout()

        self.srcMACHbox = QHBoxLayout()
        self.dstMACHbox = QHBoxLayout()
        self.srcIPHbox = QHBoxLayout()
        self.dstIPHbox = QHBoxLayout()
        self.srcPNHbox = QHBoxLayout()
        self.dstPNHbox = QHBoxLayout()

        self.srcMACHbox.addWidget(self.recSrcMACLabel)
        self.srcMACHbox.addWidget(self.recSrcMAC)
        self.dstMACHbox.addWidget(self.recDstMACLabel)
        self.dstMACHbox.addWidget(self.recDstMAC)

        self.recMACVbox.addLayout(self.srcMACHbox)
        self.recMACVbox.addLayout(self.dstMACHbox)

        self.srcIPHbox.addWidget(self.recSrcIPLabel)
        self.srcIPHbox.addWidget(self.recSrcIP)
        self.dstIPHbox.addWidget(self.recDstIPLabel)
        self.dstIPHbox.addWidget(self.recDstIP)

        self.recIPVbox.addLayout(self.srcIPHbox)
        self.recIPVbox.addLayout(self.dstIPHbox)

        self.recAddrHbox.addLayout(self.recMACVbox)
        self.recAddrHbox.addLayout(self.recIPVbox)

        self.srcPNHbox.addWidget(self.recSrcPNLabel)
        self.srcPNHbox.addWidget(self.recSrcPN)
        self.dstPNHbox.addWidget(self.recDstPNLabel)
        self.dstPNHbox.addWidget(self.recDstPN)

        self.recTRHbox.addLayout(self.srcPNHbox)
        self.recTRHbox.addLayout(self.dstPNHbox)

        self.recMsgVbox.addLayout(self.recAddrHbox)
        self.recMsgVbox.addLayout(self.recIPHbox)
        self.recMsgVbox.addLayout(self.recTRHbox)
        self.recMsgVbox.addLayout(self.recSerHbox)

        self.groupboxRX.setLayout(self.recMsgVbox)

        # GUI Layout set
        self.mainframe.addWidget(self.groupboxEC)
        self.mainframe.addWidget(self.groupboxIP)
        self.mainframe.addWidget(self.groupboxSS)
        self.mainframe.addWidget(self.groupboxMsg)
        self.mainframe.addWidget(self.groupboxRX)
        self.setLayout(self.mainframe)

        self.initialize()

    def initialize(self):
        # show
        self.allocFunc()
        self.printNetInfo()
        self.show()

    def allocFunc(self):
        self.setBtnEC.clicked.connect(self.setEthernet)
        self.selectTCP.clicked.connect(self.setProtocolTCP)
        self.selectUDP.clicked.connect(self.setProtocolUDP)
        self.setBtnTR.clicked.connect(self.setTransport)
        self.selectSIP.clicked.connect(self.setProtocolSOMEIP)
        self.selectDIP.clicked.connect(self.setProtocolDoIP)
        self.setBtnSS.clicked.connect(self.setSession)
        self.setBtnSend.clicked.connect(self.setMessage)

    def printNetInfo(self):
        c = wmi.WMI()
        qry = "select Name from Win32_NetworkAdapter where NetEnabled=True and NetConnectionStatus=2"
        lst = [o.Name for o in c.query(qry)]
        for key in lst:
            self.niBox.addItem(key)

    def setEthernet(self):
        self.setFrame.mac = Ether(src=self.srcMAC.text(), dst=self.dstMAC.text())
        self.setFrame.netinfo = self.niBox.currentText()
        self.setFrame.ip = IP(src=self.srcIP.text(), dst=self.dstIP.text())

        self.stateE.setText('Connected')
        self.stateE.setStyleSheet('font-weight: bold; '
                                  'color: red; '
                                  'background-color: rgb(255, 255, 255)')
        self.setBtnEC.toggle()

    def setProtocolTCP(self):
        self.protocol = "TCP"
        self.stateT.setText(self.protocol)
        self.selectTCP.toggle()

    def setProtocolUDP(self):
        self.protocol = "UDP"
        self.stateT.setText(self.protocol)
        self.selectUDP.toggle()

    def setTransport(self):
        sport = int(self.srcPORT.text())
        dport = int(self.dstPORT.text())

        if self.protocol == "TCP":
            self.setFrame.trp = TCP(sport=sport, dport=dport)
        elif self.protocol == "UDP":
            self.setFrame.trp = UDP(sport=sport, dport=dport)

        self.serviceEnable()
        self.setBtnTR.toggle()

    def setProtocolSOMEIP(self):
        self.service = "SOME/IP"
        self.serID.setDisabled(False)
        self.methodID.setDisabled(False)
        self.dtype.setDisabled(True)
        self.srcAddr.setDisabled(True)
        self.tarAddr.setDisabled(True)
        self.stateSS.setText(self.service)
        self.selectSIP.toggle()

    def setProtocolDoIP(self):
        self.service = "DoIP"
        self.serID.setDisabled(True)
        self.methodID.setDisabled(True)
        self.dtype.setDisabled(False)
        self.srcAddr.setDisabled(False)
        self.tarAddr.setDisabled(False)
        self.stateSS.setText(self.service)
        self.selectDIP.toggle()

    def setSession(self):
        if self.service == "SOME/IP":
            self.setFrame.serID = int(self.serID.text())
            self.setFrame.methodID = int(self.methodID.text())
        elif self.service == "DoIP":
            self.setFrame.dtype = int(self.dtype.text())
            self.setFrame.srcAddr = int(self.srcAddr.text())
            self.setFrame.tarAddr = int(self.tarAddr.text())
        self.setBtnSS.toggle()

    def setMessage(self):
        if self.service == "SOME/IP":
            self.setFrame.someip = someip.SOMEIP()
            self.setFrame.someip.msg_id.srv_id = self.setFrame.serID
            self.setFrame.someip.msg_id.sub_id = 0x0000
            self.setFrame.someip.msg_id.method_id = self.setFrame.methodID

            self.setFrame.someip.req_id.client_id = 0x0000
            self.setFrame.someip.req_id.session_id = 0x0000

            self.setFrame.someip.msg_type = 0x00
            self.setFrame.someip.retcode = 0x00
            self.setFrame.someip.payload = Raw(load=bytes([int(self.inputBox.text())]))

            pkt = self.setFrame.mac / self.setFrame.ip / self.setFrame.trp / self.setFrame.someip
        elif self.service == "DoIP":
            self.setFrame.doip = DoIP(payload_type=self.setFrame.dtype,
                                      source_address=self.setFrame.srcAddr,
                                      target_address=self.setFrame.tarAddr)
            pkt = self.setFrame.mac / self.setFrame.ip / self.setFrame.trp / self.setFrame.doip
        else:
            pkt = None

        sendp(pkt, iface=self.setFrame.netinfo)
        self.setBtnSend.toggle()

    def serviceEnable(self):
        self.Thread = ThreadInfo(self)
        self.Thread.start()


# Main Function
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Application()
    sys.exit(app.exec_())
