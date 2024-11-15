import sys
import threading
import time
import sys
from scapy.all import ARP, Ether, srp, conf
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton, QVBoxLayout,
    QHBoxLayout, QLineEdit, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QMessageBox, QCheckBox, QTextEdit
)
from PyQt5.QtCore import Qt
from network_scanner import NetworkScanner
from spoof_thread import SpoofThread
from restore_thread import RestoreThread

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Netcut-21127574")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #2E3440; color: #fff;")

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()

        # IP Range Input
        self.ip_layout = QHBoxLayout()
        self.ip_label = QLabel("IP Range:")
        self.ip_label.setStyleSheet("font-weight: bold;")
        self.ip_input = QLineEdit("192.168.0.1/24")
        self.ip_input.setStyleSheet("padding: 5px;")
        self.scan_button = QPushButton("Scan")
        self.scan_button.setStyleSheet("background-color: #81A1C1; color: #2E3440; padding: 5px;")
        self.scan_button.clicked.connect(self.scan_network)

        self.ip_layout.addWidget(self.ip_label)
        self.ip_layout.addWidget(self.ip_input)
        self.ip_layout.addWidget(self.scan_button)

        self.layout.addLayout(self.ip_layout)

        # Device Table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Select", "IP Address", "MAC Address"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setStyleSheet("background-color: #3B4252;")
        self.layout.addWidget(self.table)

        # Gateway Information
        self.gateway_layout = QHBoxLayout()
        self.gateway_label = QLabel("Gateway IP:")
        self.gateway_label.setStyleSheet("font-weight: bold;")
        self.gateway_ip = QLineEdit("192.168.0.1")
        self.gateway_ip.setStyleSheet("padding: 5px;")
        self.gateway_ip.setReadOnly(True)
        self.gateway_mac_label = QLabel("Gateway MAC:")
        self.gateway_mac_label.setStyleSheet("font-weight: bold;")
        self.gateway_mac = QLineEdit()
        self.gateway_mac.setStyleSheet("padding: 5px;")
        self.gateway_mac.setReadOnly(True)

        self.gateway_layout.addWidget(self.gateway_label)
        self.gateway_layout.addWidget(self.gateway_ip)
        self.gateway_layout.addWidget(self.gateway_mac_label)
        self.gateway_layout.addWidget(self.gateway_mac)

        self.layout.addLayout(self.gateway_layout)

        # Spoof and Stop Buttons
        self.button_layout = QHBoxLayout()
        self.spoof_button = QPushButton("Start Spoofing")
        self.spoof_button.setStyleSheet("background-color: #A3BE8C; color: #2E3440; padding: 10px;")
        self.spoof_button.clicked.connect(self.start_spoofing)
        self.stop_button = QPushButton("Stop Spoofing")
        self.stop_button.setStyleSheet("background-color: #BF616A; color: #2E3440; padding: 10px;")
        self.stop_button.clicked.connect(self.stop_spoofing)
        self.stop_button.setEnabled(False)

        self.button_layout.addWidget(self.spoof_button)
        self.button_layout.addWidget(self.stop_button)

        self.layout.addLayout(self.button_layout)

        # Log Window
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet("background-color: #3B4252; color: #D8DEE9;")
        self.layout.addWidget(self.log)

        self.central_widget.setLayout(self.layout)

        self.spoof_threads = []
        self.stop_event = threading.Event()

    def scan_network(self):
        gateway_ip = self.get_default_gateway()
        if gateway_ip:
            self.gateway_ip.setText(gateway_ip)
        ip_range = self.ip_input.text().strip()
        if not ip_range:
            QMessageBox.warning(self, "Input Error", "Please enter a valid IP range.")
            return
        self.table.setRowCount(0)
        self.log.append(f"<b>Scanning network: {ip_range}</b>")
        self.scanner = NetworkScanner(ip_range)
        self.scanner.scan_result.connect(self.display_devices)
        self.scanner.log_signal.connect(self.update_log)
        self.scanner.start()

    def display_devices(self, devices):
        self.table.setRowCount(len(devices))
        for row, device in enumerate(devices):
            # Checkbox
            checkbox = QCheckBox()
            checkbox_widget = QWidget()
            checkbox_layout = QHBoxLayout(checkbox_widget)
            checkbox_layout.addWidget(checkbox)
            checkbox_layout.setAlignment(Qt.AlignCenter)
            checkbox_layout.setContentsMargins(0,0,0,0)
            self.table.setCellWidget(row, 0, checkbox_widget)

            # IP Address
            ip_item = QTableWidgetItem(device['ip'])
            ip_item.setForeground(Qt.white)
            self.table.setItem(row, 1, ip_item)

            # MAC Address
            mac_item = QTableWidgetItem(device['mac'])
            mac_item.setForeground(Qt.white)
            self.table.setItem(row, 2, mac_item)
        self.log.append("<b>Scan complete.</b>")

        # Get gateway MAC
        gateway_ip = self.gateway_ip.text().strip()
        if gateway_ip:
            self.log.append(f"<b>Retrieving MAC address for gateway: {gateway_ip}</b>")
            gateway_mac = self.get_mac_address(gateway_ip, devices)
            if gateway_mac:
                self.gateway_mac.setText(gateway_mac)
                self.log.append(f"<b>Gateway MAC: {gateway_mac}</b>")
            else:
                self.gateway_mac.setText("Not Found")
                self.log.append("<b>Could not find MAC address for the gateway.</b>")

    def get_mac_address(self, ip, devices):
        for device in devices:
            if device['ip'] == ip:
                return device['mac']
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
            for sent, received in ans:
                return received.hwsrc
        except Exception as e:
            self.log.append(f"Error retrieving gateway MAC: {e}")
            return None
        return None
    
    def get_default_gateway(self):
        default_route = conf.route.route("0.0.0.0")
        gateway_ip = default_route[2]  
        return gateway_ip

    def start_spoofing(self):
        selected_devices = []
        for row in range(self.table.rowCount()):
            widget = self.table.cellWidget(row, 0)
            checkbox = widget.layout().itemAt(0).widget()
            if checkbox.isChecked():
                ip = self.table.item(row, 1).text()
                mac = self.table.item(row, 2).text()
                selected_devices.append({'ip': ip, 'mac': mac})

        if not selected_devices:
            QMessageBox.warning(self, "Selection Error", "Please select at least one device to spoof.")
            return

        gateway_ip = self.gateway_ip.text().strip()
        gateway_mac = self.gateway_mac.text().strip()
        if not gateway_ip or not gateway_mac:
            QMessageBox.warning(self, "Gateway Error", "Please ensure the gateway IP and MAC are correctly set.")
            return

        # Check spoofing the gateway
        selected_devices = [d for d in selected_devices if d['ip'] != gateway_ip]
        if not selected_devices:
            QMessageBox.warning(self, "Selection Error", "Cannot spoof the gateway device.")
            return

        self.log.append(f"<b>Starting ARP spoofing on {len(selected_devices)} device(s).</b>")
        self.spoof_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        for device in selected_devices:
            print(f"ip target {device['ip']} mac target {device['mac']} gateway_ip {gateway_ip} gateway mac {gateway_mac}")
            spoof_thread = SpoofThread(device['ip'], device['mac'], gateway_ip, gateway_mac, self.stop_event)
            spoof_thread.log_signal.connect(self.update_log)
            spoof_thread.start()
            self.spoof_threads.append(spoof_thread)

    def stop_spoofing(self):
        self.log.append("<b>Stopping ARP spoofing...</b>")
        self.stop_event.set()

        for thread in self.spoof_threads:
            thread.wait()

        self.spoof_threads = []
        self.stop_event.clear()
        self.log.append("<b>ARP spoofing stopped.</b>")
        self.spoof_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        self.log.append("<b>Restoring ARP tables...</b>")
        for row in range(self.table.rowCount()):
            widget = self.table.cellWidget(row, 0)
            checkbox = widget.layout().itemAt(0).widget()
            if checkbox.isChecked():
                ip = self.table.item(row, 1).text()
                mac = self.table.item(row, 2).text()
                self.restore_arp(ip, mac)
        self.log.append("<b>ARP tables restored.</b>")

    def restore_arp(self, target_ip, target_mac):
        gateway_ip = self.gateway_ip.text().strip()
        gateway_mac = self.gateway_mac.text().strip()
        if not gateway_ip or not gateway_mac:
            self.log.append(f"Cannot restore ARP for {target_ip}: Gateway information incomplete.")
            return
        restore_thread = RestoreThread(target_ip, target_mac, gateway_ip, gateway_mac)
        restore_thread.log_signal.connect(self.update_log)
        restore_thread.start()
        restore_thread.wait()

    def update_log(self, message):
        self.log.append(message)

    def closeEvent(self, event):
        if self.spoof_threads:
            reply = QMessageBox.question(self, 'Quit', 'ARP spoofing is active. Do you want to stop spoofing and exit?',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.stop_spoofing()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
