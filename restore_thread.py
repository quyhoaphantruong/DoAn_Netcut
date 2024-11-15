from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import ARP, send, Ether

class RestoreThread(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, target_ip, target_mac, gateway_ip, gateway_mac):
        super().__init__()
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac

    def run(self):
        self.log_signal.emit(f"Restoring ARP tables for {self.target_ip} and gateway {self.gateway_ip}.")
        ether_target = Ether(dst=self.target_mac) 
        packet_target = ARP(op=2, psrc=self.gateway_ip, hwsrc=self.gateway_mac, pdst=self.target_ip, hwdst=self.target_mac)
      
        packet_gateway = ARP(op=2, psrc=self.target_ip, hwsrc=self.target_mac, pdst=self.gateway_ip, hwdst=self.gateway_mac)
        ether_gateway = Ether(dst=self.gateway_mac)

        try:
            send(ether_target / packet_target, count=3, verbose=False)
            send(ether_gateway / packet_gateway, count=3, verbose=False)
            self.log_signal.emit(f"Restored ARP tables for {self.target_ip} and gateway {self.gateway_ip}.")
        except Exception as e:
            self.log_signal.emit(f"Error during restoration: {e}")