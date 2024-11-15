from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import ARP, Ether, srp
import ipaddress

def is_valid_ip_range(ip_range):
    try:
        if '/' in ip_range:
            ipaddress.IPv4Network(ip_range)
        else:
            ipaddress.IPv4Address(ip_range)
        return True
    except ValueError:
        return False

class NetworkScanner(QThread):
    scan_result = pyqtSignal(list)
    log_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, ip_range):
        super().__init__()
        self.ip_range = ip_range

    def run(self):
        devices = []
        self.log_signal.emit(f"Scanning the network ({self.ip_range})...")
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip_range),
                timeout=2,
                verbose=False
            )
            self.log_signal.emit(f"Found {len(ans)} device(s).")
            for sent, received in ans:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            self.scan_result.emit(devices)
        except PermissionError:
            error_message = "Permission denied: Run the application as administrator/root."
            self.log_signal.emit(error_message)
            self.error_signal.emit(error_message)
        except Exception as e:
            import traceback
            error_message = f"Error during scanning: {e}\n{traceback.format_exc()}"
            self.log_signal.emit(error_message)
            self.error_signal.emit("An unexpected error occurred during scanning.")
        finally:
            if not devices:
                self.scan_result.emit(devices)
