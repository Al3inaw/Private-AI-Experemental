import scapy.all as scapy
from scapy.layers import http
import nmap
import netifaces
import psutil
import threading
import time

class NetworkAnalyzer:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.packet_count = 0
        self.network_stats = {}
        self.stop_sniffing = threading.Event()

    def get_local_ip(self):
        return netifaces.ifaddresses(netifaces.gateways()['default'][netifaces.AF_INET][1])[netifaces.AF_INET][0]['addr']

    def scan_network(self):
        local_ip = self.get_local_ip()
        network = local_ip.rsplit('.', 1)[0] + '.0/24'
        self.nm.scan(hosts=network, arguments='-sn')
        return [(x, self.nm[x]['status']['state']) for x in self.nm.all_hosts()]

    def packet_callback(self, packet):
        self.packet_count += 1
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            print(f"HTTP Request >> {url}")

    def start_packet_sniffing(self):
        self.stop_sniffing.clear()
        scapy.sniff(prn=self.packet_callback, store=False, stop_filter=lambda x: self.stop_sniffing.is_set())

    def stop_packet_sniffing(self):
        self.stop_sniffing.set()

    def get_network_stats(self):
        net_io = psutil.net_io_counters()
        self.network_stats = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }
        return self.network_stats

    def monitor_network(self, duration=60):
        start_time = time.time()
        while time.time() - start_time < duration:
            self.get_network_stats()
            time.sleep(1)

    def detect_port_scan(self):
        def callback(packet):
            if packet.haslayer(scapy.TCP) and packet.getlayer(scapy.TCP).flags == 2:
                print(f"Possible port scan detected from {packet[scapy.IP].src}")

        scapy.sniff(filter="tcp", prn=callback, store=0, timeout=60)

class ExpandedAIWithNetworkAnalysis(ExpandedAI):
    def __init__(self):
        super().__init__()
        self.network_analyzer = NetworkAnalyzer()

    def process_query(self, query):
        if "scan network" in query.lower():
            return self.network_analyzer.scan_network()
        elif "start packet sniffing" in query.lower():
            threading.Thread(target=self.network_analyzer.start_packet_sniffing).start()
            return "Packet sniffing started"
        elif "stop packet sniffing" in query.lower():
            self.network_analyzer.stop_packet_sniffing()
            return f"Packet sniffing stopped. Total packets captured: {self.network_analyzer.packet_count}"
        elif "get network stats" in query.lower():
            return self.network_analyzer.get_network_stats()
        elif "monitor network" in query.lower():
            threading.Thread(target=self.network_analyzer.monitor_network).start()
            return "Network monitoring started for 60 seconds"
        elif "detect port scan" in query.lower():
            threading.Thread(target=self.network_analyzer.detect_port_scan).start()
            return "Port scan detection started for 60 seconds"
        else:
            return super().process_query(query)

ai_assistant = ExpandedAIWithNetworkAnalysis()
