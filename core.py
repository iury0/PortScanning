# Parte principal do código "Há mais coisas entre o céu e a terra do que supõe sua vã filosofia" - que deus me abençoe nessa empreita de codigo
import socket
import threading
import time

PORTAS_PRINCIPAIS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

class PortScanner:
    def __init__(self, callback=None):
        self.callback = callback
        self.running = False
        self.threads = []
        self.lock = threading.Lock()
        self.scanned_ports = 0
        self.total_ports = 0
        self.open_ports = []
    
    def resolve_host(self, host):
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None
    
    def scan_port(self, host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((host, int(port)))
            s.close()
            
            is_open = (result == 0)
            
            with self.lock:
                self.scanned_ports += 1
                if is_open:
                    self.open_ports.append(port)
            
            if is_open and self.callback:
                self.callback("open", port, self.scanned_ports, self.total_ports)
            elif self.callback:
                self.callback("closed", port, self.scanned_ports, self.total_ports)
                
            return is_open
        except Exception as e:
            with self.lock:
                self.scanned_ports += 1
            
            if self.callback:
                self.callback("error", port, self.scanned_ports, self.total_ports, error=str(e))
            
            return False
    
    def parse_port_range(self, port_string):
        ports = []
        
        for part in port_string.split(','):
            try:
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
            except ValueError:
                raise ValueError(f"Formato inválido: '{part}' não é um número ou intervalo válido")
        
        return ports
    
    def start_scan(self, host, ports=None, use_main_ports=False, max_threads=50):
        if self.running:
            return False
        
        ip = self.resolve_host(host)
        if not ip:
            return False
        
        if use_main_ports:
            target_ports = PORTAS_PRINCIPAIS
        elif isinstance(ports, list):
            target_ports = ports
        elif isinstance(ports, str):
            try:
                target_ports = self.parse_port_range(ports)
            except ValueError:
                return False
        else:
            return False
        
        self.running = True
        self.threads = []
        self.scanned_ports = 0
        self.total_ports = len(target_ports)
        self.open_ports = []
        
        active_threads = 0
        for port in target_ports:
            if not self.running:
                break
            
            thread = threading.Thread(
                target=self.scan_port,
                args=(ip, port)
            )
            thread.daemon = True
            self.threads.append(thread)
            thread.start()
            
            active_threads += 1
            
            if active_threads >= max_threads:
                while active_threads >= max_threads and self.running:
                    active_threads = sum(1 for t in self.threads if t.is_alive())
                    time.sleep(0.05)
        
        return True
    
    def stop_scan(self):
        if not self.running:
            return
        
        self.running = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join()
    
    def is_running(self):
        return self.running and self.scanned_ports < self.total_ports
    
    def get_progress(self):
        percentage = 0
        if self.total_ports > 0:
            percentage = (self.scanned_ports / self.total_ports) * 100
        
        return (self.scanned_ports, self.total_ports, percentage)
    
    def get_open_ports(self):
        return self.open_ports