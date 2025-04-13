# Parte da interface gráfica para o scanner de portas (NÃO AGUENTO MAIS USAR O TKINTER PQP)

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from core import PortScanner

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner de Portas")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        self.scanner = PortScanner(callback=self.update_scan_status)
        
        self.create_widgets()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        host_frame = ttk.Frame(main_frame)
        host_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(host_frame, text="Host (IP ou domínio):").pack(side=tk.LEFT)
        self.host_entry = ttk.Entry(host_frame, width=30)
        self.host_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        scan_options_frame = ttk.LabelFrame(main_frame, text="Opções de Scan", padding="5")
        scan_options_frame.pack(fill=tk.X, pady=5)
        
        self.scan_option = tk.StringVar(value="main")
        ttk.Radiobutton(scan_options_frame, text="Portas Principais", variable=self.scan_option, 
                        value="main", command=self.toggle_port_entry).pack(anchor=tk.W, pady=2)
        
        ttk.Radiobutton(scan_options_frame, text="Portas Personalizadas", variable=self.scan_option, 
                        value="custom", command=self.toggle_port_entry).pack(anchor=tk.W, pady=2)
        
        self.ports_frame = ttk.Frame(scan_options_frame)
        self.ports_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.ports_frame, text="Portas (ex: 80,443,8080 ou 1-1000):").pack(side=tk.LEFT)
        self.ports_entry = ttk.Entry(self.ports_frame)
        self.ports_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.ports_entry.config(state="disabled")
        
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        self.scan_button = ttk.Button(buttons_frame, text="Iniciar Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text="Parar Scan", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame, text="Limpar Resultados", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(self.progress_frame, text="Progresso:").pack(side=tk.LEFT)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var, length=300, mode="determinate")
        self.progress_bar.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        results_frame = ttk.LabelFrame(main_frame, text="Resultados", padding="5")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=15)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.config(state="disabled")
        
        self.status_var = tk.StringVar(value="Pronto para iniciar o scan")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
    
    def toggle_port_entry(self):
        if self.scan_option.get() == "custom":
            self.ports_entry.config(state="normal")
        else:
            self.ports_entry.config(state="disabled")
    
    def log_message(self, message):
        self.results_text.config(state="normal")
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        self.results_text.config(state="disabled")
    
    def update_scan_status(self, status, port, scanned, total, error=None):
        if status == "open":
            self.log_message(f"Porta {port} [TCP] aberta")
        elif status == "error":
            self.log_message(f"Erro ao escanear a porta {port}: {error}")
        
        progress = (scanned / total) * 100 if total > 0 else 0
        self.progress_var.set(progress)
        
        self.status_var.set(f"Escaneando... ({scanned}/{total})")
        
        self.root.update_idletasks()
    
    def start_scan(self):
        if self.scanner.is_running():
            return
        
        host = self.host_entry.get().strip()
        if not host:
            messagebox.showerror("Erro", "Por favor, digite um host válido")
            return
        
        use_main_ports = (self.scan_option.get() == "main")
        custom_ports = None
        
        if not use_main_ports:
            ports_input = self.ports_entry.get().strip()
            if not ports_input:
                messagebox.showerror("Erro", "Por favor, especifique as portas para escanear")
                return
            custom_ports = ports_input
        
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_var.set(0)
        
        self.clear_results()
        
        ip = self.scanner.resolve_host(host)
        if not ip:
            messagebox.showerror("Erro", "Host inválido, tente novamente")
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")
            return
        
        self.log_message(f"Iniciando scan em {host} ({ip})")
        
        scan_thread = threading.Thread(
            target=self.run_scanner,
            args=(host, custom_ports, use_main_ports)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        self.monitor_scan_progress()
    
    def run_scanner(self, host, ports, use_main_ports):
        success = self.scanner.start_scan(
            host=host,
            ports=ports,
            use_main_ports=use_main_ports
        )
        
        if not success:
            self.root.after(0, lambda: messagebox.showerror("Erro", "Não foi possível iniciar o scan"))
            self.root.after(0, self.scan_completed)
    
    def monitor_scan_progress(self):
        if not self.scanner.is_running():
            self.scan_completed()
            return
        
        self.root.after(200, self.monitor_scan_progress)
    
    def scan_completed(self):
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        
        open_ports = self.scanner.get_open_ports()
        if open_ports:
            self.log_message(f"\nPortas abertas encontradas: {', '.join(map(str, sorted(open_ports)))}")
        else:
            self.log_message("\nNenhuma porta aberta encontrada.")
        
        self.status_var.set("Scan concluído")
        self.log_message("Scan concluído")
        self.scanner.running = False
    
    def stop_scan(self):
        if not self.scanner.is_running():
            return
        
        self.scanner.stop_scan()
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_var.set("Scan interrompido")
        self.log_message("Scan interrompido pelo usuário")
    
    def clear_results(self):
        self.results_text.config(state="normal")
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state="disabled")
        self.progress_var.set(0)
        self.status_var.set("Pronto para iniciar o scan")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()