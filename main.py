# main.py
import tkinter as tk
from gui import PortScannerApp

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()