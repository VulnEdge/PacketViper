#!/usr/bin/env python3
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP
import threading

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PacketViper - Hacker Choice")
        self.root.geometry("800x500")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e1e")

        self.title_label = tk.Label(
            root,
            text="📡 PacketViper - Network Guardian",
            font=("Courier", 16),
            bg="#1e1e1e",
            fg="#00ff99"
        )
        self.title_label.pack(pady=10)

        self.text_area = scrolledtext.ScrolledText(
            root,
            wrap=tk.WORD,
            width=90,
            height=25,
            bg="#0e0e0e",
            fg="#00ff99",
            insertbackground='white'
        )
        self.text_area.pack(padx=10, pady=5)

        self.start_button = tk.Button(
            root,
            text="▶ Start Sniffing",
            width=15,
            command=self.start_sniffing,
            bg="#00ff99",
            fg="black",
            font=("Courier", 12)
        )
        self.start_button.pack(side=tk.LEFT, padx=20)

        self.stop_button = tk.Button(
            root,
            text="⏹ Stop Sniffing",
            width=15,
            command=self.stop_sniffing,
            bg="#ff4d4d",
            fg="black",
            font=("Courier", 12)
        )
        self.stop_button.pack(side=tk.RIGHT, padx=20)

        self.sniffing = False

    def packet_handler(self, pkt):
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            proto = pkt[IP].proto

            protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"

            line = f"[+] {ip_src} -> {ip_dst} | Protocol: {protocol} | Len: {len(pkt)}\n"
            self.text_area.insert(tk.END, line)
            self.text_area.see(tk.END)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, "[*] Starting packet capture...\n")
            thread = threading.Thread(target=self.run_sniffer)
            thread.daemon = True
            thread.start()

    def run_sniffer(self):
        sniff(prn=self.packet_handler, store=False, stop_filter=lambda x: not self.sniffing)

    def stop_sniffing(self):
        self.sniffing = False
        self.text_area.insert(tk.END, "[!] Packet capture stopped.\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
