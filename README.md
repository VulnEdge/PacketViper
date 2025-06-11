# 📡 PacketViper - Network Guardian

**PacketViper** is a lightweight, GUI-based network packet sniffer built with Python using `tkinter` and `scapy`. This tool provides a real-time view of packet activity on your network, making it ideal for security enthusiasts, students, and hackers who want to peek into the packets flying through the wires.

---

## 🚀 Features

- Real-time packet capture and display
- Identifies and labels protocols (TCP/UDP/Other)
- Color-coded, terminal-style GUI
- Start and stop packet sniffing with a click
- Minimal setup, no root access required for most systems

---

## 🛠 Installation & Usage

Follow these steps to install dependencies and run PacketViper.

### 1. Install the Tk development libraries:

sudo apt-get update
sudo apt-get install -y python3-tk tk-dev

### 2. Install Scapy:

pip install scapy

### 3. Run PacketViper:

python3 PacketViper.py

---

## 🧠 Notes

- PacketViper uses `scapy` to sniff packets. On some systems, you may require root privileges to capture packets, depending on your network interface and OS restrictions.
- Tested on Linux-based systems. Compatibility may vary on Windows or macOS.

---

## 📜 License

MIT License - feel free to use, modify, and distribute.

---

## 🧑‍💻 Author

Crafted with 💻 by [VulnEdge]

---

## ✨ Contributions

Want to improve PacketViper? Feel free to open issues or submit pull requests!
