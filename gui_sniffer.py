#
# A Desktop GUI Network Sniffer using PySide6 and Scapy
#
# This final version features a polished dark theme with vibrant accent colors,
# hover effects, and robust code for a professional user experience.
#
# Requirements:
#   - PySide6 (`pip install pyside6`)
#   - Scapy (`pip install scapy`)
#   - Npcap for Windows users (installed in WinPcap compatibility mode)
#
# To Run:
#   You MUST execute this script with administrative/root privileges.
#

import sys
import os
import time
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QToolBar, QTableWidget,
    QTableWidgetItem, QSplitter, QTreeWidget, QTreeWidgetItem, QTextEdit,
    QAbstractItemView, QHeaderView, QLabel, QStyle, QTabWidget
)
from PySide6.QtCore import Qt, QThread, Signal, Slot, QByteArray
from PySide6.QtGui import QAction, QIcon, QFont, QColor, QPixmap

# Import Scapy layers for type checking
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, Ether, ICMP, ARP
except ImportError:
    print("Scapy is not installed. Please run 'pip install scapy'.")
    sys.exit(1)


# --- Enhanced Dark Theme Stylesheet ---
ENHANCED_DARK_STYLESHEET = """
QWidget {
    background-color: #2e2f30;
    color: #e0e0e0;
    font-size: 10pt;
}
QMainWindow {
    background-color: #2e2f30;
}
QToolBar {
    background-color: #353637;
    border: none;
    padding: 5px;
}
QTableWidget {
    background-color: #252526;
    gridline-color: #3a3a3a;
    outline: 0;
    border: 1px solid #3a3a3a;
}
QTableWidget::item {
    border-bottom: 1px solid #3a3a3a;
    padding: 6px;
}
QTableWidget::item:selected {
    background-color: #0078d7; /* Vibrant blue for selection */
    color: #ffffff;
}
QTableWidget::item:hover {
    background-color: #3e3e40;
}
QHeaderView::section {
    background-color: #353637;
    color: #e0e0e0;
    padding: 5px;
    border: none;
    border-bottom: 1px solid #252526;
}
QTreeWidget {
    background-color: #252526;
    outline: 0;
    border: 1px solid #3a3a3a;
}
QTreeWidget::item:selected {
    background-color: #0078d7;
    color: #ffffff;
}
QTextEdit {
    background-color: #202021;
    color: #d0d0d0;
    border: 1px solid #3a3a3a;
}
QSplitter::handle {
    background-color: #353637;
    border: 1px solid #2e2f30;
}
QSplitter::handle:vertical { height: 6px; }
QSplitter::handle:horizontal { width: 6px; }
QStatusBar {
    background-color: #353637;
    color: #e0e0e0;
}
QScrollBar:vertical, QScrollBar:horizontal {
    border: none;
    background: #252526;
    width: 12px;
    margin: 0px;
}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background: #4a4a4c;
    min-height: 20px;
    border-radius: 6px;
}
QScrollBar::add-line, QScrollBar::sub-line {
    border: none;
    background: none;
}
"""

# --- Sniffer Worker Thread ---
class SnifferThread(QThread):
    packet_captured = Signal(object)
    def __init__(self):
        super().__init__()
        self.running = False
        self.interface = None
    def run(self):
        self.running = True
        sniff(iface=self.interface, prn=self.emit_packet, stop_filter=lambda p: not self.running, store=False)
    def emit_packet(self, packet):
        self.packet_captured.emit(packet)
    def stop(self):
        self.running = False


# --- Main Application Window ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python Network Sniffer")
        self.setGeometry(100, 100, 1200, 800)
        self.check_admin_rights()
        self.packets = []
        self.sniffer_thread = SnifferThread()
        self.sniffer_thread.packet_captured.connect(self.add_packet_to_table)
        self.setup_ui()

    def check_admin_rights(self):
        try:
            is_admin = (os.getuid() == 0)
        except AttributeError:
            import ctypes
            is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
        if not is_admin:
            print("Warning: Not running as admin. Packet sniffing may fail.")

    def setup_ui(self):
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)

        play_svg = QByteArray('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="#4CAF50" d="M8 5v14l11-7z"/></svg>'.encode('utf-8'))
        stop_svg = QByteArray('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="#F44336" d="M6 6h12v12H6z"/></svg>'.encode('utf-8'))
        clear_svg = QByteArray('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="#FFEB3B" d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>'.encode('utf-8'))
        
        start_pixmap = QPixmap()
        start_pixmap.loadFromData(play_svg)
        start_icon = QIcon(start_pixmap)

        stop_pixmap = QPixmap()
        stop_pixmap.loadFromData(stop_svg)
        stop_icon = QIcon(stop_pixmap)

        clear_pixmap = QPixmap()
        clear_pixmap.loadFromData(clear_svg)
        clear_icon = QIcon(clear_pixmap)

        self.start_action = QAction(start_icon, "Start Capture", self)
        self.start_action.triggered.connect(self.start_sniffing)
        toolbar.addAction(self.start_action)

        self.stop_action = QAction(stop_icon, "Stop Capture", self)
        self.stop_action.triggered.connect(self.stop_sniffing)
        self.stop_action.setEnabled(False)
        toolbar.addAction(self.stop_action)

        self.clear_action = QAction(clear_icon, "Clear All", self)
        self.clear_action.triggered.connect(self.clear_all)
        toolbar.addAction(self.clear_action)

        splitter = QSplitter(Qt.Orientation.Vertical)
        
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.packet_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.itemSelectionChanged.connect(self.show_packet_details)
        self.packet_table.setShowGrid(False)

        header = self.packet_table.horizontalHeader()
        for i, size in enumerate([50, 120, 200, 200, 80, 80, 0]):
            if size > 0:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
                header.resizeSection(i, size)
            else:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)

        details_splitter = QSplitter(Qt.Orientation.Vertical)
        
        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["Field", "Value"])
        details_header = self.details_tree.header()
        details_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        details_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        self.bytes_view = QTextEdit()
        self.bytes_view.setReadOnly(True)
        self.bytes_view.setFont(QFont("Monospace", 9))

        details_splitter.addWidget(self.details_tree)
        details_splitter.addWidget(self.bytes_view)

        splitter.addWidget(self.packet_table)
        splitter.addWidget(details_splitter)
        
        splitter.setSizes([350, 450])
        details_splitter.setSizes([300, 150])

        self.setCentralWidget(splitter)

        self.status_bar = self.statusBar()
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)

    @Slot()
    def start_sniffing(self):
        self.sniffer_thread.start()
        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        self.clear_action.setEnabled(False)
        self.status_label.setText("Capturing packets...")

    @Slot()
    def stop_sniffing(self):
        self.sniffer_thread.stop()
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        self.clear_action.setEnabled(True)
        self.status_label.setText("Capture stopped.")

    @Slot()
    def clear_all(self):
        self.packet_table.setRowCount(0)
        self.packets.clear()
        self.details_tree.clear()
        self.bytes_view.clear()
        self.status_label.setText("Ready")

    def get_protocol_color(self, proto_name):
        color_map = {
            "TCP": QColor("#1e3a5f"),
            "UDP": QColor("#2f4f4f"),
            "ICMP": QColor("#5f3a1e"),
            "HTTP": QColor("#5f5a1e"),
            "HTTPS": QColor("#5f5a1e"),
            "DNS": QColor("#4c3a70"),
            "ARP": QColor("#505050"),
        }
        return color_map.get(proto_name, QColor("#252526"))

    @Slot(object)
    def add_packet_to_table(self, packet):
        self.packets.append(packet)
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)
        
        packet_time = datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')
        src, dst, proto, info = "N/A", "N/A", "N/A", packet.summary()
        
        if packet.haslayer(IP): src, dst = packet[IP].src, packet[IP].dst
        elif packet.haslayer(ARP): src, dst = packet[ARP].psrc, packet[ARP].pdst
        elif packet.haslayer(Ether): src, dst = packet[Ether].src, packet[Ether].dst

        if packet.haslayer(TCP):
            dport, sport = packet[TCP].dport, packet[TCP].sport
            if dport == 443 or sport == 443: proto = "HTTPS"
            elif dport == 80 or sport == 80: proto = "HTTP"
            else: proto = "TCP"
        elif packet.haslayer(UDP): proto = "DNS" if packet.haslayer(DNS) else "UDP"
        elif packet.haslayer(ICMP): proto = "ICMP"
        elif packet.haslayer(ARP): proto = "ARP"
        else: proto = packet.name
        
        items = [
            QTableWidgetItem(str(row_position + 1)),
            QTableWidgetItem(packet_time), QTableWidgetItem(src),
            QTableWidgetItem(dst), QTableWidgetItem(proto),
            QTableWidgetItem(str(len(packet))), QTableWidgetItem(info)
        ]
        
        row_color = self.get_protocol_color(proto)
        for i, item in enumerate(items):
            item.setData(Qt.BackgroundRole, row_color)
            self.packet_table.setItem(row_position, i, item)

        self.packet_table.scrollToBottom()

    @Slot()
    def show_packet_details(self):
        selected_items = self.packet_table.selectedItems()
        if not selected_items:
            self.details_tree.clear()
            self.bytes_view.clear()
            return
            
        row = selected_items[0].row()
        packet = self.packets[row]
        
        self.details_tree.clear()
        current_layer = packet
        while current_layer:
            layer_name = current_layer.name
            layer_item = QTreeWidgetItem(self.details_tree, [f"{layer_name}"])
            
            for field in current_layer.fields_desc:
                field_name = field.name
                if hasattr(current_layer, field_name):
                    field_value = repr(getattr(current_layer, field_name))
                    QTreeWidgetItem(layer_item, [field_name, field_value])
            
            current_layer = current_layer.payload

        self.bytes_view.setText(self.format_hexdump(bytes(packet)))
        
    def format_hexdump(self, data):
        """
        Formats raw bytes into a visually structured table using simple,
        reliable ASCII characters for perfect alignment.
        """
        if not data:
            return "No data to display."

        lines = []
        # --- FIX: New, robust table formatting for hexdump ---
        # Define table structure
        offset_w, hex_w, ascii_w = 8, 49, 16 # Column widths
        top_border    = f"+{'='*10}+{'='*51}+{'='*18}+"
        header        = f"| {'Offset':<8} | {'Hexadecimal':<49} | {'ASCII':<16} |"
        middle_border = f"|{'─'*10}+{'─'*51}+{'─'*18}|"
        bottom_border = f"+{'─'*10}+{'─'*51}+{'─'*18}+"

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            
            # Column 1: Offset
            offset_str = f'| {i:08x} '

            # Column 2: Hexadecimal values, grouped
            hex_part1 = ' '.join(f'{b:02x}' for b in chunk[:8])
            hex_part2 = ' '.join(f'{b:02x}' for b in chunk[8:])
            hex_str = f'| {hex_part1:<23}  {hex_part2:<24} '
            
            # Column 3: ASCII representation
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            ascii_str = f'| {ascii_part:<16} |'

            lines.append(f'{offset_str}{hex_str}{ascii_str}')

        return '\n'.join([top_border, header, middle_border] + lines + [bottom_border])


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(ENHANCED_DARK_STYLESHEET)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
