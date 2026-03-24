import sys
import os
import time
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QFrame, QTableWidget, 
                             QTableWidgetItem, QListWidget, QPushButton, QHeaderView)
from PySide6.QtCore import Qt, QTimer, Signal, Slot, QObject
from PySide6.QtGui import QColor, QFont
from ui_glass import GLASSS_STYLE
from monitor import LogMonitorThread

class IDS_App(QMainWindow):
    # Signals for thread-safe UI updates
    update_log_signal = Signal(dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("ANTIGRAVITY IDS — Advanced Threat Security")
        self.setMinimumSize(1100, 750)
        self.setStyleSheet(GLASSS_STYLE)

        # 1. Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.main_layout = QVBoxLayout(central_widget)
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(20)

        # 2. Top Bar
        top_bar = QHBoxLayout()
        header = QLabel("ANTIGRAVITY IDS")
        header.setObjectName("Header")
        
        self.status_label = QLabel("🛡️ PROTECTION: ACTIVE")
        self.status_label.setObjectName("StatusOn")
        
        self.model_label = QLabel("MODEL: ids_v2.joblib (Snapshot)")
        self.model_label.setStyleSheet("color: #718096; font-size: 11px;")

        top_bar.addWidget(header)
        top_bar.addStretch()
        top_bar.addWidget(self.model_label)
        top_bar.addSpacing(20)
        top_bar.addWidget(self.status_label)
        self.main_layout.addLayout(top_bar)

        # 3. Stats Row
        stats_layout = QHBoxLayout()
        self.stat_threats = self.create_stat_card("Threats Detected", "0", "#ff3366")
        self.stat_logs = self.create_stat_card("Total Logs Processed", "0", "#00d2ff")
        self.stat_confidence = self.create_stat_card("Core Confidence", "99.2%", "#00ffcc")
        stats_layout.addWidget(self.stat_threats)
        stats_layout.addWidget(self.stat_logs)
        stats_layout.addWidget(self.stat_confidence)
        self.main_layout.addLayout(stats_layout)

        # 4. Content Area (Alerts + Live Stream)
        content_layout = QHBoxLayout()
        content_layout.setSpacing(20)

        # Left: Alerts Table
        left_panel = QFrame()
        left_panel.setObjectName("GlassPanel")
        left_layout = QVBoxLayout(left_panel)
        left_layout.addWidget(QLabel("🛑 RECENT ALERTS"))
        
        self.alert_table = QTableWidget(0, 4)
        self.alert_table.setHorizontalHeaderLabels(["Timestamp", "Domain", "Stage", "Confidence"])
        self.alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        left_layout.addWidget(self.alert_table)
        content_layout.addWidget(left_panel, 2)

        # Right: Live Stream
        right_panel = QFrame()
        right_panel.setObjectName("GlassPanel")
        right_layout = QVBoxLayout(right_panel)
        right_layout.addWidget(QLabel("📜 LIVE LOG STREAM"))
        
        self.log_list = QListWidget()
        right_layout.addWidget(self.log_list)
        content_layout.addWidget(right_panel, 1)

        self.main_layout.addLayout(content_layout)

        # 5. Monitor Thread
        # Using a dummy log for PoC or auth.log if sudo
        log_to_watch = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "test_logs.txt"
        if not os.path.exists(log_to_watch):
             open(log_to_watch, "w").close()

        self.monitor_thread = LogMonitorThread(log_to_watch, self.on_log_received)
        self.update_log_signal.connect(self.process_new_event)
        self.monitor_thread.start()

        # Counters
        self.total_logs = 0
        self.total_threats = 0

    def create_stat_card(self, title, val, color):
        card = QFrame()
        card.setObjectName("GlassPanel")
        card.setMinimumHeight(100)
        lay = QVBoxLayout(card)
        t = QLabel(title)
        t.setStyleSheet("color: #a0aec0; font-size: 12px;")
        v = QLabel(val)
        v.setStyleSheet(f"color: {color}; font-size: 32px; font-weight: bold;")
        lay.addWidget(t)
        lay.addWidget(v)
        return card

    def on_log_received(self, data):
        self.update_log_signal.emit(data)

    @Slot(dict)
    def process_new_event(self, data):
        self.total_logs += 1
        self.stat_logs.findChild(QLabel, "").setText(str(self.total_logs))
        
        # Add to log list
        log_msg = f"[{time.strftime('%H:%M:%S')}] {data['raw'][:80]}..."
        self.log_list.insertItem(0, log_msg)
        if self.log_list.count() > 100:
            self.log_list.takeItem(100)

        # Handle Attack
        if data['is_attack']:
            self.total_threats += 1
            # Update Stat
            self.stat_threats.findChildren(QLabel)[1].setText(str(self.total_threats))
            
            # Add to table
            row = self.alert_table.rowCount()
            self.alert_table.insertRow(row)
            self.alert_table.setItem(row, 0, QTableWidgetItem(time.strftime('%H:%M:%S')))
            self.alert_table.setItem(row, 1, QTableWidgetItem(data['norm']['domain']))
            self.alert_table.setItem(row, 2, QTableWidgetItem(data['stage']))
            self.alert_table.setItem(row, 3, QTableWidgetItem(f"{data['confidence']:.2%}"))
            
            # Highlight
            for i in range(4):
                self.alert_table.item(row, i).setForeground(QColor("#ff3366"))
            
            self.alert_table.scrollToBottom()

    def closeEvent(self, event):
        self.monitor_thread.stop()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IDS_App()
    window.show()
    sys.exit(app.exec())
