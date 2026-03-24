GLASSS_STYLE = """
QMainWindow {
    background-color: #0b0e14;
}

QFrame#GlassPanel {
    background-color: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 15px;
}

QLabel {
    color: #e0e6ed;
    font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
}

QLabel#StatusOn {
    color: #00ffcc;
    font-weight: bold;
    font-size: 14px;
}

QLabel#StatusOff {
    color: #ff3366;
    font-weight: bold;
    font-size: 14px;
}

QLabel#Header {
    font-size: 24px;
    font-weight: bold;
    color: #00d2ff;
}

QTableWidget {
    background-color: transparent;
    border: none;
    color: #e0e6ed;
    gridline-color: rgba(255, 255, 255, 0.05);
}

QHeaderView::section {
    background-color: rgba(0, 0, 0, 0.3);
    padding: 10px;
    border: none;
    color: #00d2ff;
    font-weight: bold;
}

QListWidget {
    background-color: transparent;
    border: none;
    color: #a0aec0;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 11px;
}

QPushButton#ActionBtn {
    background-color: #00d2ff;
    color: #0b0e14;
    border-radius: 8px;
    padding: 10px 20px;
    font-weight: bold;
}

QPushButton#ActionBtn:hover {
    background-color: #00ffff;
}
"""
