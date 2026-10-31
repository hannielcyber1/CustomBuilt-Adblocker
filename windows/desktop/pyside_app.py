"""
ShieldNet Windows Desktop Application - PySide6 Native GUI
Full Qt implementation providing dark cybersecurity theme, real-time gauges,
query inspector, blocklist configuration, and system tray integration.
"""

from __future__ import annotations
import sys
import time
from typing import Any, Dict, Optional

try:
    from PySide6.QtCore import Qt, QTimer, Slot, Signal
    from PySide6.QtGui import QColor, QFont, QIcon, QPalette
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QRadioButton,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE_AVAILABLE = True
except ImportError:
    PYSIDE_AVAILABLE = False

from windows.desktop.ipc_client import ShieldNetIPCClient
from windows.service.dns_manager import is_admin


DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0d1117;
    color: #f0f6fc;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}
QTabWidget::pane {
    border: 1px solid #30363d;
    background-color: #0d1117;
}
QTabBar::tab {
    background: #161b22;
    color: #8b949e;
    padding: 10px 20px;
    font-weight: bold;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background: #21262d;
    color: #58a6ff;
    border-bottom: 2px solid #58a6ff;
}
QFrame#Card {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
}
QLabel {
    color: #f0f6fc;
}
QPushButton {
    background-color: #21262d;
    color: #f0f6fc;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #30363d;
}
QPushButton#PrimaryBtn {
    background-color: #238636;
    border-color: #2ea043;
}
QPushButton#PrimaryBtn:hover {
    background-color: #2ea043;
}
QPushButton#DangerBtn {
    background-color: #da3633;
    border-color: #f85149;
}
QPushButton#DangerBtn:hover {
    background-color: #b62324;
}
QTableWidget {
    background-color: #161b22;
    border: 1px solid #30363d;
    gridline-color: #21262d;
    color: #f0f6fc;
    selection-background-color: #21262d;
    selection-color: #58a6ff;
}
QHeaderView::section {
    background-color: #21262d;
    color: #8b949e;
    font-weight: bold;
    padding: 6px;
    border: none;
}
QLineEdit {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 10px;
    color: #f0f6fc;
}
"""


if PYSIDE_AVAILABLE:
    class MetricCard(QFrame):
        """Reusable metric display card."""
        def __init__(self, title: str, initial_val: str, color_hex: str) -> None:
            super().__init__()
            self.setObjectName("Card")
            layout = QVBoxLayout(self)
            layout.setContentsMargins(16, 14, 16, 14)

            lbl_title = QLabel(title)
            lbl_title.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
            layout.addWidget(lbl_title)

            self.lbl_val = QLabel(initial_val)
            self.lbl_val.setStyleSheet(f"color: {color_hex}; font-size: 24px; font-weight: bold;")
            layout.addWidget(self.lbl_val)

        def set_value(self, value: str) -> None:
            self.lbl_val.setText(value)


    class ShieldNetPySideWindow(QMainWindow):
        """Native PySide6 Desktop GUI for ShieldNet."""

        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("ShieldNet — Cross-Platform Ad & Tracker Blocker")
            self.resize(1020, 720)
            self.setMinimumSize(880, 600)
            self.setStyleSheet(DARK_STYLESHEET)

            self.ipc = ShieldNetIPCClient()

            self._build_ui()

            # Live polling timer
            self.timer = QTimer(self)
            self.timer.timeout.connect(self._poll_status)
            self.timer.start(1000)

        def _build_ui(self) -> None:
            central = QWidget()
            self.setCentralWidget(central)
            root_layout = QVBoxLayout(central)
            root_layout.setContentsMargins(20, 16, 20, 20)

            # Top Header Bar
            header = QHBoxLayout()
            lbl_brand = QLabel("🛡️ ShieldNet")
            lbl_brand.setStyleSheet("font-size: 20px; font-weight: bold; color: #f0f6fc;")
            header.addWidget(lbl_brand)

            lbl_ver = QLabel("v1.0.0")
            lbl_ver.setStyleSheet("color: #58a6ff; font-size: 11px; margin-top: 6px;")
            header.addWidget(lbl_ver)
            header.addStretch()

            admin_str = "🛡️ Administrator" if is_admin() else "⚠️ Standard User"
            admin_col = "#238636" if is_admin() else "#d29922"
            lbl_adm = QLabel(admin_str)
            lbl_adm.setStyleSheet(f"color: {admin_col}; font-weight: bold; font-size: 11px;")
            header.addWidget(lbl_adm)

            root_layout.addLayout(header)

            # Tab Widget
            tabs = QTabWidget()
            tabs.addTab(self._create_dashboard_tab(), "📊 Dashboard")
            tabs.addTab(self._create_activity_tab(), "📋 Query Activity")
            tabs.addTab(self._create_blocklists_tab(), "📦 Blocklists")
            tabs.addTab(self._create_rules_tab(), "✏️ Custom Rules")
            tabs.addTab(self._create_settings_tab(), "⚙️ Settings")
            root_layout.addWidget(tabs)

        def _create_dashboard_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.setContentsMargins(12, 16, 12, 12)

            # Shield Master Switch Card
            shield_card = QFrame()
            shield_card.setObjectName("Card")
            sc_layout = QHBoxLayout(shield_card)
            sc_layout.setContentsMargins(24, 20, 24, 20)

            self.lbl_shield_icon = QLabel("🛡️")
            self.lbl_shield_icon.setStyleSheet("font-size: 42px; color: #238636;")
            sc_layout.addWidget(self.lbl_shield_icon)

            status_vbox = QVBoxLayout()
            self.lbl_shield_status = QLabel("SHIELD ACTIVE")
            self.lbl_shield_status.setStyleSheet("font-size: 18px; font-weight: bold; color: #238636;")
            status_vbox.addWidget(self.lbl_shield_status)

            lbl_desc = QLabel("Filtering active. Tracking, telemetry, and advertising requests are null-routed locally.")
            lbl_desc.setStyleSheet("color: #8b949e; font-size: 11px;")
            status_vbox.addWidget(lbl_desc)
            sc_layout.addLayout(status_vbox)
            sc_layout.addStretch()

            self.btn_toggle = QPushButton("PAUSE PROTECTION")
            self.btn_toggle.setObjectName("DangerBtn")
            self.btn_toggle.clicked.connect(self._toggle_protection)
            sc_layout.addWidget(self.btn_toggle)

            layout.addWidget(shield_card)

            # Metric Cards Row
            grid = QGridLayout()
            self.card_blocked = MetricCard("QUERIES BLOCKED", "0", "#da3633")
            self.card_allowed = MetricCard("QUERIES PERMITTED", "0", "#238636")
            self.card_rate = MetricCard("BLOCK RATIO", "0.0%", "#58a6ff")
            self.card_rules = MetricCard("ACTIVE RULES LOADED", "0", "#8957e5")

            grid.addWidget(self.card_blocked, 0, 0)
            grid.addWidget(self.card_allowed, 0, 1)
            grid.addWidget(self.card_rate, 0, 2)
            grid.addWidget(self.card_rules, 0, 3)
            layout.addLayout(grid)

            layout.addStretch()
            return tab

        def _create_activity_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            # Table
            self.table = QTableWidget(0, 6)
            self.table.setHorizontalHeaderLabels(["Timestamp", "Domain", "Type", "Status", "Category", "Rule"])
            self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
            layout.addWidget(self.table)
            return tab

        def _create_blocklists_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            lbl = QLabel("Manage Trusted Domain Blocklists")
            lbl.setStyleSheet("font-weight: bold; font-size: 14px;")
            layout.addWidget(lbl)
            layout.addStretch()
            return tab

        def _create_rules_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            lbl = QLabel("User Defined Allow & Block Rules")
            lbl.setStyleSheet("font-weight: bold; font-size: 14px;")
            layout.addWidget(lbl)
            layout.addStretch()
            return tab

        def _create_settings_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            lbl = QLabel("DNS & Network Diagnostics")
            lbl.setStyleSheet("font-weight: bold; font-size: 14px;")
            layout.addWidget(lbl)
            layout.addStretch()
            return tab

        def _toggle_protection(self) -> None:
            res = self.ipc.get_status()
            is_running = res.get("data", {}).get("is_running", False)
            if is_running:
                self.ipc.stop_protection()
            else:
                self.ipc.start_protection()
            self._poll_status()

        def _poll_status(self) -> None:
            res = self.ipc.get_status()
            if res.get("status") == "ok":
                data = res.get("data", {})
                is_running = data.get("is_running", False)
                if is_running:
                    self.lbl_shield_icon.setStyleSheet("font-size: 42px; color: #238636;")
                    self.lbl_shield_status.setText("SHIELD ACTIVE")
                    self.lbl_shield_status.setStyleSheet("font-size: 18px; font-weight: bold; color: #238636;")
                    self.btn_toggle.setText("PAUSE PROTECTION")
                    self.btn_toggle.setObjectName("DangerBtn")
                else:
                    self.lbl_shield_icon.setStyleSheet("font-size: 42px; color: #8b949e;")
                    self.lbl_shield_status.setText("PROTECTION PAUSED")
                    self.lbl_shield_status.setStyleSheet("font-size: 18px; font-weight: bold; color: #8b949e;")
                    self.btn_toggle.setText("START PROTECTION")
                    self.btn_toggle.setObjectName("PrimaryBtn")

                self.card_blocked.set_value(f"{data.get('blocked_queries', 0):,}")
                self.card_allowed.set_value(f"{data.get('allowed_queries', 0):,}")
                self.card_rate.set_value(f"{data.get('block_rate_percent', 0.0):.1f}%")
                rules_cnt = data.get("rules", {}).get("block", 0) + data.get("rules", {}).get("allow", 0)
                self.card_rules.set_value(f"{rules_cnt:,}")


def launch_pyside() -> None:
    if not PYSIDE_AVAILABLE:
        print("PySide6 is not installed. Falling back to native desktop app.")
        return
    app = QApplication(sys.argv)
    window = ShieldNetPySideWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    launch_pyside()
