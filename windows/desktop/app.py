"""
ShieldNet Windows Desktop Application - Modern Cybersecurity Dashboard
Provides real-time metrics, master shield switch, live query inspector,
blocklist management, custom rules editor, diagnostics, and DNS settings.
"""

from __future__ import annotations
import json
import logging
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from pathlib import Path
from typing import Any, Dict, List, Optional

from windows.desktop.ipc_client import ShieldNetIPCClient
from windows.service.daemon import ShieldNetDaemon, is_admin

# Cybersecurity Palette (Dark Modern UI)
PALETTE = {
    "bg_main": "#0d1117",        # GitHub/VSCode dark background
    "bg_card": "#161b22",        # Card background
    "bg_card_hover": "#21262d",  # Card hover
    "border": "#30363d",         # Subtle border
    "text_main": "#f0f6fc",       # High contrast white
    "text_muted": "#8b949e",      # Muted gray text
    "accent_green": "#238636",    # Protection Active Green
    "accent_green_light": "#2ea043",
    "accent_red": "#da3633",      # Blocked / Alert Red
    "accent_blue": "#58a6ff",     # Informational Blue
    "accent_purple": "#8957e5",   # Tracking / Analytics
    "accent_yellow": "#d29922",   # Warning / Pending
}

logger = logging.getLogger("shieldnet.desktop")


class ShieldNetDesktopApp:
    """Primary GUI Application for ShieldNet on Windows."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("ShieldNet — Cross-Platform Ad & Tracker Blocker")
        self.root.geometry("1020x720")
        self.root.minsize(880, 600)
        self.root.configure(bg=PALETTE["bg_main"])

        self.ipc = ShieldNetIPCClient()
        self.embedded_daemon: Optional[ShieldNetDaemon] = None
        self._ensure_backend_available()

        self._current_tab = "dashboard"
        self._status_cache: Dict[str, Any] = {}
        self._polling_active = True

        self._setup_styles()
        self._build_header()
        self._build_navigation()

        self.content_frame = tk.Frame(self.root, bg=PALETTE["bg_main"])
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=12)

        self._show_dashboard()
        self._start_polling()

    def _ensure_backend_available(self) -> None:
        """If external daemon is not running, spin up an embedded daemon in background."""
        if not self.ipc.is_alive():
            logger.info("Local daemon not detected; initializing embedded background engine...")
            self.embedded_daemon = ShieldNetDaemon()
            self.embedded_daemon.start()
            # Give IPC server 0.5s to bind
            time.sleep(0.5)

    def _setup_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        # Treeview (table) dark theme
        style.configure(
            "Treeview",
            background=PALETTE["bg_card"],
            foreground=PALETTE["text_main"],
            fieldbackground=PALETTE["bg_card"],
            rowheight=30,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=PALETTE["border"],
            foreground=PALETTE["text_main"],
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
        )
        style.map(
            "Treeview",
            background=[("selected", PALETTE["bg_card_hover"])],
            foreground=[("selected", PALETTE["accent_blue"])],
        )

    def _build_header(self) -> None:
        header_frame = tk.Frame(self.root, bg=PALETTE["bg_card"], height=64)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        header_frame.pack_propagate(False)

        # Brand / Logo
        brand_frame = tk.Frame(header_frame, bg=PALETTE["bg_card"])
        brand_frame.pack(side=tk.LEFT, padx=20, pady=12)

        lbl_logo = tk.Label(
            brand_frame,
            text="🛡️ ShieldNet",
            font=("Segoe UI", 16, "bold"),
            fg=PALETTE["text_main"],
            bg=PALETTE["bg_card"],
        )
        lbl_logo.pack(side=tk.LEFT)

        lbl_sub = tk.Label(
            brand_frame,
            text=" v1.0.0",
            font=("Segoe UI", 10),
            fg=PALETTE["accent_blue"],
            bg=PALETTE["bg_card"],
        )
        lbl_sub.pack(side=tk.LEFT, pady=4)

        # Admin privilege indicator badge
        admin_status = "🛡️ Administrator" if is_admin() else "⚠️ Standard User (Read Only DNS)"
        admin_color = PALETTE["accent_green"] if is_admin() else PALETTE["accent_yellow"]
        lbl_admin = tk.Label(
            header_frame,
            text=admin_status,
            font=("Segoe UI", 9),
            fg=admin_color,
            bg=PALETTE["bg_card"],
        )
        lbl_admin.pack(side=tk.RIGHT, padx=24)

    def _build_navigation(self) -> None:
        nav_frame = tk.Frame(self.root, bg=PALETTE["bg_main"], height=48)
        nav_frame.pack(fill=tk.X, side=tk.TOP, padx=24, pady=8)

        self.nav_buttons: Dict[str, tk.Button] = {}
        tabs = [
            ("dashboard", "📊 Dashboard"),
            ("activity", "📋 Query Activity"),
            ("blocklists", "📦 Blocklists"),
            ("custom_rules", "✏️ Custom Rules"),
            ("settings", "⚙️ Settings & Diagnostics"),
        ]

        for tab_id, label in tabs:
            btn = tk.Button(
                nav_frame,
                text=label,
                font=("Segoe UI", 10, "bold"),
                fg=PALETTE["text_muted"],
                bg=PALETTE["bg_card"],
                activebackground=PALETTE["bg_card_hover"],
                activeforeground=PALETTE["text_main"],
                relief=tk.FLAT,
                bd=0,
                padx=16,
                pady=8,
                cursor="hand2",
                command=lambda t=tab_id: self._switch_tab(t),
            )
            btn.pack(side=tk.LEFT, padx=4)
            self.nav_buttons[tab_id] = btn

    def _switch_tab(self, tab_id: str) -> None:
        self._current_tab = tab_id
        for tid, btn in self.nav_buttons.items():
            if tid == tab_id:
                btn.configure(fg=PALETTE["accent_blue"], bg=PALETTE["bg_card_hover"])
            else:
                btn.configure(fg=PALETTE["text_muted"], bg=PALETTE["bg_card"])

        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        if tab_id == "dashboard":
            self._show_dashboard()
        elif tab_id == "activity":
            self._show_activity()
        elif tab_id == "blocklists":
            self._show_blocklists()
        elif tab_id == "custom_rules":
            self._show_custom_rules()
        elif tab_id == "settings":
            self._show_settings()

    # ==========================================
    # TAB 1: DASHBOARD
    # ==========================================
    def _show_dashboard(self) -> None:
        dash_container = tk.Frame(self.content_frame, bg=PALETTE["bg_main"])
        dash_container.pack(fill=tk.BOTH, expand=True)

        # Shield & Master Switch Card
        shield_card = tk.Frame(dash_container, bg=PALETTE["bg_card"], bd=1, relief=tk.SOLID)
        shield_card.pack(fill=tk.X, pady=(0, 16), ipady=16)

        self.lbl_shield_icon = tk.Label(
            shield_card,
            text="🛡️",
            font=("Segoe UI", 48),
            bg=PALETTE["bg_card"],
            fg=PALETTE["accent_green"],
        )
        self.lbl_shield_icon.pack(side=tk.LEFT, padx=32)

        status_text_frame = tk.Frame(shield_card, bg=PALETTE["bg_card"])
        status_text_frame.pack(side=tk.LEFT, fill=tk.Y, expand=True)

        self.lbl_status_title = tk.Label(
            status_text_frame,
            text="SHIELD ACTIVE",
            font=("Segoe UI", 18, "bold"),
            fg=PALETTE["accent_green"],
            bg=PALETTE["bg_card"],
            anchor="w",
        )
        self.lbl_status_title.pack(fill=tk.X)

        self.lbl_status_desc = tk.Label(
            status_text_frame,
            text="Protecting your connection. Ad, telemetry, and tracking DNS queries are filtered locally.",
            font=("Segoe UI", 10),
            fg=PALETTE["text_muted"],
            bg=PALETTE["bg_card"],
            anchor="w",
            wraplength=500,
        )
        self.lbl_status_desc.pack(fill=tk.X, pady=4)

        self.btn_toggle_protection = tk.Button(
            shield_card,
            text="PAUSE PROTECTION",
            font=("Segoe UI", 11, "bold"),
            bg=PALETTE["accent_red"],
            fg=PALETTE["text_main"],
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2",
            command=self._toggle_protection,
        )
        self.btn_toggle_protection.pack(side=tk.RIGHT, padx=32)

        # 4 Metric Cards in Grid
        metrics_grid = tk.Frame(dash_container, bg=PALETTE["bg_main"])
        metrics_grid.pack(fill=tk.X, pady=8)

        # Column configuration
        for i in range(4):
            metrics_grid.columnconfigure(i, weight=1, uniform="metric_col")

        self.lbl_blocked_count = self._create_metric_card(metrics_grid, 0, "Queries Blocked", "0", PALETTE["accent_red"])
        self.lbl_allowed_count = self._create_metric_card(metrics_grid, 1, "Queries Permitted", "0", PALETTE["accent_green"])
        self.lbl_block_rate = self._create_metric_card(metrics_grid, 2, "Block Rate", "0.0%", PALETTE["accent_blue"])
        self.lbl_active_rules = self._create_metric_card(metrics_grid, 3, "Active Rules Loaded", "0", PALETTE["accent_purple"])

        # Category Breakdown & Diagnostics Preview
        bottom_frame = tk.Frame(dash_container, bg=PALETTE["bg_main"])
        bottom_frame.pack(fill=tk.BOTH, expand=True, pady=16)

        # Left: Category breakdown
        cat_card = tk.Frame(bottom_frame, bg=PALETTE["bg_card"], bd=1, relief=tk.SOLID)
        cat_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8), ipady=12)

        tk.Label(
            cat_card,
            text="Blocked by Category",
            font=("Segoe UI", 12, "bold"),
            fg=PALETTE["text_main"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w", padx=16, pady=(12, 8))

        self.lbl_cat_details = tk.Label(
            cat_card,
            text="Advertising: 0  |  Tracking: 0  |  Telemetry: 0  |  Custom: 0",
            font=("Segoe UI", 10),
            fg=PALETTE["text_muted"],
            bg=PALETTE["bg_card"],
            justify=tk.LEFT,
        )
        self.lbl_cat_details.pack(anchor="w", padx=16, pady=4)

        # Right: Quick Controls / Diagnostics
        quick_card = tk.Frame(bottom_frame, bg=PALETTE["bg_card"], bd=1, relief=tk.SOLID)
        quick_card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0), ipady=12)

        tk.Label(
            quick_card,
            text="Quick Diagnostics",
            font=("Segoe UI", 12, "bold"),
            fg=PALETTE["text_main"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w", padx=16, pady=(12, 8))

        btn_row = tk.Frame(quick_card, bg=PALETTE["bg_card"])
        btn_row.pack(anchor="w", padx=16, pady=6)

        tk.Button(
            btn_row,
            text="Flush Windows DNS",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_card_hover"],
            fg=PALETTE["text_main"],
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            command=self._flush_dns,
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_row,
            text="Update Blocklists",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_card_hover"],
            fg=PALETTE["text_main"],
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            command=self._trigger_blocklist_update,
        ).pack(side=tk.LEFT)

    def _create_metric_card(self, parent: tk.Frame, col: int, title: str, initial_value: str, color: str) -> tk.Label:
        card = tk.Frame(parent, bg=PALETTE["bg_card"], bd=1, relief=tk.SOLID)
        card.grid(row=0, column=col, padx=6, sticky="nsew", ipady=12)

        tk.Label(
            card,
            text=title,
            font=("Segoe UI", 9),
            fg=PALETTE["text_muted"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w", padx=14, pady=(8, 2))

        val_label = tk.Label(
            card,
            text=initial_value,
            font=("Segoe UI", 20, "bold"),
            fg=color,
            bg=PALETTE["bg_card"],
        )
        val_label.pack(anchor="w", padx=14, pady=(0, 8))
        return val_label

    def _toggle_protection(self) -> None:
        status_res = self.ipc.get_status()
        is_running = status_res.get("data", {}).get("is_running", False)
        if is_running:
            self.ipc.stop_protection()
        else:
            self.ipc.start_protection()
        self._refresh_ui()

    def _flush_dns(self) -> None:
        res = self.ipc.flush_dns()
        msg = res.get("message", "Flushed")
        messagebox.showinfo("DNS Cache Flush", f"Windows DNS resolver cache flushed successfully.\n{msg}")

    def _trigger_blocklist_update(self) -> None:
        def worker():
            res = self.ipc.update_blocklists()
            self.root.after(0, lambda: messagebox.showinfo("Update Complete", res.get("message", "Blocklists updated")))

        threading.Thread(target=worker, daemon=True).start()

    # ==========================================
    # TAB 2: QUERY ACTIVITY
    # ==========================================
    def _show_activity(self) -> None:
        act_container = tk.Frame(self.content_frame, bg=PALETTE["bg_main"])
        act_container.pack(fill=tk.BOTH, expand=True)

        # Search and filter header
        bar = tk.Frame(act_container, bg=PALETTE["bg_card"], bd=1, relief=tk.SOLID)
        bar.pack(fill=tk.X, pady=(0, 12), ipady=8, padx=2)

        tk.Label(bar, text="Search Domain:", fg=PALETTE["text_main"], bg=PALETTE["bg_card"], font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(12, 6))

        self.ent_search = tk.Entry(bar, bg=PALETTE["bg_main"], fg=PALETTE["text_main"], insertbackground="white", width=25, font=("Segoe UI", 9))
        self.ent_search.pack(side=tk.LEFT, padx=6)
        self.ent_search.bind("<KeyRelease>", lambda e: self._refresh_logs_table())

        self.filter_var = tk.StringVar(value="ALL")
        for val in ["ALL", "BLOCKED", "ALLOWED"]:
            tk.Radiobutton(
                bar,
                text=val,
                variable=self.filter_var,
                value=val,
                fg=PALETTE["text_main"],
                bg=PALETTE["bg_card"],
                selectcolor=PALETTE["bg_card_hover"],
                activebackground=PALETTE["bg_card"],
                command=self._refresh_logs_table,
            ).pack(side=tk.LEFT, padx=8)

        tk.Button(
            bar,
            text="Clear Logs",
            font=("Segoe UI", 9),
            bg=PALETTE["bg_card_hover"],
            fg=PALETTE["text_main"],
            relief=tk.FLAT,
            padx=10,
            command=self._clear_logs,
        ).pack(side=tk.RIGHT, padx=12)

        tk.Button(
            bar,
            text="Allow Selected Domain",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["accent_green"],
            fg=PALETTE["text_main"],
            relief=tk.FLAT,
            padx=12,
            command=self._allow_selected_domain,
        ).pack(side=tk.RIGHT, padx=6)

        # Table
        cols = ("time", "domain", "type", "status", "category", "rule", "latency")
        self.log_tree = ttk.Treeview(act_container, columns=cols, show="headings", selectmode="browse")
        self.log_tree.heading("time", text="Timestamp")
        self.log_tree.heading("domain", text="Domain")
        self.log_tree.heading("type", text="Type")
        self.log_tree.heading("status", text="Status")
        self.log_tree.heading("category", text="Category")
        self.log_tree.heading("rule", text="Rule Matched")
        self.log_tree.heading("latency", text="Latency (ms)")

        self.log_tree.column("time", width=140, anchor="w")
        self.log_tree.column("domain", width=280, anchor="w")
        self.log_tree.column("type", width=60, anchor="center")
        self.log_tree.column("status", width=90, anchor="center")
        self.log_tree.column("category", width=110, anchor="w")
        self.log_tree.column("rule", width=180, anchor="w")
        self.log_tree.column("latency", width=90, anchor="e")

        scrollbar = ttk.Scrollbar(act_container, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=scrollbar.set)
        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._refresh_logs_table()

    def _refresh_logs_table(self) -> None:
        if not hasattr(self, "log_tree"):
            return
        status_filter = self.filter_var.get()
        filter_status = None if status_filter == "ALL" else status_filter
        search_txt = self.ent_search.get() if hasattr(self, "ent_search") else ""

        res = self.ipc.get_logs(limit=150, filter_status=filter_status, search=search_txt)
        logs = res.get("logs", [])

        # Clear existing items
        for row in self.log_tree.get_children():
            self.log_tree.delete(row)

        for item in logs:
            status_text = "🚫 BLOCKED" if item.get("status") == "BLOCKED" else "✅ ALLOWED"
            self.log_tree.insert(
                "",
                tk.END,
                values=(
                    item.get("time_str", ""),
                    item.get("domain", ""),
                    item.get("qtype", "A"),
                    status_text,
                    item.get("category") or "—",
                    item.get("rule_pattern") or "—",
                    f"{item.get('latency_ms', 0):.1f}",
                ),
            )

    def _allow_selected_domain(self) -> None:
        selected = self.log_tree.selection()
        if not selected:
            messagebox.showwarning("Selection", "Please select a domain from the log table first.")
            return
        item = self.log_tree.item(selected[0])
        domain = item["values"][1]
        self.ipc.add_rule(domain, rule_type="ALLOW", category="Custom", comment="Allowlisted via Activity Log")
        messagebox.showinfo("Rule Added", f"Domain '{domain}' has been added to the Allowlist.")
        self._refresh_logs_table()

    def _clear_logs(self) -> None:
        self.ipc.clear_logs()
        self._refresh_logs_table()

    # ==========================================
    # TAB 3: BLOCKLISTS
    # ==========================================
    def _show_blocklists(self) -> None:
        bl_container = tk.Frame(self.content_frame, bg=PALETTE["bg_main"])
        bl_container.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(bl_container, bg=PALETTE["bg_main"])
        header.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            header,
            text="Verified Domain Blocklists",
            font=("Segoe UI", 14, "bold"),
            fg=PALETTE["text_main"],
            bg=PALETTE["bg_main"],
        ).pack(side=tk.LEFT)

        tk.Button(
            header,
            text="Update All Lists",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["accent_blue"],
            fg=PALETTE["text_main"],
            relief=tk.FLAT,
            padx=12,
            pady=6,
            command=self._trigger_blocklist_update,
        ).pack(side=tk.RIGHT)

        status_res = self.ipc.get_status()
        sources = status_res.get("data", {}).get("blocklist_sources", [])

        for s in sources:
            card = tk.Frame(bl_container, bg=PALETTE["bg_card"], bd=1, relief=tk.SOLID)
            card.pack(fill=tk.X, pady=6, ipady=8, padx=2)

            top_row = tk.Frame(card, bg=PALETTE["bg_card"])
            top_row.pack(fill=tk.X, padx=16, pady=4)

            tk.Label(
                top_row,
                text=s.get("name", "Blocklist"),
                font=("Segoe UI", 11, "bold"),
                fg=PALETTE["text_main"],
                bg=PALETTE["bg_card"],
            ).pack(side=tk.LEFT)

            cat_badge = tk.Label(
                top_row,
                text=f"[{s.get('category')}]",
                font=("Segoe UI", 9),
                fg=PALETTE["accent_purple"],
                bg=PALETTE["bg_card"],
            )
            cat_badge.pack(side=tk.LEFT, padx=8)

            rule_count_badge = tk.Label(
                top_row,
                text=f"{s.get('rule_count', 0):,} rules",
                font=("Segoe UI", 9, "bold"),
                fg=PALETTE["accent_green"],
                bg=PALETTE["bg_card"],
            )
            rule_count_badge.pack(side=tk.RIGHT)

            # Description / URL
            desc_text = s.get("description") or s.get("url")
            tk.Label(
                card,
                text=desc_text,
                font=("Segoe UI", 9),
                fg=PALETTE["text_muted"],
                bg=PALETTE["bg_card"],
                anchor="w",
            ).pack(fill=tk.X, padx=16, pady=2)

    # ==========================================
    # TAB 4: CUSTOM RULES
    # ==========================================
    def _show_custom_rules(self) -> None:
        cr_container = tk.Frame(self.content_frame, bg=PALETTE["bg_main"])
        cr_container.pack(fill=tk.BOTH, expand=True)

        # Add rule bar
        add_bar = tk.Frame(cr_container, bg=PALETTE["bg_card"], bd=1, relief=tk.SOLID)
        add_bar.pack(fill=tk.X, pady=(0, 16), ipady=10, padx=2)

        tk.Label(add_bar, text="Domain:", fg=PALETTE["text_main"], bg=PALETTE["bg_card"], font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(16, 6))
        self.ent_new_domain = tk.Entry(add_bar, bg=PALETTE["bg_main"], fg=PALETTE["text_main"], insertbackground="white", width=25, font=("Segoe UI", 9))
        self.ent_new_domain.pack(side=tk.LEFT, padx=6)

        self.rule_type_var = tk.StringVar(value="BLOCK")
        tk.Radiobutton(add_bar, text="Block", variable=self.rule_type_var, value="BLOCK", fg=PALETTE["text_main"], bg=PALETTE["bg_card"], selectcolor=PALETTE["bg_card_hover"]).pack(side=tk.LEFT, padx=6)
        tk.Radiobutton(add_bar, text="Allow", variable=self.rule_type_var, value="ALLOW", fg=PALETTE["text_main"], bg=PALETTE["bg_card"], selectcolor=PALETTE["bg_card_hover"]).pack(side=tk.LEFT, padx=6)

        tk.Button(
            add_bar,
            text="+ Add Rule",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["accent_green"],
            fg=PALETTE["text_main"],
            relief=tk.FLAT,
            padx=12,
            pady=4,
            command=self._add_custom_rule,
        ).pack(side=tk.LEFT, padx=16)

        tk.Button(
            add_bar,
            text="Export Rules (JSON)",
            font=("Segoe UI", 9),
            bg=PALETTE["bg_card_hover"],
            fg=PALETTE["text_main"],
            relief=tk.FLAT,
            padx=10,
            command=self._export_rules,
        ).pack(side=tk.RIGHT, padx=16)

        # Custom rules tree
        cols = ("domain", "type", "category", "comment")
        self.rules_tree = ttk.Treeview(cr_container, columns=cols, show="headings", selectmode="browse")
        self.rules_tree.heading("domain", text="Domain Pattern")
        self.rules_tree.heading("type", text="Action")
        self.rules_tree.heading("category", text="Category")
        self.rules_tree.heading("comment", text="Notes")

        self.rules_tree.column("domain", width=300)
        self.rules_tree.column("type", width=100, anchor="center")
        self.rules_tree.column("category", width=120)
        self.rules_tree.column("comment", width=250)

        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        btn_del = tk.Button(
            cr_container,
            text="Delete Selected",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["accent_red"],
            fg=PALETTE["text_main"],
            relief=tk.FLAT,
            padx=12,
            pady=6,
            command=self._delete_custom_rule,
        )
        btn_del.pack(side=tk.BOTTOM, pady=8, anchor="e")

        self._load_custom_rules_table()

    def _load_custom_rules_table(self) -> None:
        cfg = self.ipc.get_config().get("config", {})
        rules = cfg.get("custom_rules", [])

        for r in self.rules_tree.get_children():
            self.rules_tree.delete(r)

        for rule in rules:
            self.rules_tree.insert(
                "",
                tk.END,
                values=(
                    rule.get("domain"),
                    rule.get("rule_type"),
                    rule.get("category", "Custom"),
                    rule.get("comment", ""),
                ),
            )

    def _add_custom_rule(self) -> None:
        domain = self.ent_new_domain.get().strip()
        rtype = self.rule_type_var.get()
        if not domain:
            return

        res = self.ipc.add_rule(domain, rule_type=rtype, category="Custom")
        if res.get("status") == "ok":
            self.ent_new_domain.delete(0, tk.END)
            self._load_custom_rules_table()
        else:
            messagebox.showerror("Error", res.get("message", "Could not add rule"))

    def _delete_custom_rule(self) -> None:
        selected = self.rules_tree.selection()
        if not selected:
            return
        domain = self.rules_tree.item(selected[0])["values"][0]
        self.ipc.remove_rule(domain)
        self._load_custom_rules_table()

    def _export_rules(self) -> None:
        cfg = self.ipc.get_config().get("config", {})
        rules = cfg.get("custom_rules", [])
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile="shieldnet_rules.json",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"version": "1.0.0", "custom_rules": rules}, f, indent=2)
            messagebox.showinfo("Export Successful", f"Exported {len(rules)} custom rules to {path}")

    # ==========================================
    # TAB 5: SETTINGS & DIAGNOSTICS
    # ==========================================
    def _show_settings(self) -> None:
        set_container = tk.Frame(self.content_frame, bg=PALETTE["bg_main"])
        set_container.pack(fill=tk.BOTH, expand=True)

        card = tk.Frame(set_container, bg=PALETTE["bg_card"], bd=1, relief=tk.SOLID)
        card.pack(fill=tk.BOTH, expand=True, padx=2, pady=2, ipady=16)

        tk.Label(card, text="DNS Resolver Settings", font=("Segoe UI", 12, "bold"), fg=PALETTE["text_main"], bg=PALETTE["bg_card"]).pack(anchor="w", padx=20, pady=(16, 8))

        row1 = tk.Frame(card, bg=PALETTE["bg_card"])
        row1.pack(anchor="w", padx=20, pady=6)
        tk.Label(row1, text="Primary Upstream DNS:", fg=PALETTE["text_muted"], bg=PALETTE["bg_card"], font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.ent_upstream = tk.Entry(row1, bg=PALETTE["bg_main"], fg=PALETTE["text_main"], insertbackground="white", width=20)
        self.ent_upstream.insert(0, "9.9.9.9")
        self.ent_upstream.pack(side=tk.LEFT, padx=12)

        tk.Label(card, text="Network Diagnostics", font=("Segoe UI", 12, "bold"), fg=PALETTE["text_main"], bg=PALETTE["bg_card"]).pack(anchor="w", padx=20, pady=(20, 8))

        diag_row = tk.Frame(card, bg=PALETTE["bg_card"])
        diag_row.pack(anchor="w", padx=20, pady=6)

        tk.Button(
            diag_row,
            text="Flush System DNS Cache",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_card_hover"],
            fg=PALETTE["text_main"],
            relief=tk.FLAT,
            padx=14,
            pady=6,
            command=self._flush_dns,
        ).pack(side=tk.LEFT, padx=(0, 12))

        tk.Button(
            diag_row,
            text="Restore Original Network DNS",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["accent_yellow"],
            fg=PALETTE["bg_main"],
            relief=tk.FLAT,
            padx=14,
            pady=6,
            command=self._restore_system_dns,
        ).pack(side=tk.LEFT)

        # Content Filtering / Parental Controls Section
        tk.Label(card, text="Automatic Content Filtering & Protection", font=("Segoe UI", 12, "bold"), fg=PALETTE["text_main"], bg=PALETTE["bg_card"]).pack(anchor="w", padx=20, pady=(24, 6))
        tk.Label(card, text="Toggle specific content categories to block adult sites, gambling, and dangerous endpoints automatically.", font=("Segoe UI", 9), fg=PALETTE["text_muted"], bg=PALETTE["bg_card"]).pack(anchor="w", padx=20, pady=(0, 10))

        content_box = tk.Frame(card, bg=PALETTE["bg_card_hover"], bd=1, relief=tk.SOLID)
        content_box.pack(fill=tk.X, padx=20, pady=4, ipady=8)

        cfg_res = self.ipc.get_config()
        curr_cfg = cfg_res.get("config", {})
        enabled_cats = curr_cfg.get("enabled_categories", [])

        self.var_adult = tk.BooleanVar(value=curr_cfg.get("block_adult_content", True) or "Adult Content" in enabled_cats)
        self.var_gambling = tk.BooleanVar(value=curr_cfg.get("block_gambling", False) or "Gambling" in enabled_cats)
        self.var_malware = tk.BooleanVar(value="Malware" in enabled_cats)

        cb_adult = tk.Checkbutton(
            content_box,
            text="🔞 Block Explicit & Adult Content automatically (Porn, NSFW, Escorts)",
            variable=self.var_adult,
            font=("Segoe UI", 10, "bold"),
            fg=PALETTE["text_main"],
            bg=PALETTE["bg_card_hover"],
            selectcolor=PALETTE["bg_main"],
            activebackground=PALETTE["bg_card_hover"],
            activeforeground=PALETTE["text_main"],
            command=lambda: self._on_toggle_content_cat("Adult Content", self.var_adult.get())
        )
        cb_adult.pack(anchor="w", padx=16, pady=4)

        cb_gambling = tk.Checkbutton(
            content_box,
            text="🎰 Block Online Gambling & Casinos automatically",
            variable=self.var_gambling,
            font=("Segoe UI", 10),
            fg=PALETTE["text_main"],
            bg=PALETTE["bg_card_hover"],
            selectcolor=PALETTE["bg_main"],
            activebackground=PALETTE["bg_card_hover"],
            activeforeground=PALETTE["text_main"],
            command=lambda: self._on_toggle_content_cat("Gambling", self.var_gambling.get())
        )
        cb_gambling.pack(anchor="w", padx=16, pady=4)

        cb_malware = tk.Checkbutton(
            content_box,
            text="☣️ Block Malware, Phishing & Dangerous domains",
            variable=self.var_malware,
            font=("Segoe UI", 10),
            fg=PALETTE["text_main"],
            bg=PALETTE["bg_card_hover"],
            selectcolor=PALETTE["bg_main"],
            activebackground=PALETTE["bg_card_hover"],
            activeforeground=PALETTE["text_main"],
            command=lambda: self._on_toggle_content_cat("Malware", self.var_malware.get())
        )
        cb_malware.pack(anchor="w", padx=16, pady=4)

    def _on_toggle_content_cat(self, cat_name: str, enabled: bool) -> None:
        res = self.ipc.toggle_category(cat_name, enabled)
        status_msg = "enabled" if enabled else "disabled"
        if res.get("status") == "ok":
            messagebox.showinfo("Category Filter Updated", f"{cat_name} filtering is now {status_msg}.")
        else:
            messagebox.showerror("Error", res.get("message", f"Failed to update {cat_name}"))
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["accent_yellow"],
            fg=PALETTE["bg_main"],
            relief=tk.FLAT,
            padx=14,
            pady=6,
            command=self._restore_system_dns,
        ).pack(side=tk.LEFT)

    def _restore_system_dns(self) -> None:
        if not is_admin():
            messagebox.showwarning("Admin Privileges", "Administrator permissions are required to restore adapter DNS settings.")
            return
        if self.embedded_daemon:
            ok, msg = self.embedded_daemon.dns_manager.restore_original_dns()
            messagebox.showinfo("Restore DNS", msg)

    # ==========================================
    # POLLING & METRICS UPDATE
    # ==========================================
    def _start_polling(self) -> None:
        def poll():
            while self._polling_active:
                time.sleep(1.0)
                try:
                    res = self.ipc.get_status()
                    if res.get("status") == "ok":
                        self._status_cache = res.get("data", {})
                        self.root.after(0, self._refresh_ui)
                except Exception:
                    pass

        threading.Thread(target=poll, daemon=True).start()

    def _refresh_ui(self) -> None:
        data = self._status_cache
        is_running = data.get("is_running", False)

        # Update Master Shield Card if in Dashboard
        if self._current_tab == "dashboard" and hasattr(self, "lbl_shield_icon"):
            if is_running:
                self.lbl_shield_icon.configure(text="🛡️", fg=PALETTE["accent_green"])
                self.lbl_status_title.configure(text="SHIELD ACTIVE", fg=PALETTE["accent_green"])
                self.lbl_status_desc.configure(text="Protecting your connection. Ad, telemetry, and tracking DNS queries are filtered locally.")
                self.btn_toggle_protection.configure(text="PAUSE PROTECTION", bg=PALETTE["accent_red"])
            else:
                self.lbl_shield_icon.configure(text="🛡️", fg=PALETTE["text_muted"])
                self.lbl_status_title.configure(text="PROTECTION PAUSED", fg=PALETTE["text_muted"])
                self.lbl_status_desc.configure(text="Protection is disabled. DNS queries are resolving without domain-level filtering.")
                self.btn_toggle_protection.configure(text="START PROTECTION", bg=PALETTE["accent_green"])

            self.lbl_blocked_count.configure(text=f"{data.get('blocked_queries', 0):,}")
            self.lbl_allowed_count.configure(text=f"{data.get('allowed_queries', 0):,}")
            self.lbl_block_rate.configure(text=f"{data.get('block_rate_percent', 0.0):.1f}%")

            rule_stats = data.get("rules", {})
            total_rules = rule_stats.get("block", 0) + rule_stats.get("allow", 0)
            self.lbl_active_rules.configure(text=f"{total_rules:,}")

            cats = data.get("category_counts", {})
            cat_str = "  |  ".join(f"{k}: {v:,}" for k, v in cats.items())
            self.lbl_cat_details.configure(text=cat_str)

    def on_closing(self) -> None:
        self._polling_active = False
        if self.embedded_daemon:
            self.embedded_daemon.stop()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    app = ShieldNetDesktopApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
