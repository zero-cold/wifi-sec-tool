#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
██╗    ██╗██╗███████╗██╗    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██║    ██║██║██╔════╝██║    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
██║ █╗ ██║██║█████╗  ██║    ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ 
██║███╗██║██║██╔══╝  ██║    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
╚███╔███╔╝██║██║     ██║    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   
                                                                                             
أداة اختبار أمان شبكات الواي فاي - إصدار احترافي Pro
WiFi Security Testing Tool - Professional Edition

Version: 3.0 Pro
⚠️ للاستخدام الأخلاقي والقانوني فقط | For Ethical and Legal Use Only
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import re
import os
import json
import csv
from datetime import datetime
import time
import queue
import hashlib
from collections import defaultdict
import sqlite3

class DatabaseManager:
    """إدارة قاعدة بيانات متقدمة للنتائج"""
    def __init__(self, db_path="wifi_security.db"):
        self.db_path = os.path.expanduser(f"~/.wifi_security/{db_path}")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """إنشاء قاعدة البيانات"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                interface TEXT,
                duration INTEGER,
                networks_found INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                ssid TEXT,
                bssid TEXT UNIQUE,
                channel INTEGER,
                signal INTEGER,
                security TEXT,
                wps TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                times_seen INTEGER DEFAULT 1,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS handshakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT,
                ssid TEXT,
                capture_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                file_path TEXT,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT,
                vulnerability_type TEXT,
                severity TEXT,
                detected_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                description TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_scan(self, interface, duration, networks_found):
        """حفظ نتائج الفحص"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO scans (interface, duration, networks_found) VALUES (?, ?, ?)',
            (interface, duration, networks_found)
        )
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id
    
    def save_network(self, scan_id, network_data):
        """حفظ معلومات الشبكة"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Normalize incoming keys so callers using either parser/scanner
        # schema work without raising KeyError.
        bssid = network_data.get('bssid') or network_data.get('BSSID') or ''
        if not bssid:
            conn.close()
            return
        ssid = network_data.get('ssid') or network_data.get('essid') or ''
        channel = network_data.get('channel', '')
        signal = network_data.get('signal') or network_data.get('power', '')
        security = network_data.get('security') or network_data.get('privacy', '')
        wps = network_data.get('wps', '')

        # Check if network exists
        cursor.execute('SELECT id, times_seen FROM networks WHERE bssid = ?',
                      (bssid,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                'UPDATE networks SET last_seen = CURRENT_TIMESTAMP, times_seen = ?, '
                'ssid = ?, channel = ?, signal = ?, security = ?, wps = ? WHERE bssid = ?',
                (existing[1] + 1, ssid, channel, signal, security, wps, bssid)
            )
        else:
            cursor.execute(
                '''INSERT INTO networks (scan_id, ssid, bssid, channel, signal, security, wps)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (scan_id, ssid, bssid, channel, signal, security, wps)
            )

        conn.commit()
        conn.close()

    def get_stats(self):
        """حساب الإحصائيات من قاعدة البيانات"""
        stats = {'total_scans': 0, 'networks_found': 0,
                 'vulnerabilities': 0, 'handshakes': 0}
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = cursor.fetchone()[0] or 0
            cursor.execute('SELECT COUNT(*) FROM networks')
            stats['networks_found'] = cursor.fetchone()[0] or 0
            cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
            stats['vulnerabilities'] = cursor.fetchone()[0] or 0
            cursor.execute('SELECT COUNT(*) FROM handshakes')
            stats['handshakes'] = cursor.fetchone()[0] or 0
            conn.close()
        except Exception:
            pass
        return stats

    def get_recent_networks(self, limit=50):
        """أحدث الشبكات المحفوظة"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT ssid, bssid, channel, signal, security, wps, last_seen '
                'FROM networks ORDER BY last_seen DESC LIMIT ?', (limit,)
            )
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception:
            return []
    
    def get_network_history(self, bssid):
        """الحصول على سجل الشبكة"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT * FROM networks WHERE bssid = ? ORDER BY last_seen DESC',
            (bssid,)
        )
        history = cursor.fetchall()
        conn.close()
        return history

class AdvancedScanner:
    """ماسح متقدم مع خوارزميات محسّنة"""
    def __init__(self, interface):
        self.interface = interface
        self.networks = {}
        self.clients = {}
        self.probes = defaultdict(set)
    
    def passive_scan(self, duration=60):
        """فحص سلبي متقدم"""
        try:
            process = subprocess.Popen(
                ['sudo', 'airodump-ng', '--output-format', 'csv', 
                 '-w', '/tmp/passive_scan', self.interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            time.sleep(duration)
            process.terminate()
            
            return self._parse_airodump_csv('/tmp/passive_scan-01.csv')
        except Exception as e:
            return None
    
    def _parse_airodump_csv(self, csv_file):
        """تحليل ملف CSV من airodump"""
        networks = []
        if not os.path.exists(csv_file):
            return networks
        
        with open(csv_file, 'r', errors='ignore') as f:
            content = f.read()
            
        # Parse networks section
        lines = content.split('\n')
        in_networks = False
        
        for line in lines:
            if 'BSSID' in line and 'Station' not in line:
                in_networks = True
                continue
            if 'Station MAC' in line:
                break
            if in_networks and line.strip():
                parts = [p.strip() for p in line.split(',')]
                if len(parts) > 13:
                    try:
                        networks.append({
                            'bssid': parts[0],
                            'first_seen': parts[1],
                            'last_seen': parts[2],
                            'channel': parts[3],
                            'speed': parts[4],
                            'privacy': parts[5],
                            'cipher': parts[6],
                            'auth': parts[7],
                            'power': parts[8],
                            'beacons': parts[9],
                            'iv': parts[10],
                            'lan_ip': parts[11],
                            'id_length': parts[12],
                            'essid': parts[13],
                            'key': parts[14] if len(parts) > 14 else ''
                        })
                    except Exception:
                        pass
        
        return networks
    
    def detect_wps_vulnerability(self, bssid):
        """كشف ثغرات WPS بدقة"""
        try:
            result = subprocess.run(
                ['sudo', 'wash', '-i', self.interface, '-C'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            for line in result.stdout.split('\n'):
                if bssid in line:
                    # Parse wash output for detailed WPS info
                    parts = line.split()
                    if len(parts) >= 6:
                        return {
                            'enabled': True,
                            'version': parts[2] if len(parts) > 2 else 'Unknown',
                            'locked': 'Locked' in line,
                            'vulnerable': not ('Locked' in line)
                        }
            
            return {'enabled': False}
        except Exception:
            return {'enabled': False}

class AttackSimulator:
    """محاكي هجمات متقدم للاختبار"""
    def __init__(self, interface):
        self.interface = interface
        self.active_attacks = []
    
    def deauth_attack(self, bssid, client=None, count=10):
        """هجوم deauth محسّن"""
        try:
            cmd = ['sudo', 'aireplay-ng', '--deauth', str(count), '-a', bssid]
            if client:
                cmd.extend(['-c', client])
            cmd.append(self.interface)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return 'packets' in result.stdout.lower()
        except Exception:
            return False
    
    def pmkid_capture(self, bssid, timeout=120):
        """التقاط PMKID (أحدث تقنية)"""
        try:
            output_file = f"/tmp/pmkid_{bssid.replace(':', '')}"
            
            # Use hcxdumptool if available
            if subprocess.run(['which', 'hcxdumptool'], capture_output=True).returncode == 0:
                process = subprocess.Popen(
                    ['sudo', 'hcxdumptool', '-i', self.interface, 
                     '-o', output_file + '.pcapng', '--enable_status=1'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                time.sleep(timeout)
                process.terminate()
                
                # Convert to hashcat format
                subprocess.run(
                    ['hcxpcapngtool', '-o', output_file + '.hc22000', 
                     output_file + '.pcapng'],
                    capture_output=True
                )
                
                return os.path.exists(output_file + '.hc22000')
            else:
                return False
        except Exception:
            return False
    
    def evil_twin_detection(self, networks):
        """كشف شبكات Evil Twin"""
        ssid_bssid_map = defaultdict(list)
        
        for net in networks:
            ssid_bssid_map[net['ssid']].append(net)
        
        evil_twins = []
        for ssid, nets in ssid_bssid_map.items():
            if len(nets) > 1 and ssid != '':
                # Multiple BSSIDs with same SSID - potential evil twin
                evil_twins.append({
                    'ssid': ssid,
                    'count': len(nets),
                    'networks': nets
                })
        
        return evil_twins

class WiFiSecurityToolPro:
    """الأداة الاحترافية الرئيسية"""
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Security Tool Pro 3.0 | أداة اختبار أمان الواي فاي الاحترافية")
        self.root.geometry("1200x900")
        
        # Modern dark theme
        self.colors = {
            'bg': '#0d1117',
            'fg': '#c9d1d9',
            'accent': '#58a6ff',
            'success': '#3fb950',
            'warning': '#d29922',
            'danger': '#f85149',
            'card_bg': '#161b22',
            'border': '#30363d'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # Initialize components
        self.db = DatabaseManager()
        self.interface = tk.StringVar()
        self.monitor_mode = False
        self.scanning = False
        self.networks = []
        self.selected_network = None
        self.scanner = None
        self.attacker = None
        self.log_queue = queue.Queue()
        
        # Performance tracking
        self.scan_start_time = None
        self.stats = {
            'total_scans': 0,
            'networks_found': 0,
            'vulnerabilities': 0,
            'handshakes': 0
        }
        
        self.setup_ui()
        self.load_stats()
        self.start_log_processor()
        self.check_requirements()
    
    def setup_ui(self):
        """إعداد واجهة محسّنة"""
        # Custom style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Card.TFrame', background=self.colors['card_bg'])
        style.configure('TLabel', background=self.colors['card_bg'], 
                       foreground=self.colors['fg'])
        
        # Header with logo
        self.create_header()
        
        # Main container with sidebar
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Sidebar
        self.create_sidebar(main_container)
        
        # Content area with tabs
        content_frame = tk.Frame(main_container, bg=self.colors['bg'])
        content_frame.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_scanner_tab()
        self.create_attack_tab()
        self.create_analysis_tab()
        self.create_tools_tab()
        self.create_settings_tab()
        
        # Status bar
        self.create_status_bar()
    
    def create_header(self):
        """إنشاء header احترافي"""
        header = tk.Frame(self.root, bg=self.colors['accent'], height=80)
        header.pack(fill='x')
        header.pack_propagate(False)
        
        # Logo and title
        title_frame = tk.Frame(header, bg=self.colors['accent'])
        title_frame.pack(side='left', padx=20, pady=15)
        
        tk.Label(
            title_frame,
            text="🔒 WiFi Security Tool Pro",
            font=('Arial', 20, 'bold'),
            bg=self.colors['accent'],
            fg='white'
        ).pack()
        
        tk.Label(
            title_frame,
            text="Professional Penetration Testing Suite | أداة اختبار الاختراق الاحترافية",
            font=('Arial', 9),
            bg=self.colors['accent'],
            fg='white'
        ).pack()
        
        # Stats panel
        stats_frame = tk.Frame(header, bg=self.colors['accent'])
        stats_frame.pack(side='right', padx=20, pady=10)
        
        self.stat_labels = {}
        stats_items = [
            ('scans', '🔍 Scans', '0'),
            ('networks', '📡 Networks', '0'),
            ('vulns', '⚠️ Vulnerabilities', '0'),
            ('handshakes', '🤝 Handshakes', '0')
        ]
        
        for i, (key, label, value) in enumerate(stats_items):
            frame = tk.Frame(stats_frame, bg=self.colors['accent'])
            frame.grid(row=0, column=i, padx=10)
            
            tk.Label(
                frame,
                text=label,
                font=('Arial', 8),
                bg=self.colors['accent'],
                fg='white'
            ).pack()
            
            self.stat_labels[key] = tk.Label(
                frame,
                text=value,
                font=('Arial', 14, 'bold'),
                bg=self.colors['accent'],
                fg='white'
            )
            self.stat_labels[key].pack()
    
    def create_sidebar(self, parent):
        """إنشاء sidebar متقدم"""
        sidebar = tk.Frame(parent, bg=self.colors['card_bg'], width=250)
        sidebar.pack(side='left', fill='y', padx=(0, 10))
        sidebar.pack_propagate(False)
        
        # Interface selection card
        interface_card = self.create_card(sidebar, "🔌 Network Interface")
        interface_card.pack(fill='x', padx=10, pady=10)
        
        self.interface_combo = ttk.Combobox(
            interface_card,
            textvariable=self.interface,
            state='readonly',
            width=20
        )
        self.interface_combo.pack(pady=5)
        
        btn_frame = tk.Frame(interface_card, bg=self.colors['card_bg'])
        btn_frame.pack(pady=5)
        
        self.create_button(
            btn_frame,
            "🔄 Refresh",
            self.get_interfaces,
            width=10
        ).pack(side='left', padx=2)
        
        self.monitor_btn = self.create_button(
            interface_card,
            "🔧 Monitor Mode",
            self.toggle_monitor_mode,
            self.colors['warning']
        )
        self.monitor_btn.pack(pady=5)
        
        # Quick Actions card
        actions_card = self.create_card(sidebar, "⚡ Quick Actions")
        actions_card.pack(fill='x', padx=10, pady=10)
        
        quick_actions = [
            ("🔍 Quick Scan", self.quick_scan, self.colors['success']),
            ("📊 View Report", self.view_report, self.colors['accent']),
            ("💾 Export All", self.export_all, self.colors['accent']),
            ("🗑️ Clear Data", self.clear_all_data, self.colors['danger'])
        ]
        
        for text, command, color in quick_actions:
            self.create_button(
                actions_card,
                text,
                command,
                color,
                width=18
            ).pack(pady=3, padx=5)
        
        # System Info card
        info_card = self.create_card(sidebar, "ℹ️ System Info")
        info_card.pack(fill='x', padx=10, pady=10)
        
        self.system_info = tk.Label(
            info_card,
            text="Loading...",
            bg=self.colors['card_bg'],
            fg=self.colors['fg'],
            font=('Courier', 8),
            justify='left'
        )
        self.system_info.pack(pady=5, padx=5)
        
        self.update_system_info()
    
    def create_dashboard_tab(self):
        """تبويب Dashboard متقدم"""
        tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(tab, text='📊 Dashboard')
        
        # Overview cards
        cards_frame = tk.Frame(tab, bg=self.colors['bg'])
        cards_frame.pack(fill='x', padx=10, pady=10)
        
        # Recent scans
        recent_card = self.create_card(cards_frame, "🕐 Recent Activity")
        recent_card.pack(side='left', fill='both', expand=True, padx=5)
        
        self.recent_text = scrolledtext.ScrolledText(
            recent_card,
            height=15,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=('Courier', 9),
            insertbackground=self.colors['fg']
        )
        self.recent_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Top vulnerabilities
        vulns_card = self.create_card(cards_frame, "⚠️ Top Vulnerabilities")
        vulns_card.pack(side='left', fill='both', expand=True, padx=5)
        
        self.vulns_text = scrolledtext.ScrolledText(
            vulns_card,
            height=15,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=('Courier', 9),
            insertbackground=self.colors['fg']
        )
        self.vulns_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Chart area
        chart_card = self.create_card(tab, "📈 Statistics")
        chart_card.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.create_button(
            chart_card,
            "📊 Generate Charts",
            self.generate_dashboard_charts,
            self.colors['accent']
        ).pack(pady=10)
    
    def create_scanner_tab(self):
        """تبويب Scanner محسّن"""
        tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(tab, text='🔍 Scanner')
        
        # Control panel
        control_frame = tk.Frame(tab, bg=self.colors['card_bg'])
        control_frame.pack(fill='x', padx=10, pady=10)
        
        buttons = [
            ("🔍 Normal Scan", self.start_normal_scan, self.colors['success']),
            ("🕵️ Passive Scan", self.start_passive_scan, self.colors['accent']),
            ("🎯 Targeted Scan", self.start_targeted_scan, self.colors['warning']),
            ("🔍 Hidden Networks", self.scan_hidden, self.colors['accent']),
            ("🛑 Stop", self.stop_scan, self.colors['danger'])
        ]
        
        for text, command, color in buttons:
            self.create_button(
                control_frame,
                text,
                command,
                color,
                width=15
            ).pack(side='left', padx=5, pady=10)
        
        # Networks table
        table_card = self.create_card(tab, "📡 Discovered Networks")
        table_card.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create advanced treeview
        columns = ('SSID', 'BSSID', 'CH', 'Signal', 'Security', 'WPS', 
                   'Clients', 'Speed', 'Risk')
        self.tree = ttk.Treeview(table_card, columns=columns, show='headings', 
                                height=15)
        
        # Configure columns
        col_widths = {
            'SSID': 150, 'BSSID': 130, 'CH': 40, 'Signal': 60,
            'Security': 100, 'WPS': 50, 'Clients': 60, 'Speed': 60, 'Risk': 80
        }
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=col_widths.get(col, 100))
        
        # Add tags for coloring
        self.tree.tag_configure('high_risk', background='#3d0f0f', foreground='#f85149')
        self.tree.tag_configure('medium_risk', background='#3d2f0f', foreground='#d29922')
        self.tree.tag_configure('low_risk', background='#0f3d1d', foreground='#3fb950')
        
        # Scrollbars
        vsb = ttk.Scrollbar(table_card, orient='vertical', command=self.tree.yview)
        hsb = ttk.Scrollbar(table_card, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        table_card.grid_rowconfigure(0, weight=1)
        table_card.grid_columnconfigure(0, weight=1)
        
        # Bind selection
        self.tree.bind('<<TreeviewSelect>>', self.on_network_select)
        self.tree.bind('<Double-1>', self.show_network_details)
        
        # Console output
        console_card = self.create_card(tab, "💻 Console Output")
        console_card.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.console_text = scrolledtext.ScrolledText(
            console_card,
            height=10,
            bg='#0d1117',
            fg='#58a6ff',
            font=('Courier', 9),
            insertbackground='#58a6ff'
        )
        self.console_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_attack_tab(self):
        """تبويب Attack محسّن"""
        tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(tab, text='⚔️ Attack')
        
        # Warning banner
        warning = tk.Label(
            tab,
            text="⚠️ WARNING: Use only on networks you own or have explicit permission to test",
            bg=self.colors['danger'],
            fg='white',
            font=('Arial', 10, 'bold'),
            pady=10
        )
        warning.pack(fill='x', padx=10, pady=10)
        
        # Selected target info
        target_card = self.create_card(tab, "🎯 Selected Target")
        target_card.pack(fill='x', padx=10, pady=10)
        
        self.target_info_label = tk.Label(
            target_card,
            text="No target selected",
            bg=self.colors['card_bg'],
            fg=self.colors['fg'],
            font=('Courier', 10),
            justify='left'
        )
        self.target_info_label.pack(pady=10, padx=10)
        
        # Attack modules
        modules_frame = tk.Frame(tab, bg=self.colors['bg'])
        modules_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # WPS Attack Module
        wps_card = self.create_card(modules_frame, "🔐 WPS Attack Module")
        wps_card.pack(side='left', fill='both', expand=True, padx=5)
        
        tk.Label(
            wps_card,
            text="Test WPS vulnerabilities",
            bg=self.colors['card_bg'],
            fg=self.colors['fg'],
            font=('Arial', 9)
        ).pack(pady=5)
        
        wps_buttons = [
            ("🔍 Check WPS", self.check_wps_advanced),
            ("⚡ Pixie Dust", self.wps_pixie_attack),
            ("🔨 Brute Force", self.wps_bruteforce),
            ("🎲 Null PIN", self.wps_null_pin)
        ]
        
        for text, command in wps_buttons:
            self.create_button(
                wps_card,
                text,
                command,
                self.colors['warning'],
                width=15
            ).pack(pady=3, padx=5)
        
        # Handshake Capture Module
        hs_card = self.create_card(modules_frame, "🤝 Handshake Capture")
        hs_card.pack(side='left', fill='both', expand=True, padx=5)
        
        tk.Label(
            hs_card,
            text="Capture WPA/WPA2 handshakes",
            bg=self.colors['card_bg'],
            fg=self.colors['fg'],
            font=('Arial', 9)
        ).pack(pady=5)
        
        hs_buttons = [
            ("📡 Start Capture", self.start_handshake_capture),
            ("📊 PMKID Attack", self.pmkid_attack),
            ("💥 Send Deauth", self.send_deauth_advanced),
            ("🛑 Stop Capture", self.stop_handshake_capture)
        ]
        
        for text, command in hs_buttons:
            self.create_button(
                hs_card,
                text,
                command,
                self.colors['accent'],
                width=15
            ).pack(pady=3, padx=5)
        
        # Advanced Attacks Module
        adv_card = self.create_card(modules_frame, "🎯 Advanced Attacks")
        adv_card.pack(side='left', fill='both', expand=True, padx=5)
        
        tk.Label(
            adv_card,
            text="Professional attack vectors",
            bg=self.colors['card_bg'],
            fg=self.colors['fg'],
            font=('Arial', 9)
        ).pack(pady=5)
        
        adv_buttons = [
            ("👥 Evil Twin", self.evil_twin_attack),
            ("🎣 Phishing AP", self.phishing_ap),
            ("🔄 MITM Setup", self.mitm_attack),
            ("🌐 DNS Spoofing", self.dns_spoof)
        ]
        
        for text, command in adv_buttons:
            self.create_button(
                adv_card,
                text,
                command,
                self.colors['danger'],
                width=15
            ).pack(pady=3, padx=5)
        
        # Attack console
        console_card = self.create_card(tab, "🖥️ Attack Console")
        console_card.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.attack_console = scrolledtext.ScrolledText(
            console_card,
            height=15,
            bg='#0d1117',
            fg='#f85149',
            font=('Courier', 9),
            insertbackground='#f85149'
        )
        self.attack_console.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_analysis_tab(self):
        """تبويب Analysis متطور"""
        tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(tab, text='📊 Analysis')
        
        # Analysis controls
        control_frame = tk.Frame(tab, bg=self.colors['card_bg'])
        control_frame.pack(fill='x', padx=10, pady=10)
        
        analysis_buttons = [
            ("📊 Signal Analysis", self.signal_analysis),
            ("🔒 Security Audit", self.security_audit),
            ("👁️ Evil Twin Detection", self.detect_evil_twins),
            ("📈 Channel Analysis", self.channel_analysis),
            ("🗺️ Generate Heatmap", self.generate_heatmap)
        ]
        
        for text, command in analysis_buttons:
            self.create_button(
                control_frame,
                text,
                command,
                self.colors['accent'],
                width=18
            ).pack(side='left', padx=5, pady=10)
        
        # Analysis output
        output_card = self.create_card(tab, "📋 Analysis Results")
        output_card.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.analysis_text = scrolledtext.ScrolledText(
            output_card,
            bg='#0d1117',
            fg='#58a6ff',
            font=('Courier', 9),
            insertbackground='#58a6ff'
        )
        self.analysis_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_tools_tab(self):
        """تبويب Tools إضافي"""
        tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(tab, text='🛠️ Tools')
        
        tools_grid = tk.Frame(tab, bg=self.colors['bg'])
        tools_grid.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Password tools
        pass_card = self.create_card(tools_grid, "🔑 Password Tools")
        pass_card.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        
        pass_tools = [
            ("📝 Generate Wordlist", self.generate_wordlist),
            ("🔨 Dictionary Attack", self.dictionary_attack),
            ("🎲 Rule-based Attack", self.rule_attack),
            ("📊 Analyze Captures", self.analyze_captures)
        ]
        
        for text, command in pass_tools:
            self.create_button(
                pass_card,
                text,
                command,
                self.colors['accent'],
                width=20
            ).pack(pady=3, padx=5)
        
        # Network tools
        net_card = self.create_card(tools_grid, "🌐 Network Tools")
        net_card.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)
        
        net_tools = [
            ("📡 Monitor Traffic", self.monitor_traffic),
            ("🔍 Port Scanner", self.port_scan),
            ("🌍 Geolocation", self.geolocate_ap),
            ("📊 Bandwidth Test", self.bandwidth_test)
        ]
        
        for text, command in net_tools:
            self.create_button(
                net_card,
                text,
                command,
                self.colors['accent'],
                width=20
            ).pack(pady=3, padx=5)
        
        # Export tools
        export_card = self.create_card(tools_grid, "💾 Export Tools")
        export_card.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
        
        export_tools = [
            ("📄 Export CSV", lambda: self.export_results('csv')),
            ("📋 Export JSON", lambda: self.export_results('json')),
            ("📊 Export HTML Report", lambda: self.export_results('html')),
            ("📝 Export PDF", lambda: self.export_results('pdf'))
        ]
        
        for text, command in export_tools:
            self.create_button(
                export_card,
                text,
                command,
                self.colors['success'],
                width=20
            ).pack(pady=3, padx=5)
        
        # Database tools
        db_card = self.create_card(tools_grid, "🗄️ Database Tools")
        db_card.grid(row=1, column=1, sticky='nsew', padx=5, pady=5)
        
        db_tools = [
            ("📊 View History", self.view_history),
            ("🔍 Search Networks", self.search_networks),
            ("🗑️ Clean Database", self.clean_database),
            ("💾 Backup Data", self.backup_database)
        ]
        
        for text, command in db_tools:
            self.create_button(
                db_card,
                text,
                command,
                self.colors['warning'],
                width=20
            ).pack(pady=3, padx=5)
        
        tools_grid.grid_rowconfigure(0, weight=1)
        tools_grid.grid_rowconfigure(1, weight=1)
        tools_grid.grid_columnconfigure(0, weight=1)
        tools_grid.grid_columnconfigure(1, weight=1)
    
    def create_settings_tab(self):
        """تبويب Settings"""
        tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(tab, text='⚙️ Settings')
        
        settings_card = self.create_card(tab, "⚙️ Configuration")
        settings_card.pack(fill='x', padx=10, pady=10)

        # Scan duration
        row1 = tk.Frame(settings_card, bg=self.colors['card_bg'])
        row1.pack(fill='x', pady=8, padx=10)
        tk.Label(row1, text="Passive scan duration (seconds):",
                 bg=self.colors['card_bg'], fg=self.colors['fg'],
                 font=('Arial', 10)).pack(side='left')
        self.scan_duration = tk.IntVar(value=60)
        ttk.Spinbox(row1, from_=10, to=600, increment=10, width=8,
                    textvariable=self.scan_duration).pack(side='left', padx=10)

        # Auto-save
        row2 = tk.Frame(settings_card, bg=self.colors['card_bg'])
        row2.pack(fill='x', pady=8, padx=10)
        self.autosave_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row2, text="Auto-save scan results to database",
                       variable=self.autosave_var, bg=self.colors['card_bg'],
                       fg=self.colors['fg'], selectcolor=self.colors['bg'],
                       activebackground=self.colors['card_bg'],
                       activeforeground=self.colors['fg'],
                       font=('Arial', 10)).pack(side='left')

        # Theme toggle
        row3 = tk.Frame(settings_card, bg=self.colors['card_bg'])
        row3.pack(fill='x', pady=8, padx=10)
        tk.Label(row3, text="Theme:", bg=self.colors['card_bg'],
                 fg=self.colors['fg'], font=('Arial', 10)).pack(side='left')
        self.create_button(row3, "🌓 Toggle Light/Dark",
                           self.toggle_theme, self.colors['accent'],
                           width=20).pack(side='left', padx=10)

        # DB location info
        info_card = self.create_card(tab, "ℹ️ About")
        info_card.pack(fill='both', expand=True, padx=10, pady=10)
        tk.Label(
            info_card,
            text=("WiFi Security Tool Pro 3.0\n"
                  f"Database: {self.db.db_path}\n\n"
                  "⚠️ For authorized / ethical security testing only.\n"
                  "⚠️ للاستخدام الأمني المصرح به فقط."),
            bg=self.colors['card_bg'], fg=self.colors['fg'],
            font=('Courier', 9), justify='left'
        ).pack(pady=20, padx=10, anchor='w')

    def toggle_theme(self):
        """تبديل بين الثيم الفاتح والغامق"""
        dark = {
            'bg': '#0d1117', 'fg': '#c9d1d9', 'accent': '#58a6ff',
            'success': '#3fb950', 'warning': '#d29922', 'danger': '#f85149',
            'card_bg': '#161b22', 'border': '#30363d'
        }
        light = {
            'bg': '#f6f8fa', 'fg': '#1f2328', 'accent': '#0969da',
            'success': '#1a7f37', 'warning': '#9a6700', 'danger': '#cf222e',
            'card_bg': '#ffffff', 'border': '#d0d7de'
        }
        self.theme = 'light' if getattr(self, 'theme', 'dark') == 'dark' else 'dark'
        self.colors = light if self.theme == 'light' else dark
        self.root.configure(bg=self.colors['bg'])
        messagebox.showinfo(
            "Theme",
            f"Switched to {self.theme} theme. Restart the app to fully "
            "re-render all widgets with the new palette.")
    
    def create_status_bar(self):
        """إنشاء status bar متطور"""
        status_frame = tk.Frame(self.root, bg=self.colors['card_bg'], height=30)
        status_frame.pack(side='bottom', fill='x')
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(
            status_frame,
            text="⚡ Ready",
            bg=self.colors['card_bg'],
            fg=self.colors['success'],
            font=('Arial', 9),
            anchor='w'
        )
        self.status_label.pack(side='left', padx=10)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            status_frame,
            mode='indeterminate',
            length=200
        )
        self.progress.pack(side='right', padx=10)
    
    def create_card(self, parent, title):
        """إنشاء card جميل"""
        card = tk.LabelFrame(
            parent,
            text=title,
            bg=self.colors['card_bg'],
            fg=self.colors['fg'],
            font=('Arial', 10, 'bold'),
            relief='flat',
            borderwidth=2
        )
        return card
    
    def create_button(self, parent, text, command, color=None, width=12):
        """إنشاء زر مخصص"""
        if color is None:
            color = self.colors['accent']
        
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg='white',
            font=('Arial', 9, 'bold'),
            relief='flat',
            cursor='hand2',
            width=width,
            pady=8
        )
        
        # Hover effects
        def on_enter(e):
            btn.config(bg=self.lighten_color(color))
        
        def on_leave(e):
            btn.config(bg=color)
        
        btn.bind('<Enter>', on_enter)
        btn.bind('<Leave>', on_leave)
        
        return btn
    
    def lighten_color(self, color):
        """تفتيح اللون للـ hover effect"""
        # Simple color lightening
        color_map = {
            self.colors['accent']: '#6eb8ff',
            self.colors['success']: '#56c46a',
            self.colors['warning']: '#e0ac3a',
            self.colors['danger']: '#ff6b63'
        }
        return color_map.get(color, color)
    
    def log(self, message, level='info'):
        """نظام logging محسّن"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        level_colors = {
            'info': self.colors['accent'],
            'success': self.colors['success'],
            'warning': self.colors['warning'],
            'error': self.colors['danger']
        }
        
        color = level_colors.get(level, self.colors['fg'])
        formatted_msg = f"[{timestamp}] {message}\n"
        
        self.log_queue.put((formatted_msg, color))
    
    def start_log_processor(self):
        """معالج log آمن للـ threads (عبر حلقة tkinter نفسها)

        Tkinter widgets لا يجوز تعديلها من thread آخر، لذلك نستهلك الطابور
        من الحلقة الرئيسية باستخدام root.after بدلاً من thread خلفي.
        """
        def process_logs():
            drained = 0
            while drained < 200:  # cap per tick to keep UI responsive
                try:
                    msg, color = self.log_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    self.console_text.configure(state='normal')
                    self.console_text.insert(tk.END, msg)
                    self.console_text.see(tk.END)
                except tk.TclError:
                    return  # widget destroyed (app closing)
                drained += 1
            self.root.after(100, process_logs)

        self.root.after(100, process_logs)
    
    def update_status(self, message, level='info'):
        """تحديث status bar"""
        level_symbols = {
            'info': '⚡',
            'success': '✅',
            'warning': '⚠️',
            'error': '❌',
            'scanning': '🔍'
        }
        
        symbol = level_symbols.get(level, '⚡')
        self.status_label.config(text=f"{symbol} {message}")
    
    def update_system_info(self):
        """تحديث معلومات النظام"""
        try:
            # Get system info
            import platform
            info = f"OS: {platform.system()}\n"
            info += f"Python: {platform.python_version()}\n"
            info += f"Interface: {self.interface.get() or 'None'}\n"
            info += f"Monitor: {'Yes' if self.monitor_mode else 'No'}"
            
            self.system_info.config(text=info)
        except Exception:
            pass
        
        # Schedule next update
        self.root.after(5000, self.update_system_info)
    
    def check_requirements(self):
        """فحص المتطلبات الشامل"""
        self.log("🔍 Checking system requirements...", 'info')
        
        tools = {
            'airmon-ng': 'Monitor Mode',
            'airodump-ng': 'Network Scanning',
            'aireplay-ng': 'Packet Injection',
            'aircrack-ng': 'Handshake Analysis',
            'wash': 'WPS Detection',
            'reaver': 'WPS Attack',
            'hcxdumptool': 'PMKID Capture',
            'hcxpcapngtool': 'Hash Conversion',
            'nmcli': 'Network Management'
        }
        
        missing = []
        for tool, desc in tools.items():
            result = subprocess.run(['which', tool], capture_output=True)
            if result.returncode == 0:
                self.log(f"✅ {tool}: Available", 'success')
            else:
                self.log(f"❌ {tool}: Missing ({desc})", 'error')
                missing.append(tool)
        
        if missing:
            self.log(f"\n⚠️ Missing tools: {', '.join(missing)}", 'warning')
            self.log("Install with: sudo apt install aircrack-ng reaver hcxtools", 'warning')
        else:
            self.log("\n✅ All tools available!", 'success')
        
        self.get_interfaces()
    
    def get_interfaces(self):
        """الحصول على واجهات الشبكة"""
        try:
            result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
            interfaces = []
            
            for line in result.stdout.split('\n'):
                if 'wl' in line or 'wlan' in line:
                    match = re.search(r'\d+: (\w+):', line)
                    if match:
                        interfaces.append(match.group(1))
            
            if interfaces:
                self.interface_combo['values'] = interfaces
                self.interface_combo.current(0)
                self.log(f"✅ Found interfaces: {', '.join(interfaces)}", 'success')
            else:
                self.log("⚠️ No WiFi interfaces found", 'warning')
        except Exception as e:
            self.log(f"❌ Error getting interfaces: {str(e)}", 'error')
    
    def toggle_monitor_mode(self):
        """تبديل Monitor Mode"""
        if not self.interface.get():
            messagebox.showerror("Error", "Please select an interface first")
            return
        
        interface = self.interface.get()
        
        try:
            if not self.monitor_mode:
                self.log(f"🔧 Enabling monitor mode on {interface}...", 'info')
                subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], capture_output=True)
                subprocess.run(['sudo', 'airmon-ng', 'start', interface], capture_output=True)
                
                self.monitor_mode = True
                self.monitor_btn.config(text="🛑 Disable Monitor", bg=self.colors['danger'])
                self.log(f"✅ Monitor mode enabled", 'success')
            else:
                self.log(f"🔧 Disabling monitor mode...", 'info')
                subprocess.run(['sudo', 'airmon-ng', 'stop', interface], capture_output=True)
                
                self.monitor_mode = False
                self.monitor_btn.config(text="🔧 Monitor Mode", bg=self.colors['warning'])
                self.log(f"✅ Monitor mode disabled", 'success')
            
            self.get_interfaces()
            self.update_system_info()
            
        except Exception as e:
            self.log(f"❌ Error toggling monitor mode: {str(e)}", 'error')
    
    # Placeholder methods for all buttons
    def quick_scan(self):
        self.log("🔍 Quick scan started...", 'info')
        self.start_normal_scan()
    
    def view_report(self):
        self.notebook.select(3)
        self.analysis_text.insert(tk.END, "\n")
        self.security_audit()

    def export_all(self):
        self.log("💾 Exporting all data (JSON)...", 'info')
        self.export_results('json')
    
    def clear_all_data(self):
        if messagebox.askyesno("Confirm", "Clear the networks table? (Database is not touched)"):
            self.tree.delete(*self.tree.get_children())
            self.networks = []
            self.log("🗑️ Table cleared", 'success')

    # ---------------------------------------------------------------
    # Real scanning (nmcli based – works without monitor mode / root)
    # ---------------------------------------------------------------
    @staticmethod
    def assess_risk(security, wps):
        """تقييم مستوى الخطورة بناءً على التشفير وحالة WPS

        يُرجع (risk_label, tree_tag)
        """
        sec = (security or '').upper()
        wps_on = str(wps).lower() in ('yes', 'on', 'true', '1', 'enabled')

        if sec == '' or 'OPEN' in sec or sec == '--' or sec == 'NONE':
            return 'HIGH (Open)', 'high_risk'
        if 'WEP' in sec:
            return 'HIGH (WEP)', 'high_risk'
        if wps_on:
            return 'MEDIUM (WPS)', 'medium_risk'
        if 'WPA3' in sec or 'SAE' in sec:
            return 'LOW', 'low_risk'
        if 'WPA2' in sec or 'WPA' in sec:
            return 'MEDIUM', 'medium_risk'
        return 'UNKNOWN', 'medium_risk'

    def start_normal_scan(self):
        if self.scanning:
            self.log("⚠️ A scan is already running", 'warning')
            return
        if subprocess.run(['which', 'nmcli'], capture_output=True).returncode != 0:
            self.log("❌ nmcli not found. Install NetworkManager to use the scanner.", 'error')
            messagebox.showerror("Error", "nmcli (NetworkManager) is required for scanning.")
            return

        self.scanning = True
        self.scan_start_time = time.time()
        self.update_status("Scanning networks...", 'scanning')
        self.log("🔍 Starting network scan (nmcli)...", 'scanning')
        try:
            self.progress.start(10)
        except Exception:
            pass

        thread = threading.Thread(target=self._run_nmcli_scan, daemon=True)
        thread.start()

    def _run_nmcli_scan(self):
        """تشغيل المسح في thread ثم تسليم النتائج للحلقة الرئيسية"""
        networks = []
        try:
            subprocess.run(['nmcli', 'dev', 'wifi', 'rescan'],
                           capture_output=True, timeout=30)
            result = subprocess.run(
                ['nmcli', '-t', '-f',
                 'SSID,BSSID,CHAN,SIGNAL,SECURITY,RATE', 'dev', 'wifi', 'list'],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                # nmcli -t escapes ':' inside BSSID as '\:' – split carefully.
                fields = re.split(r'(?<!\\):', line)
                fields = [f.replace('\\:', ':') for f in fields]
                if len(fields) < 5:
                    continue
                ssid = fields[0] or '<hidden>'
                bssid = fields[1]
                channel = fields[2]
                signal = fields[3]
                security = fields[4] or 'Open'
                rate = fields[5] if len(fields) > 5 else ''
                networks.append({
                    'ssid': ssid, 'bssid': bssid, 'channel': channel,
                    'signal': signal, 'security': security,
                    'wps': '', 'clients': '', 'speed': rate
                })
        except subprocess.TimeoutExpired:
            self.root.after(0, lambda: self.log("❌ Scan timed out", 'error'))
        except Exception as e:
            self.root.after(0, lambda err=str(e): self.log(f"❌ Scan error: {err}", 'error'))

        self.root.after(0, lambda: self._scan_complete(networks))

    def _scan_complete(self, networks):
        """تحديث الواجهة بعد انتهاء المسح (يعمل في الحلقة الرئيسية)"""
        self.scanning = False
        try:
            self.progress.stop()
        except Exception:
            pass

        self.tree.delete(*self.tree.get_children())
        self.networks = networks

        duration = int(time.time() - self.scan_start_time) if self.scan_start_time else 0
        scan_id = None
        try:
            scan_id = self.db.save_scan(self.interface.get() or 'nmcli',
                                        duration, len(networks))
        except Exception:
            pass

        for net in networks:
            risk, tag = self.assess_risk(net['security'], net['wps'])
            net['risk'] = risk
            self.tree.insert('', 'end', values=(
                net['ssid'], net['bssid'], net['channel'], net['signal'],
                net['security'], net['wps'] or '-', net['clients'] or '-',
                net['speed'] or '-', risk
            ), tags=(tag,))
            try:
                self.db.save_network(scan_id, net)
            except Exception:
                pass

        self.log(f"✅ Scan complete: {len(networks)} networks found", 'success')
        self.update_status(f"Found {len(networks)} networks", 'success')
        self.refresh_stats()

    def start_passive_scan(self):
        self.log("🕵️ Passive (airodump) scan requires monitor mode and root.", 'warning')
        if not self.monitor_mode:
            self.log("   Enable Monitor Mode first, then use this on an authorized network.", 'warning')
        # Falls back to the standard scan for discovery.
        self.start_normal_scan()

    def start_targeted_scan(self):
        if not self.selected_network:
            self.log("🎯 Select a target network in the table first.", 'warning')
            return
        self.log(f"🎯 Targeted scan on {self.selected_network.get('ssid')} "
                 f"({self.selected_network.get('bssid')})", 'scanning')
        self.start_normal_scan()

    def scan_hidden(self):
        self.log("🔍 Scanning (hidden networks appear as <hidden>)...", 'scanning')
        self.start_normal_scan()

    def stop_scan(self):
        self.scanning = False
        try:
            self.progress.stop()
        except Exception:
            pass
        self.log("🛑 Scan stopped", 'warning')
        self.update_status("Ready", 'info')

    def on_network_select(self, event):
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            values = self.tree.item(item)['values']
            self.selected_network = {
                'ssid': values[0],
                'bssid': values[1],
                'channel': values[2],
                'signal': values[3],
                'security': values[4],
                'wps': values[5] if len(values) > 5 else '',
                'risk': values[8] if len(values) > 8 else ''
            }
            self.log(f"✅ Selected network: {values[0]}", 'success')
            try:
                self.target_info_label.config(
                    text=f"SSID: {values[0]}\nBSSID: {values[1]}\n"
                         f"Channel: {values[2]}  Signal: {values[3]}\n"
                         f"Security: {values[4]}  Risk: {self.selected_network['risk']}"
                )
            except Exception:
                pass
    
    def show_network_details(self, event):
        if self.selected_network:
            details = "\n".join([f"{k}: {v}" for k, v in self.selected_network.items()])
            messagebox.showinfo("Network Details", details)
    
    # Attack methods (placeholders)
    def check_wps_advanced(self):
        self.log("🔍 Checking WPS status...", 'info')
    
    def wps_pixie_attack(self):
        self.log("⚡ Starting WPS Pixie Dust attack...", 'warning')
    
    def wps_bruteforce(self):
        self.log("🔨 Starting WPS brute force...", 'warning')
    
    def wps_null_pin(self):
        self.log("🎲 Trying WPS null PIN...", 'info')
    
    def start_handshake_capture(self):
        self.log("📡 Starting handshake capture...", 'info')
    
    def pmkid_attack(self):
        self.log("📊 Starting PMKID attack...", 'warning')
    
    def send_deauth_advanced(self):
        self.log("💥 Sending deauth packets...", 'warning')
    
    def stop_handshake_capture(self):
        self.log("🛑 Capture stopped", 'warning')
    
    def evil_twin_attack(self):
        self.log("👥 Starting Evil Twin attack...", 'danger')
    
    def phishing_ap(self):
        self.log("🎣 Setting up phishing AP...", 'danger')
    
    def mitm_attack(self):
        self.log("🔄 Setting up MITM attack...", 'danger')
    
    def dns_spoof(self):
        self.log("🌐 Starting DNS spoofing...", 'danger')
    
    # Analysis methods
    def _require_networks(self):
        if not self.networks:
            self.analysis_text.insert(tk.END,
                "⚠️ No scan data. Run a scan from the Scanner tab first.\n\n")
            self.analysis_text.see(tk.END)
            self.notebook.select(3)
            return False
        return True

    def signal_analysis(self):
        self.log("📊 Analyzing signal strength...", 'info')
        if not self._require_networks():
            return
        self.analysis_text.insert(tk.END, "═══ Signal Strength Analysis ═══\n")

        def sig_val(n):
            try:
                return int(re.sub(r'[^0-9-]', '', str(n['signal'])) or 0)
            except Exception:
                return 0

        for net in sorted(self.networks, key=sig_val, reverse=True):
            s = sig_val(net)
            bar = '█' * max(0, min(20, s // 5)) if s > 0 else ''
            self.analysis_text.insert(
                tk.END, f"{net['ssid'][:20]:<20} {str(net['signal']):>5}  {bar}\n")
        self.analysis_text.insert(tk.END, "\n")
        self.analysis_text.see(tk.END)

    def security_audit(self):
        self.log("🔒 Running security audit...", 'info')
        if not self._require_networks():
            return
        buckets = {'high_risk': [], 'medium_risk': [], 'low_risk': []}
        for net in self.networks:
            risk, tag = self.assess_risk(net['security'], net['wps'])
            buckets.setdefault(tag, []).append((net, risk))

        self.analysis_text.insert(tk.END, "═══ Security Audit ═══\n")
        labels = [('high_risk', '🔴 HIGH RISK'),
                  ('medium_risk', '🟡 MEDIUM RISK'),
                  ('low_risk', '🟢 LOW RISK')]
        total = len(self.networks)
        for tag, title in labels:
            items = buckets.get(tag, [])
            self.analysis_text.insert(tk.END, f"\n{title}  ({len(items)}/{total})\n")
            for net, risk in items:
                self.analysis_text.insert(
                    tk.END, f"  • {net['ssid'][:24]:<24} {net['security']:<18} [{risk}]\n")
        self.analysis_text.insert(
            tk.END, "\nRecommendation: upgrade Open/WEP networks to WPA2/WPA3 "
                    "and disable WPS where possible.\n\n")
        self.analysis_text.see(tk.END)

    def detect_evil_twins(self):
        self.log("👁️ Detecting Evil Twin APs...", 'info')
        if not self._require_networks():
            return
        ssid_map = defaultdict(list)
        for net in self.networks:
            if net['ssid'] and net['ssid'] != '<hidden>':
                ssid_map[net['ssid']].append(net)

        self.analysis_text.insert(tk.END, "═══ Evil Twin Detection ═══\n")
        found = False
        for ssid, nets in ssid_map.items():
            bssids = {n['bssid'] for n in nets}
            if len(bssids) > 1:
                found = True
                self.analysis_text.insert(
                    tk.END, f"\n⚠️ '{ssid}' advertised by {len(bssids)} BSSIDs:\n")
                for n in nets:
                    self.analysis_text.insert(
                        tk.END, f"    {n['bssid']}  ch {n['channel']}  "
                                f"{n['security']}  {n['signal']}\n")
        if not found:
            self.analysis_text.insert(
                tk.END, "✅ No duplicate SSIDs detected (note: multi-AP networks "
                        "can be legitimate).\n")
        self.analysis_text.insert(tk.END, "\n")
        self.analysis_text.see(tk.END)

    def channel_analysis(self):
        self.log("📈 Analyzing channel usage...", 'info')
        if not self._require_networks():
            return
        counts = defaultdict(int)
        for net in self.networks:
            counts[str(net['channel']) or '?'] += 1

        self.analysis_text.insert(tk.END, "═══ Channel Usage ═══\n")

        def ch_key(k):
            try:
                return int(k)
            except Exception:
                return 9999
        for ch in sorted(counts, key=ch_key):
            self.analysis_text.insert(
                tk.END, f"Channel {ch:>3}: {'▇' * counts[ch]} ({counts[ch]})\n")
        if counts:
            busiest = max(counts, key=counts.get)
            self.analysis_text.insert(
                tk.END, f"\nBusiest channel: {busiest}. For your own AP, prefer a "
                        f"less congested channel (1/6/11 on 2.4GHz).\n\n")
        self.analysis_text.see(tk.END)

    def generate_heatmap(self):
        self.log("🗺️ Signal heatmap needs matplotlib + location data.", 'info')
        self.signal_analysis()
    
    # Tools methods
    def generate_wordlist(self):
        self.log("📝 Generating custom wordlist...", 'info')
    
    def dictionary_attack(self):
        self.log("🔨 Starting dictionary attack...", 'warning')
    
    def rule_attack(self):
        self.log("🎲 Starting rule-based attack...", 'warning')
    
    def analyze_captures(self):
        self.log("📊 Analyzing capture files...", 'info')
    
    def monitor_traffic(self):
        self.log("📡 Monitoring traffic...", 'info')
    
    def port_scan(self):
        self.log("🔍 Scanning ports...", 'info')
    
    def geolocate_ap(self):
        self.log("🌍 Geolocating AP...", 'info')
    
    def bandwidth_test(self):
        self.log("📊 Testing bandwidth...", 'info')
    
    def export_results(self, format_type):
        if not self.networks:
            messagebox.showwarning("Export", "No scan results to export. Run a scan first.")
            return
        ext_map = {'csv': '.csv', 'json': '.json', 'html': '.html', 'pdf': '.html'}
        ext = ext_map.get(format_type, '.txt')
        if format_type == 'pdf':
            self.log("ℹ️ PDF export not available; exporting an HTML report instead.", 'warning')
            format_type = 'html'
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile=f"wifi_scan_{datetime.now():%Y%m%d_%H%M%S}{ext}",
            filetypes=[(format_type.upper(), f"*{ext}"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            if format_type == 'csv':
                with open(path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(
                        f, fieldnames=['ssid', 'bssid', 'channel', 'signal',
                                       'security', 'wps', 'speed', 'risk'])
                    writer.writeheader()
                    for net in self.networks:
                        writer.writerow({k: net.get(k, '') for k in writer.fieldnames})
            elif format_type == 'json':
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump({'generated': datetime.now().isoformat(),
                               'count': len(self.networks),
                               'networks': self.networks}, f,
                              indent=2, ensure_ascii=False)
            elif format_type == 'html':
                self._write_html_report(path)
            self.log(f"💾 Exported {len(self.networks)} networks to {path}", 'success')
            messagebox.showinfo("Export", f"Saved to:\n{path}")
        except Exception as e:
            self.log(f"❌ Export failed: {e}", 'error')
            messagebox.showerror("Export failed", str(e))

    def _write_html_report(self, path):
        rows = []
        for net in self.networks:
            risk = net.get('risk') or self.assess_risk(net['security'], net['wps'])[0]
            color = '#f85149' if 'HIGH' in risk else (
                '#d29922' if 'MEDIUM' in risk else '#3fb950')
            def esc(v):
                return (str(v).replace('&', '&amp;').replace('<', '&lt;')
                        .replace('>', '&gt;'))
            rows.append(
                f"<tr><td>{esc(net['ssid'])}</td><td>{esc(net['bssid'])}</td>"
                f"<td>{esc(net['channel'])}</td><td>{esc(net['signal'])}</td>"
                f"<td>{esc(net['security'])}</td>"
                f"<td style='color:{color};font-weight:bold'>{esc(risk)}</td></tr>")
        html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>WiFi Security Report</title>
<style>body{{font-family:Arial;background:#0d1117;color:#c9d1d9;padding:24px}}
h1{{color:#58a6ff}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #30363d;padding:8px;text-align:left}}
th{{background:#161b22}}</style></head><body>
<h1>🔒 WiFi Security Report</h1>
<p>Generated: {datetime.now():%Y-%m-%d %H:%M:%S} &middot; {len(self.networks)} networks</p>
<p style="color:#d29922">⚠️ For authorized security testing only.</p>
<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>Signal</th>
<th>Security</th><th>Risk</th></tr>{''.join(rows)}</table>
</body></html>"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)

    def view_history(self):
        self.log("📊 Loading scan history...", 'info')
        rows = self.db.get_recent_networks(100)
        self.notebook.select(3)
        self.analysis_text.insert(tk.END, "═══ Saved Networks (database) ═══\n")
        if not rows:
            self.analysis_text.insert(tk.END, "No saved networks yet.\n\n")
            return
        for ssid, bssid, channel, signal, security, wps, last_seen in rows:
            self.analysis_text.insert(
                tk.END, f"{(ssid or '<hidden>')[:22]:<22} {bssid:<18} "
                        f"ch{channel}  {security}  seen:{last_seen}\n")
        self.analysis_text.insert(tk.END, "\n")
        self.analysis_text.see(tk.END)

    def search_networks(self):
        from tkinter import simpledialog
        term = simpledialog.askstring("Search", "SSID or BSSID contains:")
        if not term:
            return
        rows = self.db.get_recent_networks(500)
        self.notebook.select(3)
        self.analysis_text.insert(tk.END, f"═══ Search: '{term}' ═══\n")
        matches = [r for r in rows if term.lower() in str(r[0]).lower()
                   or term.lower() in str(r[1]).lower()]
        for ssid, bssid, channel, signal, security, wps, last_seen in matches:
            self.analysis_text.insert(
                tk.END, f"{(ssid or '<hidden>')[:22]:<22} {bssid:<18} {security}\n")
        self.analysis_text.insert(tk.END, f"({len(matches)} match(es))\n\n")
        self.analysis_text.see(tk.END)

    def clean_database(self):
        if not messagebox.askyesno("Confirm", "Delete ALL saved scan data from the database?"):
            return
        try:
            conn = sqlite3.connect(self.db.db_path)
            cur = conn.cursor()
            for t in ('networks', 'scans', 'handshakes', 'vulnerabilities'):
                cur.execute(f'DELETE FROM {t}')
            conn.commit()
            conn.close()
            self.log("🗑️ Database cleaned", 'success')
            self.refresh_stats()
        except Exception as e:
            self.log(f"❌ Clean failed: {e}", 'error')

    def backup_database(self):
        path = filedialog.asksaveasfilename(
            defaultextension='.db',
            initialfile=f"wifi_backup_{datetime.now():%Y%m%d_%H%M%S}.db",
            filetypes=[("SQLite DB", "*.db"), ("All files", "*.*")])
        if not path:
            return
        try:
            import shutil
            shutil.copy2(self.db.db_path, path)
            self.log(f"💾 Database backed up to {path}", 'success')
        except Exception as e:
            self.log(f"❌ Backup failed: {e}", 'error')

    def generate_dashboard_charts(self):
        self.refresh_dashboard()
        self.log("📊 Dashboard refreshed", 'info')

    def refresh_dashboard(self):
        """تحديث لوحة المعلومات بأحدث البيانات"""
        try:
            self.recent_text.delete('1.0', tk.END)
            for row in self.db.get_recent_networks(20):
                ssid, bssid, channel, signal, security, wps, last_seen = row
                self.recent_text.insert(
                    tk.END, f"{(ssid or '<hidden>')[:18]:<18} {security:<16} {last_seen}\n")

            self.vulns_text.delete('1.0', tk.END)
            risky = [n for n in self.networks
                     if 'HIGH' in self.assess_risk(n['security'], n['wps'])[0]
                     or 'MEDIUM' in self.assess_risk(n['security'], n['wps'])[0]]
            if not risky:
                self.vulns_text.insert(tk.END, "No risky networks in last scan.\n")
            for n in risky:
                risk = self.assess_risk(n['security'], n['wps'])[0]
                self.vulns_text.insert(
                    tk.END, f"{n['ssid'][:18]:<18} {risk}\n")
        except Exception:
            pass

    def refresh_stats(self):
        """تحديث الإحصائيات في الهيدر من قاعدة البيانات"""
        self.stats = self.db.get_stats()
        mapping = {'scans': 'total_scans', 'networks': 'networks_found',
                   'vulns': 'vulnerabilities', 'handshakes': 'handshakes'}
        for key, stat_key in mapping.items():
            if key in self.stat_labels:
                self.stat_labels[key].config(text=str(self.stats.get(stat_key, 0)))
        self.refresh_dashboard()

    def load_stats(self):
        """تحميل الإحصائيات عند بدء التشغيل"""
        self.refresh_stats()

def main():
    """نقطة الدخول الرئيسية"""
    is_root = hasattr(os, 'geteuid') and os.geteuid() == 0
    if not is_root:
        print("=" * 80)
        print("⚠️  WARNING: Some features require root privileges")
        print("⚠️  تحذير: بعض المميزات تحتاج صلاحيات root")
        print("=" * 80)
        print("\nRecommended: sudo python3 wifi_security_tool_pro.py\n")
        print("=" * 80 + "\n")
        
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return
    
    root = tk.Tk()
    app = WiFiSecurityToolPro(root)
    root.mainloop()

if __name__ == "__main__":
    main()
