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
        
        # Check if network exists
        cursor.execute('SELECT id, times_seen FROM networks WHERE bssid = ?', 
                      (network_data['bssid'],))
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute(
                'UPDATE networks SET last_seen = CURRENT_TIMESTAMP, times_seen = ? WHERE bssid = ?',
                (existing[1] + 1, network_data['bssid'])
            )
        else:
            cursor.execute(
                '''INSERT INTO networks (scan_id, ssid, bssid, channel, signal, security, wps)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (scan_id, network_data['ssid'], network_data['bssid'], 
                 network_data['channel'], network_data['signal'], 
                 network_data['security'], network_data['wps'])
            )
        
        conn.commit()
        conn.close()
    
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
                    except:
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
        except:
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
        except:
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
        except:
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
        settings_card.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Settings options
        tk.Label(
            settings_card,
            text="Coming soon: Advanced configuration options",
            bg=self.colors['card_bg'],
            fg=self.colors['fg'],
            font=('Arial', 12)
        ).pack(pady=50)
    
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
        """معالج log متزامن"""
        def process_logs():
            while True:
                try:
                    msg, color = self.log_queue.get(timeout=0.1)
                    self.console_text.insert(tk.END, msg)
                    self.console_text.see(tk.END)
                except queue.Empty:
                    pass
                time.sleep(0.01)
        
        thread = threading.Thread(target=process_logs, daemon=True)
        thread.start()
    
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
        except:
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
        messagebox.showinfo("Report", "Report generation coming soon!")
    
    def export_all(self):
        self.log("💾 Exporting all data...", 'info')
    
    def clear_all_data(self):
        if messagebox.askyesno("Confirm", "Clear all data?"):
            self.tree.delete(*self.tree.get_children())
            self.log("🗑️ Data cleared", 'success')
    
    def start_normal_scan(self):
        self.log("🔍 Starting normal scan...", 'scanning')
        self.update_status("Scanning networks...", 'scanning')
        # Implement scanning logic
    
    def start_passive_scan(self):
        self.log("🕵️ Starting passive scan...", 'scanning')
    
    def start_targeted_scan(self):
        self.log("🎯 Starting targeted scan...", 'scanning')
    
    def scan_hidden(self):
        self.log("🔍 Scanning for hidden networks...", 'scanning')
    
    def stop_scan(self):
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
                'security': values[4]
            }
            self.log(f"✅ Selected network: {values[0]}", 'success')
    
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
    def signal_analysis(self):
        self.log("📊 Analyzing signal strength...", 'info')
    
    def security_audit(self):
        self.log("🔒 Running security audit...", 'info')
    
    def detect_evil_twins(self):
        self.log("👁️ Detecting Evil Twin APs...", 'info')
    
    def channel_analysis(self):
        self.log("📈 Analyzing channel usage...", 'info')
    
    def generate_heatmap(self):
        self.log("🗺️ Generating signal heatmap...", 'info')
    
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
        self.log(f"💾 Exporting as {format_type.upper()}...", 'success')
    
    def view_history(self):
        self.log("📊 Loading scan history...", 'info')
    
    def search_networks(self):
        self.log("🔍 Searching database...", 'info')
    
    def clean_database(self):
        self.log("🗑️ Cleaning database...", 'warning')
    
    def backup_database(self):
        self.log("💾 Backing up database...", 'success')
    
    def generate_dashboard_charts(self):
        self.log("📊 Generating dashboard charts...", 'info')
    
    def load_stats(self):
        """تحميل الإحصائيات"""
        # Load from database
        pass

def main():
    """نقطة الدخول الرئيسية"""
    if os.geteuid() != 0:
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
