#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة اختبار أمان شبكات الواي فاي
WiFi Security Testing Tool
تحذير: استخدم هذه الأداة فقط على شبكاتك الخاصة أو بإذن صريح
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import re
import os

class WiFiSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("أداة اختبار أمان الواي فاي - WiFi Security Tool")
        self.root.geometry("900x700")
        self.root.configure(bg='#2c3e50')
        
        self.scanning = False
        self.monitor_mode = False
        self.interface = tk.StringVar()
        self.networks = []
        
        self.setup_ui()
        self.check_requirements()
        
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg='#34495e', height=80)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        title_label = tk.Label(
            header_frame, 
            text="🔒 أداة اختبار أمان الواي فاي",
            font=('Arial', 20, 'bold'),
            bg='#34495e',
            fg='white'
        )
        title_label.pack(pady=10)
        
        warning_label = tk.Label(
            header_frame,
            text="⚠️ تحذير: استخدم فقط على شبكاتك الخاصة",
            font=('Arial', 10),
            bg='#34495e',
            fg='#e74c3c'
        )
        warning_label.pack()
        
        # Interface Selection Frame
        interface_frame = tk.LabelFrame(
            self.root,
            text="اختيار واجهة الشبكة - Network Interface",
            font=('Arial', 12, 'bold'),
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
            text="تحديث الواجهات - Refresh",
            command=self.get_interfaces,
            bg='#3498db',
            fg='white',
            font=('Arial', 9, 'bold'),
            relief='raised',
            cursor='hand2'
        ).grid(row=0, column=2, padx=5)
        
        tk.Button(
            interface_frame,
            text="تفعيل Monitor Mode",
            command=self.toggle_monitor_mode,
            bg='#e67e22',
            fg='white',
            font=('Arial', 9, 'bold'),
            relief='raised',
            cursor='hand2'
        ).grid(row=0, column=3, padx=5)
        
        # Control Frame
        control_frame = tk.Frame(self.root, bg='#2c3e50')
        control_frame.pack(fill='x', padx=10, pady=5)
        
        self.scan_button = tk.Button(
            control_frame,
            text="🔍 فحص الشبكات - Scan Networks",
            command=self.start_scan,
            bg='#27ae60',
            fg='white',
            font=('Arial', 11, 'bold'),
            width=25,
            height=2,
            relief='raised',
            cursor='hand2'
        )
        self.scan_button.pack(side='left', padx=5)
        
        tk.Button(
            control_frame,
            text="🛑 إيقاف - Stop",
            command=self.stop_scan,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 11, 'bold'),
            width=15,
            height=2,
            relief='raised',
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        tk.Button(
            control_frame,
            text="🗑️ مسح - Clear",
            command=self.clear_output,
            bg='#95a5a6',
            fg='white',
            font=('Arial', 11, 'bold'),
            width=15,
            height=2,
            relief='raised',
            cursor='hand2'
        ).pack(side='left', padx=5)
        
        # Networks List Frame
        networks_frame = tk.LabelFrame(
            self.root,
            text="الشبكات المكتشفة - Discovered Networks",
            font=('Arial', 12, 'bold'),
            bg='#34495e',
            fg='white',
            padx=10,
            pady=10
        )
        networks_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Treeview for networks
        columns = ('SSID', 'BSSID', 'Channel', 'Signal', 'Security')
        self.tree = ttk.Treeview(networks_frame, columns=columns, show='headings', height=10)
        
        self.tree.heading('SSID', text='اسم الشبكة - SSID')
        self.tree.heading('BSSID', text='BSSID')
        self.tree.heading('Channel', text='القناة - Channel')
        self.tree.heading('Signal', text='الإشارة - Signal')
        self.tree.heading('Security', text='الحماية - Security')
        
        self.tree.column('SSID', width=150)
        self.tree.column('BSSID', width=150)
        self.tree.column('Channel', width=80)
        self.tree.column('Signal', width=80)
        self.tree.column('Security', width=120)
        
        scrollbar = ttk.Scrollbar(networks_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Output Frame
        output_frame = tk.LabelFrame(
            self.root,
            text="النتائج والسجلات - Output & Logs",
            font=('Arial', 12, 'bold'),
            bg='#34495e',
            fg='white',
            padx=10,
            pady=10
        )
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            width=80,
            height=10,
            bg='#1c2833',
            fg='#2ecc71',
            font=('Courier', 9),
            insertbackground='white'
        )
        self.output_text.pack(fill='both', expand=True)
        
        # Status Bar
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
        
    def check_requirements(self):
        """Check if required tools are installed"""
        self.log("جاري فحص الأدوات المطلوبة...")
        self.log("Checking required tools...")
        
        tools = ['airmon-ng', 'airodump-ng', 'iwconfig', 'nmcli']
        missing_tools = []
        
        for tool in tools:
            result = subprocess.run(['which', tool], capture_output=True, text=True)
            if result.returncode != 0:
                missing_tools.append(tool)
                
        if missing_tools:
            self.log(f"⚠️ الأدوات المفقودة - Missing tools: {', '.join(missing_tools)}")
            self.log("تحتاج لتثبيت aircrack-ng suite")
            self.log("You need to install aircrack-ng suite")
        else:
            self.log("✅ جميع الأدوات متوفرة - All tools available")
            
        self.get_interfaces()
        
    def get_interfaces(self):
        """Get available network interfaces"""
        try:
            result = subprocess.run(
                ['iwconfig'],
                capture_output=True,
                text=True,
                stderr=subprocess.STDOUT
            )
            
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line or 'ESSID' in line:
                    interface = line.split()[0]
                    if interface:
                        interfaces.append(interface)
            
            # Also try ip link
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
                self.log(f"✅ تم العثور على الواجهات - Found interfaces: {', '.join(interfaces)}")
            else:
                self.log("⚠️ لم يتم العثور على واجهات واي فاي - No WiFi interfaces found")
                
        except Exception as e:
            self.log(f"❌ خطأ في الحصول على الواجهات - Error: {str(e)}")
            
    def toggle_monitor_mode(self):
        """Toggle monitor mode on the selected interface"""
        if not self.interface.get():
            messagebox.showerror("خطأ - Error", "اختر واجهة الشبكة أولاً\nPlease select an interface first")
            return
            
        interface = self.interface.get()
        
        try:
            if not self.monitor_mode:
                self.log(f"🔧 تفعيل Monitor Mode على - Enabling monitor mode on {interface}")
                subprocess.run(['sudo', 'airmon-ng', 'start', interface], check=True)
                self.monitor_mode = True
                self.log(f"✅ تم تفعيل Monitor Mode - Monitor mode enabled")
            else:
                self.log(f"🔧 إيقاف Monitor Mode على - Disabling monitor mode on {interface}")
                subprocess.run(['sudo', 'airmon-ng', 'stop', interface], check=True)
                self.monitor_mode = False
                self.log(f"✅ تم إيقاف Monitor Mode - Monitor mode disabled")
                
            self.get_interfaces()
            
        except subprocess.CalledProcessError as e:
            self.log(f"❌ خطأ: تحتاج صلاحيات root - Error: Need root privileges")
            messagebox.showerror("خطأ - Error", "تحتاج لتشغيل الأداة بصلاحيات sudo\nYou need to run with sudo privileges")
            
    def start_scan(self):
        """Start scanning for networks"""
        if not self.interface.get():
            messagebox.showerror("خطأ - Error", "اختر واجهة الشبكة أولاً\nPlease select an interface first")
            return
            
        if self.scanning:
            self.log("⚠️ الفحص قيد التشغيل بالفعل - Scan already running")
            return
            
        self.scanning = True
        self.scan_button.config(state='disabled')
        self.tree.delete(*self.tree.get_children())
        
        thread = threading.Thread(target=self.scan_networks, daemon=True)
        thread.start()
        
    def scan_networks(self):
        """Scan for available networks"""
        interface = self.interface.get()
        self.log(f"🔍 بدء فحص الشبكات على - Starting scan on {interface}")
        self.update_status("جاري الفحص... - Scanning...")
        
        try:
            # Using nmcli for scanning (works without monitor mode)
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY', 'dev', 'wifi', 'list'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            networks_found = 0
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(':')
                    if len(parts) >= 5:
                        ssid = parts[0] if parts[0] else '(Hidden)'
                        bssid = parts[1]
                        channel = parts[2]
                        signal = parts[3]
                        security = parts[4]
                        
                        self.tree.insert('', 'end', values=(ssid, bssid, channel, signal, security))
                        networks_found += 1
                        
            self.log(f"✅ تم العثور على {networks_found} شبكة - Found {networks_found} networks")
            
        except subprocess.TimeoutExpired:
            self.log("⏱️ انتهت مهلة الفحص - Scan timeout")
        except Exception as e:
            self.log(f"❌ خطأ في الفحص - Scan error: {str(e)}")
            
        self.scanning = False
        self.scan_button.config(state='normal')
        self.update_status("جاهز - Ready")
        
    def stop_scan(self):
        """Stop scanning"""
        self.scanning = False
        self.log("🛑 تم إيقاف الفحص - Scan stopped")
        self.update_status("تم الإيقاف - Stopped")
        
    def clear_output(self):
        """Clear output text"""
        self.output_text.delete('1.0', tk.END)
        self.tree.delete(*self.tree.get_children())
        
    def log(self, message):
        """Log message to output"""
        self.output_text.insert(tk.END, f"{message}\n")
        self.output_text.see(tk.END)
        
    def update_status(self, message):
        """Update status bar"""
        self.status_bar.config(text=message)

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠️ تحذير: بعض المميزات تحتاج صلاحيات root")
        print("⚠️ Warning: Some features require root privileges")
        print("يُنصح بالتشغيل باستخدام: sudo python3 wifi_security_tool.py")
        print("Recommended to run with: sudo python3 wifi_security_tool.py")
        print()
        
    root = tk.Tk()
    app = WiFiSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
