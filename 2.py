
import os
import re
import difflib
import hashlib
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.scrolledtext as stx
from datetime import datetime
import xml.etree.ElementTree as ET
import pefile
import numpy as np
from sklearn.ensemble import IsolationForest
import capstone
import lief

# ======================== CONFIGURATION ========================
OUTPUT_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "output")
HASH_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "Hashes")
FINDINGS_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "Findings")
TARGET_PROCS = {"HD-Player.exe", "Bluestacks.exe", "HD-Adb.exe", "GameLoop.exe"}
ANOMALY_THRESHOLD = -0.65
SUSPICIOUS_IMPORTS = {"NtMapViewOfSection", "ZwProtectVirtualMemory", "PsCreateSystemThread"}

class ForensicCore:
    def __init__(self):
        self.parsed_data = {}
        self.findings = []
        self.error_queue = queue.Queue()
        self.output_dir = OUTPUT_DIR
        self.hash_dir = HASH_DIR
        self.findings_dir = FINDINGS_DIR
        self._init_directories()
        self.hash_baseline = self._load_hash_baseline()
        self.anomaly_detector = IsolationForest(n_estimators=100, contamination=0.01)
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._train_anomaly_model()

    def _init_directories(self):
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.hash_dir, exist_ok=True)
        os.makedirs(self.findings_dir, exist_ok=True)

    def _load_hash_baseline(self):
        baseline = {}
        try:
            for file in os.listdir(self.hash_dir):
                if file.endswith('.txt'):
                    with open(os.path.join(self.hash_dir, file), 'r') as f:
                        baseline[file[:-4]] = f.read().strip()
        except Exception as e:
            self.error_queue.put(f"Hash Load Error: {str(e)}")
        return baseline

    def _parse_vad_entry(self, line):
        elements = line.split()
        return {
            'Process': elements[1] if len(elements) > 1 else '',
            'Start': elements[3] if len(elements) > 3 else '',
            'End': elements[5] if len(elements) > 5 else '',
            'Protection': elements[7] if len(elements) > 7 else '',
            'HexDump': ' '.join(elements[8:]) if len(elements) > 8 else ''
        }

    def _parse_handle_entry(self, line):
        match = re.match(r".*PID:\s+(\d+).*Type:\s+(\w+).*Name:\s+(.*)", line)
        return {
            'PID': match.group(1) if match else '',
            'Type': match.group(2) if match else '',
            'Name': match.group(3) if match else ''
        } if match else {}

    def _parse_dynamic_file(self, real_file):
        entries = []
        try:
            with open(real_file, 'r', errors='ignore') as f:
                for line in f:
                    entry = {"Data": line.strip()}
                    if "vadinfo" in real_file:
                        entry.update(self._parse_vad_entry(line))
                    elif "handles" in real_file:
                        entry.update(self._parse_handle_entry(line))
                    entries.append(entry)
                    self.error_queue.put(f"LOADED: {os.path.basename(real_file)}")
        except Exception as e:
            self.error_queue.put(f"PARSE ERROR: {str(e)}")
        return entries

    def load_data(self):
        self.parsed_data.clear()
        for file in os.listdir(self.output_dir):
            if file.endswith('.txt'):
                real_file = os.path.join(self.output_dir, file)
                key_name = file.replace(".txt", "")
                self.parsed_data[key_name] = self._parse_dynamic_file(real_file)

    def create_hash_file(self, filepath):
        try:
            filename = os.path.basename(filepath)
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            with open(os.path.join(self.hash_dir, f"{filename}.txt"), 'w') as f:
                f.write(file_hash)
            self.hash_baseline[filename] = file_hash
            return True
        except Exception as e:
            self.error_queue.put(f"Hash creation failed: {str(e)}")
            return False

    def _train_anomaly_model(self):
        dummy_data = np.random.rand(100, 4)
        self.anomaly_detector.fit(dummy_data)

    def _add_finding(self, title, reason, severity, category):
        self.findings.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "title": title,
            "reason": reason,
            "severity": severity,
            "category": category
        })

    def check_file_integrity(self):
        self.findings.clear()
        for key in self.parsed_data:
            for entry in self.parsed_data[key]:
                data = entry.get('Data', '')
                if data.startswith("File:"):
                    filename = data.split(":", 1)[-1].strip()
                    if filename in self.hash_baseline:
                        with open(filename, 'rb') as f:
                            current_hash = hashlib.sha256(f.read()).hexdigest()
                        if current_hash != self.hash_baseline[filename]:
                            self._add_finding(
                                title=f"Modified File: {filename}",
                                reason="Hash mismatch detected",
                                severity="Critical",
                                category="Integrity"
                            )

    def detect_hidden_drivers(self):
        self.findings.clear()
        driver_list = [entry.get('Data', '') for entry in self.parsed_data.get('windows_driverscan', [])]
        module_list = [entry.get('Data', '') for entry in self.parsed_data.get('windows_modscan', [])]
        hidden = set(driver_list) - set(module_list)
        for driver in hidden:
            self._add_finding(
                title=f"Hidden Driver: {driver}",
                reason="Present in driverscan but missing in modscan",
                severity="High",
                category="Stealth"
            )

    def detect_injected_memory(self):
        self.findings.clear()
        for entry in self.parsed_data.get('windows_malfind', []):
            if 'RWX' in entry.get('Data', ''):
                self._add_finding(
                    title="Memory Injection Detected",
                    reason=entry.get('Data', ''),
                    severity="Critical",
                    category="Injection"
                )

    def detect_orphan_processes(self):
        self.findings.clear()
        pslist = [entry.get('Data', '') for entry in self.parsed_data.get('windows_pslist', [])]
        psscan = [entry.get('Data', '') for entry in self.parsed_data.get('windows_psscan', [])]
        for proc in psscan:
            if not any(proc in p for p in pslist):
                self._add_finding(
                    title=f"Orphan Process: {proc}",
                    reason="Present in psscan but missing in pslist",
                    severity="High",
                    category="Stealth"
                )

    def detect_hotkey_triggers(self):
        self.findings.clear()
        hotkey_patterns = [r'VK_\w+', r'KEY_\d+', r'0x[0-9A-F]{2}']
        for entry in self.parsed_data.get('windows_pslist', []):
            proc_name = entry.get('Data', '')
            if any(re.search(p, proc_name, re.IGNORECASE) for p in hotkey_patterns):
                self._add_finding(
                    title=f"Hotkey Process: {proc_name}",
                    reason="Name suggests hotkey trigger usage",
                    severity="Medium",
                    category="Triggers"
                )

    def detect_suspicious_services(self):
        self.findings.clear()
        for entry in self.parsed_data.get('windows_svcscan', []):
            data = entry.get('Data', '')
            if "SERVICE_RUNNING" in data and "MissingBinary" in data:
                self._add_finding(
                    title="Ghost Service Detected",
                    reason=data,
                    severity="High",
                    category="Persistence"
                )

    def detect_manual_mapping(self):
        self.findings.clear()
        self._analyze_driver_discrepancies()
        self._scan_memory_anomalies()
        self._validate_module_handles()
        self._check_binary_entropy()
        self._detect_code_injection()
        self._analyze_import_tables()
        self._check_cross_process_hooks()

    def _analyze_driver_discrepancies(self):
        drivers = {e['Data'] for e in self.parsed_data.get('windows_driverscan', [])}
        modules = {e['Data'] for e in self.parsed_data.get('windows_modscan', [])}
        for driver in drivers - modules:
            self._add_finding(
                title=f"Unlinked Driver: {driver}",
                reason="Driver present but missing from module list",
                severity="Critical",
                category="KernelStealth"
            )

    def _scan_memory_anomalies(self):
        vad_features = []
        for entry in self.parsed_data.get('windows_vadinfo', []):
            if any(p in entry.get('Process', '') for p in TARGET_PROCS):
                features = [
                    len(entry.get('HexDump', '')),
                    entry.get('Protection', '').count('EXECUTE'),
                    entry.get('Protection', '').count('WRITE'),
                    int(entry.get('End', 0)) - int(entry.get('Start', 0))
                ]
                vad_features.append(features)
        
        if vad_features:
            anomalies = self.anomaly_detector.decision_function(vad_features)
            for idx, score in enumerate(anomalies):
                if score < ANOMALY_THRESHOLD:
                    self._add_finding(
                        title="Memory Anomaly Detected",
                        reason=f"ML anomaly score {score:.2f} in process memory",
                        severity="Critical",
                        category="AI/ML Detection"
                    )

    def _validate_module_handles(self):
        handle_map = {}
        for entry in self.parsed_data.get('windows_handles', []):
            if entry.get('Type') == 'File':
                proc = entry.get('Process', '')
                handle_map.setdefault(proc, set()).add(entry.get('Name', ''))
        
        modules = {e['Data'] for e in self.parsed_data.get('windows_modscan', [])}
        for proc, handles in handle_map.items():
            if any(p in proc for p in TARGET_PROCS):
                for handle in handles:
                    if handle.endswith(('.sys', '.dll')) and handle not in modules:
                        self._add_finding(
                            title="Ghost Module Handle",
                            reason=f"{proc} accessing unloaded module: {handle}",
                            severity="High",
                            category="HandleAnalysis"
                        )

    def _check_binary_entropy(self):
        for entry in self.parsed_data.get('windows_modscan', []):
            mod_path = entry.get('Data', '')
            if os.path.exists(mod_path):
                entropy = self._calculate_entropy(mod_path)
                if entropy > 7.2 and not self._verify_digital_signature(mod_path):
                    self._add_finding(
                        title="Packed Binary Detected",
                        reason=f"High entropy ({entropy:.2f}) in {os.path.basename(mod_path)}",
                        severity="High",
                        category="BinaryAnalysis"
                    )

    def _detect_code_injection(self):
        for entry in self.parsed_data.get('windows_malfind', []):
            if "RWX" in entry.get('Data', '') and any(p in entry.get('Data', '') for p in TARGET_PROCS):
                hexdump = entry.get('HexDump', '')
                if hexdump:
                    code = bytes.fromhex(hexdump)
                    disasm = list(self.cs.disasm(code, 0x1000))
                    syscalls = sum(1 for i in disasm if i.mnemonic == 'syscall')
                    if syscalls > 3:
                        self._add_finding(
                            title="Direct Syscall Injection",
                            reason=f"{syscalls} raw syscalls in game process memory",
                            severity="Critical",
                            category="CodeInjection"
                        )

    def _analyze_import_tables(self):
        for entry in self.parsed_data.get('windows_dlllist', []):
            proc_info = entry.get('Data', '')
            if any(p in proc_info for p in TARGET_PROCS):
                match = re.search(r"Base\s+(0x[\da-fA-F]+)", proc_info)
                if match:
                    imports = re.findall(r"(0x[\da-fA-F]+)\s+([\w\.]+)", proc_info)
                    suspicious = [imp[1] for imp in imports if imp[1] in SUSPICIOUS_IMPORTS]
                    if suspicious:
                        self._add_finding(
                            title="Suspicious Imports",
                            reason=f"Found {len(suspicious)} risky imports in process",
                            severity="High",
                            category="ImportAnalysis"
                        )

    def _check_cross_process_hooks(self):
        handle_types = {}
        for entry in self.parsed_data.get('windows_handles', []):
            proc = entry.get('Process', '')
            handle_types.setdefault(proc, set()).add(entry.get('Type', ''))
        
        for proc, types in handle_types.items():
            if "Process" in types and "Thread" in types and any(p in proc for p in TARGET_PROCS):
                self._add_finding(
                    title="Cross-Process Manipulation",
                    reason=f"Suspicious handle types in {proc}",
                    severity="High",
                    category="ProcessHollowing"
                )

    def _calculate_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024*1024)
                if not data:
                    return 0
                counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
                probabilities = counts / len(data)
                return -np.sum(probabilities * np.log2(probabilities + 1e-10))
        except:
            return 0

    def _verify_digital_signature(self, file_path):
        try:
            binary = lief.parse(file_path)
            if not binary or not binary.has_signature:
                return False
            return binary.signature.check()
        except:
            return False

    def run_full_analysis(self):
        self.findings.clear()
        self.check_file_integrity()
        self.detect_hidden_drivers()
        self.detect_injected_memory()
        self.detect_orphan_processes()
        self.detect_hotkey_triggers()
        self.detect_suspicious_services()
        self.detect_manual_mapping()

class ForensicUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.core = ForensicCore()
        self._setup_ui()
        self.after(100, self._check_errors)

    def _setup_ui(self):
        self.title("DRAXOR FT HELPER -Forensic Platform")
        self.geometry("1600x950")
        self.configure(bg="#0d1116")

        # Control Panel
        control_frame = ttk.Frame(self)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(control_frame, text="📂 Load Memory Data", command=self.threaded_load).pack(side=tk.LEFT)
        ttk.Button(control_frame, text="🛡️ Create Hash File", command=self.create_hash).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🔍 Full Analysis", command=self.threaded_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="📤 Export Reports", command=self.export_reports).pack(side=tk.RIGHT)

        # Main Analysis Area
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Left Panel - Detection Modules
        modules_frame = ttk.LabelFrame(main_frame, text="Tactical Detection Suite")
        modules_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        self.module_buttons = [
            ("Integrity Check", self.run_check_file_integrity),
            ("Driver Analysis", self.run_detect_hidden_drivers),
            ("Memory Forensics", self.run_detect_injected_memory),
            ("Process Analysis", self.run_detect_orphan_processes),
            ("Hotkey Scan", self.run_detect_hotkey_triggers),
            ("Service Audit", self.run_detect_suspicious_services),
            ("Advanced Mapping", self.run_detect_manual_mapping),
            ("Full Spectrum Scan", self.threaded_scan)
        ]

        for text, cmd in self.module_buttons:
            btn = ttk.Button(modules_frame, text=text, command=cmd, width=22)
            btn.pack(padx=5, pady=3)

        # Center Panel - Findings Console
        findings_frame = ttk.LabelFrame(main_frame, text="Tactical Findings Console")
        findings_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.findings_console = stx.ScrolledText(findings_frame, height=25, width=80, 
                                               bg="#000022", fg="white", 
                                               font=("Consolas", 10), insertbackground="white")
        self.findings_console.pack(fill=tk.BOTH, expand=True)
        self.findings_console.tag_config("CRITICAL", foreground="#ff0000")
        self.findings_console.tag_config("HIGH", foreground="#ff6600")
        self.findings_console.tag_config("MEDIUM", foreground="#ffff00")
        self.findings_console.configure(state="disabled")

        # Right Panel - Live Operations Console
        console_frame = ttk.LabelFrame(main_frame, text="Live Operations Console")
        console_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.live_console = stx.ScrolledText(console_frame, height=25, width=80, 
                                           bg="#001100", fg="#00ff00", 
                                           font=("Consolas", 10), insertbackground="#00ff00")
        self.live_console.pack(fill=tk.BOTH, expand=True)
        self.live_console.tag_config("INFO", foreground="#00ffff")
        self.live_console.tag_config("SUCCESS", foreground="#00ff00")
        self.live_console.tag_config("WARNING", foreground="#ffff00")
        self.live_console.tag_config("ERROR", foreground="#ff0000")
        self.live_console.configure(state="disabled")

        # Status Bar
        self.status = ttk.Label(self, text="System Status: Operational", 
                              relief=tk.SUNKEN, anchor=tk.W)
        self.status.pack(fill=tk.X, side=tk.BOTTOM)

    def log(self, message, level="INFO"):
        def update_console():
            self.live_console.configure(state="normal")
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            self.live_console.insert(tk.END, f"[{timestamp}] {message}\n", level)
            self.live_console.configure(state="disabled")
            self.live_console.see(tk.END)
        self.after(0, update_console)

    def log_finding(self, finding):
        def update_findings():
            self.findings_console.configure(state="normal")
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.findings_console.insert(tk.END, 
                f"[{timestamp}] [{finding['severity']}] {finding['title']}\n"
                f"     Reason: {finding['reason']}\n"
                f"     Category: {finding['category']}\n"
                f"{'-'*80}\n",
                finding['severity'])
            self.findings_console.configure(state="disabled")
            self.findings_console.see(tk.END)
        self.after(0, update_findings)

    def threaded_load(self):
        self.status.config(text="Loading memory artifacts...")
        threading.Thread(target=self._load_memory_data).start()

    def _load_memory_data(self):
        self.core.load_data()
        self.log("Memory artifacts loaded successfully", "SUCCESS")
        self.after(500, self._update_status)
        self.after(100, self._process_live_updates)

    def threaded_scan(self):
        self.status.config(text="Executing full tactical scan...")
        threading.Thread(target=self._run_full_analysis).start()

    def _run_full_analysis(self):
        self.core.run_full_analysis()
        self.log("Full tactical scan completed", "SUCCESS")
        self.after(500, self._update_findings)

    def run_check_file_integrity(self):
        threading.Thread(target=self._run_and_update, args=(self.core.check_file_integrity, "Running file integrity check...")).start()

    def run_detect_hidden_drivers(self):
        threading.Thread(target=self._run_and_update, args=(self.core.detect_hidden_drivers, "Detecting hidden drivers...")).start()

    def run_detect_injected_memory(self):
        threading.Thread(target=self._run_and_update, args=(self.core.detect_injected_memory, "Analyzing memory injections...")).start()

    def run_detect_orphan_processes(self):
        threading.Thread(target=self._run_and_update, args=(self.core.detect_orphan_processes, "Finding orphan processes...")).start()

    def run_detect_hotkey_triggers(self):
        threading.Thread(target=self._run_and_update, args=(self.core.detect_hotkey_triggers, "Scanning for hotkey triggers...")).start()

    def run_detect_suspicious_services(self):
        threading.Thread(target=self._run_and_update, args=(self.core.detect_suspicious_services, "Auditing services...")).start()

    def run_detect_manual_mapping(self):
        threading.Thread(target=self._run_and_update, args=(self.core.detect_manual_mapping, "Detecting manual mapping...")).start()

    def _run_and_update(self, func, message):
        self.log(message, "INFO")
        func()
        self.log(f"{message} Completed", "SUCCESS")
        self.after(500, self._update_findings)

    def _update_findings(self):
        self.findings_console.configure(state="normal")
        self.findings_console.delete(1.0, tk.END)
        for finding in self.core.findings:
            self.log_finding(finding)
        self.findings_console.configure(state="disabled")
        self.status.config(text=f"Tactical findings: {len(self.core.findings)} critical items")

    def _process_live_updates(self):
        while not self.core.error_queue.empty():
            try:
                msg = self.core.error_queue.get_nowait()
                if msg.startswith("LOADED: "):
                    self.log(f"Artifact loaded: {msg[8:]}", "SUCCESS")
                elif msg.startswith("PARSE ERROR: "):
                    self.log(msg, "ERROR")
                else:
                    self.log(msg, "WARNING")
            except queue.Empty:
                break
        self.after(100, self._process_live_updates)

    def create_hash(self):
        filepath = filedialog.askopenfilename(title="Select File for Hashing")
        if filepath and self.core.create_hash_file(filepath):
            messagebox.showinfo("Hash Created", "Digital fingerprint stored successfully")
            self.log(f"Created hash for {os.path.basename(filepath)}", "INFO")

    def export_reports(self):
        if not self.core.findings:
            messagebox.showwarning("No Data", "No findings to export")
            return

        xml_root = ET.Element("TacticalFindings")
        for finding in self.core.findings:
            entry = ET.SubElement(xml_root, "Finding")
            ET.SubElement(entry, "Timestamp").text = finding['timestamp']
            ET.SubElement(entry, "Severity").text = finding['severity']
            ET.SubElement(entry, "Title").text = finding['title']
            ET.SubElement(entry, "Details").text = finding['reason']
            ET.SubElement(entry, "Category").text = finding['category']
        ET.ElementTree(xml_root).write(os.path.join(self.core.findings_dir, "tactical_report.xml"))

        with open(os.path.join(self.core.findings_dir, "tactical_summary.txt"), 'w') as f:
            f.write("=== DRAXOR TACTICAL FORENSIC REPORT ===\n\n")
            for finding in self.core.findings:
                f.write(f"[{finding['severity']}] {finding['title']}\n")
                f.write(f"Time: {finding['timestamp']}\n")
                f.write(f"Category: {finding['category']}\n")
                f.write(f"Details: {finding['reason']}\n")
                f.write("-"*80 + "\n")

        self.log("Reports exported to Findings directory", "INFO")
        messagebox.showinfo("Export Complete", "Tactical reports generated successfully")

    def _check_errors(self):
        while not self.core.error_queue.empty():
            try:
                error = self.core.error_queue.get_nowait()
                self.log(error, "ERROR")
                messagebox.showerror("System Error", error)
            except queue.Empty:
                break
        self.after(100, self._check_errors)

    def _update_status(self):
        total_entries = sum(len(v) for v in self.core.parsed_data.values())
        self.status.config(text=f"Operational Status: Loaded {total_entries} memory artifacts")
        self.log(f"Memory artifact database updated ({total_entries} entries)", "INFO")

if __name__ == "__main__":
    app = ForensicUI()
    app.mainloop()


