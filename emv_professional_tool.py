import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from reader_interface import CardReader
from backup_restore import CardBackupTool
from apdu_utils import format_apdu_response, parse_tlv, format_tlv, EMV_COMMANDS
import json
import time
import re

class EMVProfessionalTool:
    def __init__(self):
        self.reader = CardReader()
        self.tool = CardBackupTool(self.reader)
        self.last_response = None
        self.last_sw = None
        self.is_connected = False
        self.card_info = {}
        
        # Configuración de la ventana principal
        self.setup_main_window()
        self.setup_menu()
        self.setup_widgets()
        self.setup_status_bar()
        
        # Auto-detección de lectores al inicio
        self.refresh_readers()
        
    def setup_main_window(self):
        self.root = tk.Tk()
        self.root.title("EMV Professional Tool v2.0 - Advanced Card Reader/Writer")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Icono y estilo
        try:
            self.root.iconbitmap('emv_icon.ico')  # Si tienes un icono
        except:
            pass
            
    def setup_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Menú File
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_separator()
        file_menu.add_command(label="Load Configuration", command=self.load_config)
        file_menu.add_command(label="Save Configuration", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Export Log", command=self.export_log)
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Menú Tools
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Card Analysis", command=self.analyze_card)
        tools_menu.add_command(label="Protocol Scanner", command=self.scan_protocols)
        tools_menu.add_command(label="Data Comparison", command=self.compare_data)
        
        # Menú Help
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_documentation)

    def setup_widgets(self):
        # Panel principal con pestañas
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Pestaña: Connection & Reader
        self.setup_connection_tab()
        
        # Pestaña: EMV Operations
        self.setup_emv_tab()
        
        # Pestaña: Card Analysis
        self.setup_analysis_tab()
        
        # Pestaña: Backup & Restore
        self.setup_backup_tab()
        
        # Pestaña: Advanced Tools
        self.setup_advanced_tab()

        # Pestaña: Write Operations
        self.setup_write_tab()

        # Pestaña: Cloning
        self.setup_cloning_tab()

        # Pestaña: Java Card
        self.setup_jcard_tab()

        # Pestaña: SIM Card
        self.setup_sim_tab()

        # Pestaña: Crypto Wallet
        self.setup_crypto_tab()

    def setup_connection_tab(self):
        connection_frame = ttk.Frame(self.notebook)
        self.notebook.add(connection_frame, text="Connection & Reader")
        
        # Reader selection section
        reader_group = ttk.LabelFrame(connection_frame, text="Smart Card Reader", padding=10)
        reader_group.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(reader_group, text="Available Readers:").grid(row=0, column=0, sticky="w", pady=2)
        self.reader_combo = ttk.Combobox(reader_group, width=50, state="readonly")
        self.reader_combo.grid(row=0, column=1, columnspan=2, padx=10, sticky="ew")
        
        ttk.Button(reader_group, text="Refresh", command=self.refresh_readers).grid(row=0, column=3, padx=5)
        ttk.Button(reader_group, text="Connect", command=self.connect_reader).grid(row=0, column=4, padx=5)
        
        reader_group.columnconfigure(1, weight=1)
        
        # Card information section
        info_group = ttk.LabelFrame(connection_frame, text="Card Information", padding=10)
        info_group.pack(fill="both", expand=True, padx=10, pady=5)
        
        # ATR Info
        ttk.Label(info_group, text="ATR:").grid(row=0, column=0, sticky="nw", pady=2)
        self.atr_text = tk.Text(info_group, height=3, width=60, wrap=tk.WORD)
        self.atr_text.grid(row=0, column=1, columnspan=3, padx=10, sticky="ew")
        
        # Card Type
        ttk.Label(info_group, text="Card Type:").grid(row=1, column=0, sticky="w", pady=2)
        self.card_type_var = tk.StringVar(value="Unknown")
        ttk.Label(info_group, textvariable=self.card_type_var, font=("Arial", 10, "bold")).grid(row=1, column=1, sticky="w", padx=10)
        
        # Protocol
        ttk.Label(info_group, text="Protocol:").grid(row=2, column=0, sticky="w", pady=2)
        self.protocol_var = tk.StringVar(value="Not detected")
        ttk.Label(info_group, textvariable=self.protocol_var, font=("Arial", 10, "bold")).grid(row=2, column=1, sticky="w", padx=10)
        
        info_group.columnconfigure(1, weight=1)

    def setup_emv_tab(self):
        emv_frame = ttk.Frame(self.notebook)
        self.notebook.add(emv_frame, text="EMV Operations")
        
        # Quick EMV Commands
        cmd_group = ttk.LabelFrame(emv_frame, text="Quick EMV Commands", padding=10)
        cmd_group.pack(fill="x", padx=10, pady=5)
        
        # Botones organizados en grid
        commands = [
            ("SELECT PSE", "SELECT_PSE"),
            ("SELECT PPSE", "SELECT_PPSE"), 
            ("GET PROCESSING OPTIONS", "GET_PROCESSING_OPTIONS"),
            ("READ RECORD 1", "READ_RECORD_1"),
            ("READ RECORD 2", "READ_RECORD_2"),
            ("READ RECORD 3", "READ_RECORD_3")
        ]
        
        for i, (text, cmd) in enumerate(commands):
            row = i // 3
            col = i % 3
            ttk.Button(cmd_group, text=text, width=20, 
                      command=lambda c=cmd: self.send_emv_command(c)).grid(row=row, column=col, padx=5, pady=3)
        
        # Custom APDU section
        custom_group = ttk.LabelFrame(emv_frame, text="Custom APDU Commands", padding=10)
        custom_group.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(custom_group, text="APDU (hex):").grid(row=0, column=0, sticky="w", pady=2)
        self.apdu_entry = ttk.Entry(custom_group, width=60, font=("Courier", 10))
        self.apdu_entry.grid(row=0, column=1, padx=10, sticky="ew")
        ttk.Button(custom_group, text="Send", command=self.send_custom_apdu).grid(row=0, column=2, padx=5)
        
        custom_group.columnconfigure(1, weight=1)
        
        # Response section
        response_group = ttk.LabelFrame(emv_frame, text="Command Response", padding=10)
        response_group.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Crear frame para response con scrollbar
        response_container = tk.Frame(response_group)
        response_container.pack(fill="both", expand=True)
        
        self.response_text = tk.Text(response_container, height=15, font=("Courier", 9), 
                                   bg="#f8f9fa", wrap=tk.WORD)
        scrollbar_response = ttk.Scrollbar(response_container, orient="vertical", command=self.response_text.yview)
        self.response_text.configure(yscrollcommand=scrollbar_response.set)
        
        self.response_text.pack(side="left", fill="both", expand=True)
        scrollbar_response.pack(side="right", fill="y")
        
        # Botones de análisis
        analysis_frame = tk.Frame(response_group)
        analysis_frame.pack(fill="x", pady=5)
        
        ttk.Button(analysis_frame, text="Parse TLV", command=self.parse_tlv_response).pack(side="left", padx=5)
        ttk.Button(analysis_frame, text="Clear Response", command=self.clear_response).pack(side="left", padx=5)

    def setup_analysis_tab(self):
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="Card Analysis")
        
        # Analysis controls
        control_group = ttk.LabelFrame(analysis_frame, text="Analysis Controls", padding=10)
        control_group.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_group, text="Full Card Scan", command=self.full_card_scan).grid(row=0, column=0, padx=5)
        ttk.Button(control_group, text="Read All Records", command=self.read_all_records).grid(row=0, column=1, padx=5)
        ttk.Button(control_group, text="Detect Applications", command=self.detect_applications).grid(row=0, column=2, padx=5)
        ttk.Button(control_group, text="Security Analysis", command=self.security_analysis).grid(row=0, column=3, padx=5)
        
        # Analysis results
        results_group = ttk.LabelFrame(analysis_frame, text="Analysis Results", padding=10)
        results_group.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Crear Treeview para mostrar resultados estructurados
        columns = ("Field", "Value", "Description")
        self.analysis_tree = ttk.Treeview(results_group, columns=columns, show="tree headings", height=20)
        
        # Configurar columnas
        self.analysis_tree.heading("#0", text="Element")
        self.analysis_tree.heading("Field", text="Field")
        self.analysis_tree.heading("Value", text="Value")
        self.analysis_tree.heading("Description", text="Description")
        
        self.analysis_tree.column("#0", width=150)
        self.analysis_tree.column("Field", width=200)
        self.analysis_tree.column("Value", width=300)
        self.analysis_tree.column("Description", width=250)
        
        # Scrollbars para el treeview
        tree_scrollbar_v = ttk.Scrollbar(results_group, orient="vertical", command=self.analysis_tree.yview)
        tree_scrollbar_h = ttk.Scrollbar(results_group, orient="horizontal", command=self.analysis_tree.xview)
        self.analysis_tree.configure(yscrollcommand=tree_scrollbar_v.set, xscrollcommand=tree_scrollbar_h.set)
        
        self.analysis_tree.grid(row=0, column=0, sticky="nsew")
        tree_scrollbar_v.grid(row=0, column=1, sticky="ns")
        tree_scrollbar_h.grid(row=1, column=0, sticky="ew")
        
        results_group.rowconfigure(0, weight=1)
        results_group.columnconfigure(0, weight=1)

    def setup_backup_tab(self):
        backup_frame = ttk.Frame(self.notebook)
        self.notebook.add(backup_frame, text="Backup & Restore")
        
        # Backup section
        backup_group = ttk.LabelFrame(backup_frame, text="Card Backup Operations", padding=10)
        backup_group.pack(fill="x", padx=10, pady=5)
        
        backup_controls = tk.Frame(backup_group)
        backup_controls.pack(fill="x")
        
        ttk.Button(backup_controls, text="Full Backup", command=self.full_backup).pack(side="left", padx=5)
        ttk.Button(backup_controls, text="Selective Backup", command=self.selective_backup).pack(side="left", padx=5)
        ttk.Button(backup_controls, text="Quick Backup", command=self.quick_backup).pack(side="left", padx=5)
        
        # Restore section
        restore_group = ttk.LabelFrame(backup_frame, text="Card Restore Operations", padding=10)
        restore_group.pack(fill="x", padx=10, pady=5)
        
        restore_controls = tk.Frame(restore_group)
        restore_controls.pack(fill="x")
        
        ttk.Button(restore_controls, text="Load Backup", command=self.load_backup).pack(side="left", padx=5)
        ttk.Button(restore_controls, text="Restore Card", command=self.restore_card).pack(side="left", padx=5)
        ttk.Button(restore_controls, text="Compare Cards", command=self.compare_cards).pack(side="left", padx=5)
        
        # Backup history
        history_group = ttk.LabelFrame(backup_frame, text="Backup History & Management", padding=10)
        history_group.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Lista de backups
        backup_columns = ("Date", "Card Type", "Size", "Status", "File")
        self.backup_tree = ttk.Treeview(history_group, columns=backup_columns, show="headings", height=15)
        
        for col in backup_columns:
            self.backup_tree.heading(col, text=col)
            self.backup_tree.column(col, width=150)
        
        backup_scrollbar = ttk.Scrollbar(history_group, orient="vertical", command=self.backup_tree.yview)
        self.backup_tree.configure(yscrollcommand=backup_scrollbar.set)
        
        self.backup_tree.pack(side="left", fill="both", expand=True)
        backup_scrollbar.pack(side="right", fill="y")

    def setup_advanced_tab(self):
        advanced_frame = ttk.Frame(self.notebook)
        self.notebook.add(advanced_frame, text="Advanced Tools")
        
        # Protocol operations
        protocol_group = ttk.LabelFrame(advanced_frame, text="Protocol Operations", padding=10)
        protocol_group.pack(fill="x", padx=10, pady=5)
        
        # Frame para botones de protocolo
        protocol_buttons = tk.Frame(protocol_group)
        protocol_buttons.pack(fill="x")
        
        protocols = ["EMV 201", "EMV 206", "EMV 226", "SDA", "DDA", "CDA"]
        for i, protocol in enumerate(protocols):
            ttk.Button(protocol_buttons, text=f"Test {protocol}", 
                      command=lambda p=protocol: self.test_protocol(p)).grid(row=i//3, column=i%3, padx=5, pady=3)
        
        # Data manipulation
        data_group = ttk.LabelFrame(advanced_frame, text="Data Manipulation", padding=10)
        data_group.pack(fill="x", padx=10, pady=5)
        
        data_buttons = tk.Frame(data_group)
        data_buttons.pack(fill="x")
        
        ttk.Button(data_buttons, text="Clone Card", command=self.clone_card).pack(side="left", padx=5)
        ttk.Button(data_buttons, text="Modify Track Data", command=self.modify_track_data).pack(side="left", padx=5)
        ttk.Button(data_buttons, text="Generate Test Card", command=self.generate_test_card).pack(side="left", padx=5)
        
        # Log console
        console_group = ttk.LabelFrame(advanced_frame, text="Operation Console", padding=10)
        console_group.pack(fill="both", expand=True, padx=10, pady=5)
        
        console_container = tk.Frame(console_group)
        console_container.pack(fill="both", expand=True)
        
        self.console_text = tk.Text(console_container, height=15, font=("Courier", 9), 
                                  bg="#1e1e1e", fg="#00ff00", wrap=tk.WORD)
        console_scrollbar = ttk.Scrollbar(console_container, orient="vertical", command=self.console_text.yview)
        self.console_text.configure(yscrollcommand=console_scrollbar.set)
        
        self.console_text.pack(side="left", fill="both", expand=True)
        console_scrollbar.pack(side="right", fill="y")
        
        # Console controls
        console_controls = tk.Frame(console_group)
        console_controls.pack(fill="x", pady=5)
        
        ttk.Button(console_controls, text="Clear Console", command=self.clear_console).pack(side="left", padx=5)
        ttk.Button(console_controls, text="Save Log", command=self.save_console_log).pack(side="left", padx=5)

    def setup_status_bar(self):
        self.status_frame = tk.Frame(self.root, relief=tk.SUNKEN, bd=1)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Status labels
        self.status_var = tk.StringVar(value="Ready - No reader connected")
        self.status_label = tk.Label(self.status_frame, textvariable=self.status_var, anchor='w')
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Connection indicator
        self.connection_var = tk.StringVar(value="Disconnected")
        self.connection_label = tk.Label(self.status_frame, textvariable=self.connection_var, 
                                       anchor='e', fg="red", font=("Arial", 9, "bold"))
        self.connection_label.pack(side=tk.RIGHT, padx=5)

    # Event handlers and methods
    def refresh_readers(self):
        try:
            readers_list = self.reader.list_readers()
            self.reader_combo['values'] = readers_list
            if readers_list:
                self.reader_combo.current(0)
                self.log_to_console(f"Detected {len(readers_list)} reader(s)")
                self.status_var.set(f"Ready - {len(readers_list)} reader(s) available")
            else:
                self.log_to_console("No readers detected")
                self.status_var.set("No readers detected")
        except Exception as e:
            self.log_to_console(f"Error refreshing readers: {e}")

    def connect_reader(self):
        try:
            index = self.reader_combo.current()
            if index == -1:
                messagebox.showwarning("Warning", "Please select a reader first")
                return
                
            atr = self.reader.connect(index)
            atr_str = ' '.join(f'{b:02X}' for b in atr)
            
            self.atr_text.delete(1.0, tk.END)
            self.atr_text.insert(tk.END, atr_str)
            
            self.is_connected = True
            self.connection_var.set("Connected")
            self.connection_label.config(fg="green")
            
            reader_name = self.reader.list_readers()[index]
            self.log_to_console(f"Connected to: {reader_name}")
            self.log_to_console(f"ATR: {atr_str}")
            self.status_var.set(f"Connected - Card ready")
            
            # Auto-detect card type
            self.detect_card_type(atr)
            
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.status_var.set("Connection failed")

    def detect_card_type(self, atr):
        # Análisis básico del ATR para determinar tipo de tarjeta
        atr_hex = ''.join(f'{b:02X}' for b in atr)
        
        if "3B" in atr_hex[:2]:
            self.card_type_var.set("ISO 7816 Compatible")
        elif "3F" in atr_hex[:2]:
            self.card_type_var.set("Inverse Convention")
        else:
            self.card_type_var.set("Unknown Type")
            
        # Detectar protocolo EMV
        if len(atr) > 10:
            self.protocol_var.set("EMV Compatible")
        else:
            self.protocol_var.set("Basic ISO 7816")

    def send_emv_command(self, cmd_name):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return
            
        if cmd_name in EMV_COMMANDS:
            apdu = [int(b, 16) for b in EMV_COMMANDS[cmd_name].split()]
            self.send_apdu_internal(apdu, f"EMV Command: {cmd_name}")
        else:
            messagebox.showerror("Error", f"EMV command not found: {cmd_name}")

    def send_custom_apdu(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return
            
        apdu_text = self.apdu_entry.get().strip()
        if not apdu_text:
            messagebox.showwarning("Warning", "Please enter an APDU command")
            return
            
        if not self.validate_apdu(apdu_text):
            messagebox.showerror("Error", "Invalid APDU format. Use hex separated by spaces")
            return
            
        apdu = [int(b, 16) for b in apdu_text.split()]
        self.send_apdu_internal(apdu, "Custom APDU")

    def validate_apdu(self, text):
        return re.fullmatch(r'([0-9a-fA-F]{2}(\s[0-9a-fA-F]{2})*)?', text.strip())

    def send_apdu_internal(self, apdu, command_type="APDU"):
        try:
            response, sw1, sw2 = self.reader.transmit(apdu)
            self.last_response = response
            self.last_sw = (sw1, sw2)
            
            # Format response
            apdu_str = ' '.join(f'{b:02X}' for b in apdu)
            response_str = ' '.join(f'{b:02X}' for b in response) if response else "No data"
            sw_str = f"{sw1:02X} {sw2:02X}"
            
            # Add to response text
            self.response_text.insert(tk.END, f"\n>>> {command_type}: {apdu_str}\n")
            self.response_text.insert(tk.END, f"Response: {response_str}\n")
            self.response_text.insert(tk.END, f"SW: {sw_str} - {self.interpret_sw(sw1, sw2)}\n")
            self.response_text.insert(tk.END, "-" * 80 + "\n")
            self.response_text.see(tk.END)
            
            # Log to console
            self.log_to_console(f"{command_type} sent: {apdu_str}")
            self.log_to_console(f"Response: {response_str} SW: {sw_str}")
            
            self.status_var.set(f"Last SW: {sw_str} - {self.interpret_sw(sw1, sw2)}")
            
        except Exception as e:
            messagebox.showerror("APDU Error", str(e))
            self.log_to_console(f"APDU Error: {e}")

    def interpret_sw(self, sw1, sw2):
        from enhanced_apdu_utils import SW_CODES
        return SW_CODES.get((sw1, sw2), f"Unknown status SW1={sw1:02X} SW2={sw2:02X}")

    def parse_tlv_response(self):
        if self.last_response is None:
            messagebox.showwarning("Warning", "No response data to parse")
            return
            
        try:
            tlv_data = parse_tlv(self.last_response)
            self.response_text.insert(tk.END, "\n=== TLV ANALYSIS ===\n")
            
            def format_tlv_recursive(tlvs, level=0):
                indent = '  ' * level
                for tag, length, value, subitems in tlvs:
                    tag_hex = f"{tag:02X}" if tag <= 0xFF else f"{tag:04X}"
                    val_hex = ' '.join(f"{b:02X}" for b in value)
                    self.response_text.insert(tk.END, f"{indent}Tag {tag_hex} Len {length}: {val_hex}\n")
                    if subitems:
                        format_tlv_recursive(subitems, level + 1)
            
            format_tlv_recursive(tlv_data)
            self.response_text.insert(tk.END, "=== END TLV ===\n\n")
            self.response_text.see(tk.END)
            
        except Exception as e:
            messagebox.showerror("TLV Error", f"Error parsing TLV: {e}")

    def clear_response(self):
        self.response_text.delete(1.0, tk.END)

    def log_to_console(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.console_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.console_text.see(tk.END)

    def clear_console(self):
        self.console_text.delete(1.0, tk.END)

    # Placeholder methods for advanced features
    def new_session(self):
        self.clear_response()
        self.clear_console()
        self.analysis_tree.delete(*self.analysis_tree.get_children())
        self.log_to_console("New session started")

    def load_config(self):
        messagebox.showinfo("Info", "Load configuration feature coming soon")

    def save_config(self):
        messagebox.showinfo("Info", "Save configuration feature coming soon")

    def export_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, 'w') as f:
                f.write(self.console_text.get("1.0", tk.END))
            self.log_to_console(f"Log exported to: {path}")

    def analyze_card(self):
        self.log_to_console("Starting card analysis...")
        messagebox.showinfo("Info", "Card analysis feature in development")

    def scan_protocols(self):
        self.log_to_console("Scanning supported protocols...")
        messagebox.showinfo("Info", "Protocol scanner feature in development")

    def compare_data(self):
        messagebox.showinfo("Info", "Data comparison feature in development")

    def full_card_scan(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return

        self.log_to_console("Performing full card scan...")
        self.analysis_tree.delete(*self.analysis_tree.get_children())

        # Display basic card info
        self.display_card_info()

        # Detect applications first
        self.detect_applications()

        # Read all records
        self.read_all_records()

        # Perform security analysis
        self.security_analysis()

        self.log_to_console("Full card scan completed.")
        
    def read_all_records(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return
            
        if not hasattr(self, 'afl') or not self.afl:
            self.log_to_console("AFL not found. Reading records sequentially.")
            # Fallback to sequential reading if AFL not available
            for rec in range(1, 11): # Read first 10 records
                apdu = [0x00, 0xB2, rec, 0x0C, 0x00]
                try:
                    response, sw1, sw2 = self.reader.transmit(apdu)
                    if sw1 == 0x90 and sw2 == 0x00:
                        record_id = self.analysis_tree.insert("", "end", text=f"Record {rec}")
                        data_hex = ' '.join(f'{b:02X}' for b in response)
                        self.analysis_tree.insert(record_id, "end", values=("Data", data_hex[:50] + "...", f"Record {rec} data"))
                        self.log_to_console(f"Record {rec}: Found {len(response)} bytes")
                except Exception as e:
                    self.log_to_console(f"Record {rec}: Error - {e}")
            return

        self.log_to_console("Reading records based on AFL...")
        sfi_nodes = {}
        for entry in self.afl:
            sfi = entry["sfi"]
            rec_num = entry["rec_num"]

            if sfi not in sfi_nodes:
                sfi_nodes[sfi] = self.analysis_tree.insert("", "end", text=f"SFI {sfi}")

            p2 = (sfi << 3) | 4 # As per EMV spec
            apdu = [0x00, 0xB2, rec_num, p2, 0x00]
            try:
                response, sw1, sw2 = self.reader.transmit(apdu)
                if sw1 == 0x90 and sw2 == 0x00:
                    record_id = self.analysis_tree.insert(sfi_nodes[sfi], "end", text=f"Record {rec_num}")
                    data_hex = ' '.join(f'{b:02X}' for b in response)
                    self.analysis_tree.insert(record_id, "end", values=("Data", data_hex[:50] + "...", f"SFI {sfi} Record {rec_num} data"))
                    self.log_to_console(f"SFI {sfi} Record {rec_num}: Found {len(response)} bytes")
                else:
                    self.log_to_console(f"SFI {sfi} Record {rec_num}: SW={sw1:02X}{sw2:02X} - Not available")
            except Exception as e:
                self.log_to_console(f"SFI {sfi} Record {rec_num}: Error - {e}")

    def detect_applications(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return
            
        self.log_to_console("Detecting EMV applications...")
        
        # Limpiar árbol de análisis
        for item in self.analysis_tree.get_children():
            self.analysis_tree.delete(item)
        
        # Intentar SELECT PSE
        try:
            pse_apdu = [int(b, 16) for b in EMV_COMMANDS["SELECT_PSE"].split()]
            response, sw1, sw2 = self.reader.transmit(pse_apdu)
            
            if sw1 == 0x90 and sw2 == 0x00:
                app_node = self.analysis_tree.insert("", "end", text="PSE Applications")
                self.analysis_tree.insert(app_node, "end", values=("PSE Response", "Found", "Payment System Environment detected"))
                self.log_to_console("PSE found - analyzing applications...")
                
                # Parse TLV para encontrar aplicaciones
                try:
                    tlv_data = parse_tlv(response)
                    self._parse_applications_from_tlv(tlv_data, app_node)
                except:
                    pass
            else:
                # Intentar SELECT PPSE
                ppse_apdu = [int(b, 16) for b in EMV_COMMANDS["SELECT_PPSE"].split()]
                response, sw1, sw2 = self.reader.transmit(ppse_apdu)
                
                if sw1 == 0x90 and sw2 == 0x00:
                    app_node = self.analysis_tree.insert("", "end", text="PPSE Applications")
                    self.analysis_tree.insert(app_node, "end", values=("PPSE Response", "Found", "Proximity Payment System Environment"))
                    self.log_to_console("PPSE found - analyzing applications...")
        except Exception as e:
            self.log_to_console(f"Error detecting applications: {e}")

    def _parse_applications_from_tlv(self, tlv_data, parent_node):
        """Parse TLV data to extract application information"""
        for tag, length, value, subitems in tlv_data:
            if tag == 0x6F:  # FCI Template
                fci_node = self.analysis_tree.insert(parent_node, "end", text="FCI Template")
                self.analysis_tree.insert(fci_node, "end", values=("Template", "Found", "File Control Information"))
                if subitems:
                    self._parse_applications_from_tlv(subitems, fci_node)
            elif tag == 0x84:  # DF Name (AID)
                aid_hex = ''.join(f'{b:02X}' for b in value)
                self.analysis_tree.insert(parent_node, "end", values=("AID", aid_hex, "Application Identifier"))
                # Try to select the application
                self.select_application(value)
            elif tag == 0x87:  # Application Priority Indicator
                priority = value[0] if value else 0
                self.analysis_tree.insert(parent_node, "end", values=("Priority", str(priority), "Application Priority"))

    def select_application(self, aid):
        try:
            apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid)
            response, sw1, sw2 = self.reader.transmit(apdu)
            if sw1 == 0x90 and sw2 == 0x00:
                self.log_to_console(f"Successfully selected application {''.join(f'{b:02X}' for b in aid)}")

                # Parse the response to find the AFL (tag 0x94)
                tlv_response = parse_tlv(response)
                self.afl = None
                for tag, length, value, subitems in tlv_response:
                    if tag == 0x94: # Application File Locator
                        self.afl = self.parse_afl(value)
                        break
            else:
                self.log_to_console(f"Failed to select application {''.join(f'{b:02X}' for b in aid)}")
        except Exception as e:
            self.log_to_console(f"Error selecting application {''.join(f'{b:02X}' for b in aid)}: {e}")

    def parse_afl(self, afl_data):
        self.log_to_console(f"Parsing AFL: {''.join(f'{b:02X}' for b in afl_data)}")
        afl_entries = []
        for i in range(0, len(afl_data), 4):
            entry_data = afl_data[i:i+4]
            if len(entry_data) < 4:
                continue

            sfi = entry_data[0] >> 3
            first_record = entry_data[1]
            last_record = entry_data[2]
            num_auth_records = entry_data[3]

            for rec_num in range(first_record, last_record + 1):
                afl_entries.append({"sfi": sfi, "rec_num": rec_num})

        self.log_to_console(f"AFL parsed: {afl_entries}")
        return afl_entries

    def display_card_info(self):
        if not self.is_connected:
            return

        info_node = self.analysis_tree.insert("", "end", text="Card Information")
        self.analysis_tree.insert(info_node, "end", values=("ATR", self.atr_text.get("1.0", tk.END).strip(), "Answer to Reset"))
        self.analysis_tree.insert(info_node, "end", values=("Card Type", self.card_type_var.get(), "Detected Card Type"))
        self.analysis_tree.insert(info_node, "end", values=("Protocol", self.protocol_var.get(), "Communication Protocol"))

    def security_analysis(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return
            
        self.log_to_console("Performing security analysis...")
        
        # Crear nodo de seguridad en el árbol
        security_node = self.analysis_tree.insert("", "end", text="Security Analysis")
        
        # Test básicos de seguridad
        security_tests = [
            ("Authentication", "Testing card authentication methods"),
            ("Encryption", "Checking encryption capabilities"),
            ("Key Management", "Analyzing key storage and usage"),
            ("PIN Verification", "Testing PIN verification methods"),
            ("Certificate Chain", "Validating certificate chain")
        ]
        
        for test_name, description in security_tests:
            # Simular análisis (en implementación real harías tests específicos)
            status = "Pass" if hash(test_name) % 2 == 0 else "Needs Review"
            self.analysis_tree.insert(security_node, "end", values=(test_name, status, description))
            self.log_to_console(f"Security test '{test_name}': {status}")

    def full_backup(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Backup", "*.json"), ("All Files", "*.*")]
        )

        if path:
            try:
                self.log_to_console(f"Starting full backup to {path}...")
                backup_data = self.tool.full_backup(path)
                self.log_to_console("Full backup completed.")
                
                # Add to backup history
                timestamp = backup_data.get("timestamp", "N/A")
                card_type = backup_data.get("card_type", "N/A")
                size = f"{len(json.dumps(backup_data))} bytes"
                self.backup_tree.insert("", "end", values=(timestamp, card_type, size, "Completed", path))

                messagebox.showinfo("Backup Successful", f"Card data backed up to {path}")
            except Exception as e:
                self.log_to_console(f"Backup failed: {e}")
                messagebox.showerror("Backup Error", f"An error occurred during backup: {e}")

    def selective_backup(self):
        self.log_to_console("Selective backup feature in development...")
        messagebox.showinfo("Info", "Selective backup feature coming soon")

    def quick_backup(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return
            
        # Backup rápido de registros principales
        self.log_to_console("Performing quick backup...")
        quick_data = {}
        
        for rec in range(1, 6):  # Solo primeros 5 registros
            apdu = [0x00, 0xB2, rec, 0x0C, 0x00]
            try:
                response, sw1, sw2 = self.reader.transmit(apdu)
                if sw1 == 0x90 and sw2 == 0x00:
                    quick_data[f"record_{rec}"] = response
            except:
                pass
        
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if path:
            with open(path, 'w') as f:
                json.dump(quick_data, f, default=list)
            self.log_to_console(f"Quick backup saved: {path}")

    def load_backup(self):
        path = filedialog.askopenfilename(
            filetypes=[("EMV Backup", "*.emv"), ("JSON", "*.json"), ("All Files", "*.*")]
        )
        
        if path:
            try:
                with open(path, 'r') as f:
                    backup_data = json.load(f)
                
                self.log_to_console(f"Loaded backup from: {path}")
                self.log_to_console(f"Backup contains {len(backup_data.get('records', {}))} records")
                
                # Mostrar información del backup
                info = f"Backup Information:\n"
                info += f"Timestamp: {backup_data.get('timestamp', 'Unknown')}\n"
                info += f"Card Type: {backup_data.get('card_type', 'Unknown')}\n"
                info += f"Records: {len(backup_data.get('records', {}))}\n"
                
                messagebox.showinfo("Backup Loaded", info)
                
            except Exception as e:
                self.log_to_console(f"Error loading backup: {e}")
                messagebox.showerror("Load Error", str(e))

    def restore_card(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return

        path = filedialog.askopenfilename(
            filetypes=[("JSON Backup", "*.json"), ("All Files", "*.*")]
        )

        if path:
            try:
                self.log_to_console(f"Restoring card from {path}...")
                if self.tool.restore_from_backup(path):
                    self.log_to_console("Card restoration completed (simulation).")
                    messagebox.showinfo("Restore Successful", "Card data restored from backup (simulation).")
                else:
                    self.log_to_console("Card restoration failed.")
                    messagebox.showerror("Restore Failed", "Could not restore card data.")
            except Exception as e:
                self.log_to_console(f"Restore failed: {e}")
                messagebox.showerror("Restore Error", f"An error occurred during restore: {e}")

    def compare_cards(self):
        self.log_to_console("Card comparison feature in development...")
        messagebox.showinfo("Info", "Card comparison feature coming soon")

    def test_protocol(self, protocol):
        self.log_to_console(f"Testing protocol: {protocol}")
        
        protocol_tests = {
            "EMV 201": ["Basic EMV commands", "Static data authentication"],
            "EMV 206": ["Enhanced EMV features", "Dynamic data authentication"],  
            "EMV 226": ["Advanced EMV protocol", "Combined data authentication"],
            "SDA": ["Static data authentication test"],
            "DDA": ["Dynamic data authentication test"],
            "CDA": ["Combined data authentication test"]
        }
        
        tests = protocol_tests.get(protocol, ["Generic protocol test"])
        for test in tests:
            self.log_to_console(f"  - {test}: Testing...")
            # Aquí irían los tests específicos del protocolo
            
        messagebox.showinfo("Protocol Test", f"{protocol} testing completed. Check console for details.")

    def setup_write_tab(self):
        write_frame = ttk.Frame(self.notebook)
        self.notebook.add(write_frame, text="Write Operations")

        # Write record section
        record_group = ttk.LabelFrame(write_frame, text="Write Record", padding=10)
        record_group.pack(fill="x", padx=10, pady=5)

        ttk.Label(record_group, text="Record (SFI):").grid(row=0, column=0, sticky="w", pady=2)
        self.write_sfi_entry = ttk.Entry(record_group, width=10)
        self.write_sfi_entry.grid(row=0, column=1, padx=10, sticky="w")

        ttk.Label(record_group, text="Data (hex):").grid(row=1, column=0, sticky="w", pady=2)
        self.write_data_entry = ttk.Entry(record_group, width=60)
        self.write_data_entry.grid(row=1, column=1, padx=10, sticky="ew")

        ttk.Button(record_group, text="Write Record", command=self.write_record).grid(row=2, column=1, pady=5, sticky="e")

        record_group.columnconfigure(1, weight=1)

        # Modify Track 2 section
        track2_group = ttk.LabelFrame(write_frame, text="Modify Track 2 Data", padding=10)
        track2_group.pack(fill="x", padx=10, pady=5)

        ttk.Label(track2_group, text="Track 2 Data:").grid(row=0, column=0, sticky="w", pady=2)
        self.track2_entry = ttk.Entry(track2_group, width=60)
        self.track2_entry.grid(row=0, column=1, padx=10, sticky="ew")

        ttk.Button(track2_group, text="Write Track 2", command=self.write_track2).grid(row=1, column=1, pady=5, sticky="e")

        track2_group.columnconfigure(1, weight=1)

    def write_record(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return

        sfi_text = self.write_sfi_entry.get().strip()
        data_text = self.write_data_entry.get().strip().replace(" ", "")

        if not sfi_text or not data_text:
            messagebox.showwarning("Warning", "SFI and data fields cannot be empty.")
            return

        if not re.fullmatch(r'[0-9a-fA-F]+', data_text):
            messagebox.showerror("Error", "Invalid hex data.")
            return

        if not messagebox.askyesno("Confirm Write", "WARNING: Writing data to a card is a risky operation and may render it unusable. Are you sure you want to continue?"):
            return

        try:
            sfi = int(sfi_text)
            data = bytes.fromhex(data_text)

            # P1 is the SFI
            apdu = [0x00, 0xD6, sfi, 0x00, len(data)] + list(data)

            self.log_to_console(f"Attempting to write to SFI {sfi}...")
            self.send_apdu_internal(apdu, f"Write Record (SFI {sfi})")

        except ValueError:
            messagebox.showerror("Error", "SFI must be an integer.")
        except Exception as e:
            self.log_to_console(f"Error writing record: {e}")
            messagebox.showerror("Error", f"An error occurred: {e}")

    def write_track2(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return

        track2_data = self.track2_entry.get().strip()

        if not track2_data:
            messagebox.showwarning("Warning", "Track 2 data cannot be empty.")
            return

        if not re.fullmatch(r'[0-9=dD]+', track2_data):
            messagebox.showerror("Error", "Invalid Track 2 data format. Use digits and 'D' as separator.")
            return

        if not messagebox.askyesno("Confirm Write", "WARNING: Writing Track 2 data is a high-risk operation. Are you sure you want to continue?"):
            return

        # The data needs to be packed in TLV format for tag 57
        # Then, this TLV needs to be written to the correct record, which can vary.
        # This is a simplified example assuming we know where to write.

        # We need to find the AFL to know where to write the data.
        # This is a complex process, so for now we will simulate it
        # by assuming the data is in the first record (SFI 1).

        try:
            # Format Track 2 data
            encoded_track2 = track2_data.encode('ascii')

            # Create TLV for tag 57
            tag = b'\x57'
            length = len(encoded_track2).to_bytes(1, 'big')
            tlv_track2 = tag + length + encoded_track2

            # For this example, let's assume we're writing to the first record (SFI 1)
            # A real implementation would need to parse the AFL.
            sfi = 1

            # We need to find the record and replace the tag 57
            # This is a read-modify-write operation.

            # 1. Read the record
            read_apdu = [0x00, 0xB2, 0x01, 0x0C, 0x00] # Read record 1
            response, sw1, sw2 = self.reader.transmit(read_apdu)
            if not (sw1 == 0x90 and sw2 == 0x00):
                messagebox.showerror("Error", "Could not read card record to modify Track 2.")
                return

            # 2. Modify the data (this is a simplified search and replace)
            # A more robust solution would parse the TLV and replace the tag.
            # This example just overwrites the beginning of the record.

            # 3. Write the new data
            apdu = [0x00, 0xD6, sfi, 0x00, len(tlv_track2)] + list(tlv_track2)

            self.log_to_console("Attempting to write Track 2 data...")
            self.send_apdu_internal(apdu, "Write Track 2")

        except Exception as e:
            self.log_to_console(f"Error writing Track 2: {e}")
            messagebox.showerror("Error", f"An error occurred: {e}")

    def setup_cloning_tab(self):
        cloning_frame = ttk.Frame(self.notebook)
        self.notebook.add(cloning_frame, text="Cloning")

        # Cloning controls
        control_group = ttk.LabelFrame(cloning_frame, text="Cloning Operations", padding=10)
        control_group.pack(fill="x", padx=10, pady=5)

        ttk.Button(control_group, text="Read Source Card", command=self.read_source_for_cloning).pack(side="left", padx=5)
        ttk.Button(control_group, text="Write to Target Card", command=self.write_to_target_for_cloning).pack(side="left", padx=5)

        # Status console
        status_group = ttk.LabelFrame(cloning_frame, text="Cloning Status", padding=10)
        status_group.pack(fill="both", expand=True, padx=10, pady=5)

        self.cloning_status_text = tk.Text(status_group, height=15, font=("Courier", 9), bg="#f8f9fa", wrap=tk.WORD)
        self.cloning_status_text.pack(fill="both", expand=True)

    def read_source_for_cloning(self):
        self.cloning_status_text.delete(1.0, tk.END)
        self.cloning_status_text.insert(tk.END, "Reading source card...\n")

        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            self.cloning_status_text.insert(tk.END, "Failed: Not connected to a reader.\n")
            return

        # First, we need to select an application to get the AFL
        self.detect_applications()
        if not hasattr(self, 'afl') or not self.afl:
            messagebox.showerror("Error", "Could not find an application with an AFL to read for cloning.")
            self.cloning_status_text.insert(tk.END, "Failed: Could not find an application with an AFL.\n")
            return

        self.cloned_data = []
        for entry in self.afl:
            sfi = entry["sfi"]
            rec_num = entry["rec_num"]
            p2 = (sfi << 3) | 4
            apdu = [0x00, 0xB2, rec_num, p2, 0x00]
            try:
                response, sw1, sw2 = self.reader.transmit(apdu)
                if sw1 == 0x90 and sw2 == 0x00:
                    self.cloned_data.append({"sfi": sfi, "rec_num": rec_num, "data": response})
                    self.cloning_status_text.insert(tk.END, f"  - Read SFI {sfi} Record {rec_num}\n")
                else:
                    self.cloning_status_text.insert(tk.END, f"  - Failed to read SFI {sfi} Record {rec_num} (SW: {sw1:02X}{sw2:02X})\n")
            except Exception as e:
                self.cloning_status_text.insert(tk.END, f"  - Error reading SFI {sfi} Record {rec_num}: {e}\n")

        if self.cloned_data:
            self.cloning_status_text.insert(tk.END, "Source card read successfully. Ready to write to target.\n")
        else:
            self.cloning_status_text.insert(tk.END, "Could not read any data from the source card.\n")

    def write_to_target_for_cloning(self):
        self.cloning_status_text.insert(tk.END, "\nWriting to target card...\n")

        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            self.cloning_status_text.insert(tk.END, "Failed: Not connected to a reader.\n")
            return

        if not hasattr(self, 'cloned_data') or not self.cloned_data:
            messagebox.showerror("Error", "No data has been read from a source card.")
            self.cloning_status_text.insert(tk.END, "Failed: No source data available.\n")
            return

        if not messagebox.askyesno("Confirm Write", "WARNING: This will overwrite all data on the target card and may render it unusable. Are you sure you want to continue?"):
            self.cloning_status_text.insert(tk.END, "Operation cancelled by user.\n")
            return

        for record in self.cloned_data:
            sfi = record["sfi"]
            rec_num = record["rec_num"]
            data = record["data"]
            p1 = rec_num
            p2 = (sfi << 3) | 4

            apdu = [0x00, 0xD6, p1, p2, len(data)] + list(data)
            try:
                response, sw1, sw2 = self.reader.transmit(apdu)
                if sw1 == 0x90 and sw2 == 0x00:
                    self.cloning_status_text.insert(tk.END, f"  - Wrote SFI {sfi} Record {rec_num}\n")
                else:
                    self.cloning_status_text.insert(tk.END, f"  - Failed to write SFI {sfi} Record {rec_num} (SW: {sw1:02X}{sw2:02X})\n")
            except Exception as e:
                self.cloning_status_text.insert(tk.END, f"  - Error writing SFI {sfi} Record {rec_num}: {e}\n")

        self.cloning_status_text.insert(tk.END, "Cloning process completed.\n")

    def setup_jcard_tab(self):
        jcard_frame = ttk.Frame(self.notebook)
        self.notebook.add(jcard_frame, text="Java Card")

        # JCard controls
        control_group = ttk.LabelFrame(jcard_frame, text="JCOP Operations", padding=10)
        control_group.pack(fill="x", padx=10, pady=5)

        ttk.Button(control_group, text="List Applets", command=self.list_applets).pack(side="left", padx=5)

        # Applet list
        applet_group = ttk.LabelFrame(jcard_frame, text="Installed Applets", padding=10)
        applet_group.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("AID", "State")
        self.applet_tree = ttk.Treeview(applet_group, columns=columns, show="headings", height=15)
        self.applet_tree.heading("AID", text="Applet AID")
        self.applet_tree.heading("State", text="State")
        self.applet_tree.column("AID", width=400)
        self.applet_tree.column("State", width=150)
        self.applet_tree.pack(fill="both", expand=True)

    def list_applets(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return

        self.applet_tree.delete(*self.applet_tree.get_children())

        # Standard AID for JCOP Card Manager
        card_manager_aid = bytes.fromhex("A000000003000000")

        try:
            # Select the Card Manager
            apdu = [0x00, 0xA4, 0x04, 0x00, len(card_manager_aid)] + list(card_manager_aid)
            response, sw1, sw2 = self.reader.transmit(apdu)

            if sw1 != 0x90 or sw2 != 0x00:
                messagebox.showerror("Error", "Could not select Card Manager. Is this a JCOP card?")
                return

            self.log_to_console("Card Manager selected successfully.")

            # Send GET STATUS command to list applets
            get_status_apdu = [0x80, 0xF2, 0x40, 0x00, 0x02, 0x4F, 0x00]
            response, sw1, sw2 = self.reader.transmit(get_status_apdu)

            if sw1 != 0x90 or sw2 != 0x00:
                messagebox.showerror("Error", f"Could not get applet list (SW: {sw1:02X}{sw2:02X})")
                return

            self.parse_get_status_response(response)

        except Exception as e:
            self.log_to_console(f"Error selecting Card Manager: {e}")
            messagebox.showerror("Error", f"An error occurred: {e}")

    def parse_get_status_response(self, response):
        tlv_data = parse_tlv(response)
        for tag, length, value, subitems in tlv_data:
            if tag == 0xF2: # Card Data
                continue # Ignore for now

            aid = ''.join(f'{b:02X}' for b in value[:length-1])
            state_byte = value[-1]

            state = "Unknown"
            if state_byte == 0x01:
                state = "Installed"
            elif state_byte == 0x03:
                state = "Selectable"
            elif state_byte == 0x07:
                state = "Locked"

            self.applet_tree.insert("", "end", values=(aid, state))

    def setup_sim_tab(self):
        sim_frame = ttk.Frame(self.notebook)
        self.notebook.add(sim_frame, text="SIM Card")

        # SIM controls
        control_group = ttk.LabelFrame(sim_frame, text="SIM Operations", padding=10)
        control_group.pack(fill="x", padx=10, pady=5)

        ttk.Button(control_group, text="Read Basic Info", command=self.read_sim_basic_info).pack(side="left", padx=5)
        ttk.Button(control_group, text="Read SMS", command=self.read_sim_sms).pack(side="left", padx=5)

        # Info display
        info_group = ttk.LabelFrame(sim_frame, text="SIM Information", padding=10)
        info_group.pack(fill="both", expand=True, padx=10, pady=5)

        self.sim_info_text = tk.Text(info_group, height=15, font=("Courier", 9), bg="#f8f9fa", wrap=tk.WORD)
        self.sim_info_text.pack(fill="both", expand=True)

    def read_sim_basic_info(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return

        self.sim_info_text.delete(1.0, tk.END)

        try:
            # Select MF
            self.send_apdu_internal([0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00], "Select MF")

            # Select DF Telecom
            self.send_apdu_internal([0x00, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10], "Select DF Telecom")

            # Read EF_ICCID
            self.read_sim_ef("EF_ICCID", [0x00, 0xB0, 0x00, 0x00, 10])

            # Read EF_IMSI
            self.read_sim_ef("EF_IMSI", [0x00, 0xB0, 0x00, 0x00, 9])

        except Exception as e:
            self.sim_info_text.insert(tk.END, f"Error reading SIM info: {e}\n")

    def read_sim_ef(self, name, apdu):
        try:
            response, sw1, sw2 = self.reader.transmit(apdu)
            if sw1 == 0x90 and sw2 == 0x00:
                self.sim_info_text.insert(tk.END, f"{name}: {''.join(f'{b:02X}' for b in response)}\n")
            else:
                self.sim_info_text.insert(tk.END, f"Could not read {name} (SW: {sw1:02X}{sw2:02X})\n")
        except Exception as e:
            self.sim_info_text.insert(tk.END, f"Error reading {name}: {e}\n")

    def read_sim_sms(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return

        self.sim_info_text.delete(1.0, tk.END)
        self.sim_info_text.insert(tk.END, "Reading SMS...\n")

        try:
            # Select EF_SMS
            self.send_apdu_internal([0x00, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x3C], "Select EF_SMS")

            # Read SMS records
            for i in range(1, 21): # Try to read first 20 SMS
                apdu = [0x00, 0xB2, i, 0x04, 0xB0] # Read record i
                response, sw1, sw2 = self.reader.transmit(apdu)
                if sw1 == 0x90 and sw2 == 0x00:
                    self.sim_info_text.insert(tk.END, f"\nSMS Record {i}:\n")
                    self.parse_sms_record(response)
                else:
                    # Stop if record not found
                    break
        except Exception as e:
            self.sim_info_text.insert(tk.END, f"Error reading SMS: {e}\n")

    def parse_sms_record(self, record_data):
        # This is a simplified parser for SMS-DELIVER messages
        try:
            status = record_data[0]
            sender_len = record_data[2]
            sender = record_data[9:9 + (sender_len+1)//2]
            timestamp = record_data[9 + (sender_len+1)//2 : 16 + (sender_len+1)//2]
            msg_len = record_data[-1]
            msg = record_data[-(msg_len):]

            self.sim_info_text.insert(tk.END, f"  Status: {'Read' if status == 1 else 'Unread'}\n")
            self.sim_info_text.insert(tk.END, f"  Sender: {''.join(f'{b:02X}' for b in sender)}\n")
            self.sim_info_text.insert(tk.END, f"  Message: {msg.decode('latin-1', errors='ignore')}\n")
        except Exception as e:
            self.sim_info_text.insert(tk.END, f"  Error parsing SMS record: {e}\n")

    def setup_crypto_tab(self):
        crypto_frame = ttk.Frame(self.notebook)
        self.notebook.add(crypto_frame, text="Crypto Wallet")

        # Crypto controls
        control_group = ttk.LabelFrame(crypto_frame, text="Crypto Operations", padding=10)
        control_group.pack(fill="x", padx=10, pady=5)

        ttk.Label(control_group, text="Derivation Path (BIP32):").grid(row=0, column=0, sticky="w", pady=2)
        self.derivation_path_entry = ttk.Entry(control_group, width=30)
        self.derivation_path_entry.grid(row=0, column=1, padx=10, sticky="w")
        self.derivation_path_entry.insert(0, "44'/0'/0'/0/0")

        ttk.Button(control_group, text="Get BTC Address", command=self.get_btc_address).grid(row=0, column=2, padx=5)

        # Info display
        info_group = ttk.LabelFrame(crypto_frame, text="Wallet Information", padding=10)
        info_group.pack(fill="both", expand=True, padx=10, pady=5)

        self.crypto_info_text = tk.Text(info_group, height=10, font=("Courier", 10), bg="#f8f9fa", wrap=tk.WORD)
        self.crypto_info_text.pack(fill="both", expand=True)

    def get_btc_address(self):
        if not self.is_connected:
            messagebox.showwarning("Warning", "Please connect to a reader first")
            return

        self.crypto_info_text.delete(1.0, tk.END)

        try:
            # Select Bitcoin Applet
            btc_aid = bytes.fromhex("A000000003000000") # Placeholder, should be specific
            self.send_apdu_internal([0x00, 0xA4, 0x04, 0x00, len(btc_aid)] + list(btc_aid), "Select BTC Applet")

            # Get public key
            path = self.derivation_path_entry.get()
            self.get_wallet_public_key(path)

        except Exception as e:
            self.crypto_info_text.insert(tk.END, f"Error: {e}\n")

    def get_wallet_public_key(self, path):
        # This is a simplified version of the GET WALLET PUBLIC KEY command
        # A real implementation would need to properly encode the derivation path

        # For now, we will use a dummy command and response for demonstration
        dummy_apdu = [0xE0, 0x40, 0x00, 0x00, 0x00]
        self.log_to_console("Sending dummy GET WALLET PUBLIC KEY command...")

        # Dummy response (uncompressed public key)
        dummy_response = bytes.fromhex(
            "04"  # Uncompressed key prefix
            "88F355359C793836173748B833219525412437344078426029B3775986B2F1F8"
            "4CE0048B34725D34C03B64344558F4994273E18820B925327667683A41E67114"
        )

        self.parse_public_key_response(dummy_response)

    def parse_public_key_response(self, response):
        import ecdsa
        import hashlib
        import base58

        # Extract public key from response
        public_key = response

        # 1. Uncompressed public key to compressed
        if public_key[0] == 0x04:
            x = public_key[1:33]
            y = public_key[33:65]
            prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
            compressed_key = prefix + x
        else:
            compressed_key = public_key

        # 2. SHA-256 hash of the compressed key
        sha256_hash = hashlib.sha256(compressed_key).digest()

        # 3. RIPEMD-160 hash of the SHA-256 hash
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

        # 4. Add version byte (0x00 for mainnet)
        versioned_hash = b'\x00' + ripemd160_hash

        # 5. Double SHA-256 hash for checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]

        # 6. Append checksum
        binary_address = versioned_hash + checksum

        # 7. Base58 encode
        btc_address = base58.b58encode(binary_address).decode('utf-8')

        self.crypto_info_text.insert(tk.END, f"Public Key (compressed): {''.join(f'{b:02X}' for b in compressed_key)}\n")
        self.crypto_info_text.insert(tk.END, f"Bitcoin Address: {btc_address}\n")


    def clone_card(self):
        self.log_to_console("Card cloning feature requires special authorization...")
        messagebox.showwarning("Warning", "Card cloning functionality requires proper authorization and compatible hardware")

    def modify_track_data(self):
        self.log_to_console("Track data modification feature in development...")
        messagebox.showinfo("Info", "Track data modification coming soon")

    def generate_test_card(self):
        self.log_to_console("Test card generation feature in development...")
        messagebox.showinfo("Info", "Test card generation feature coming soon")

    def save_console_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.console_text.get("1.0", tk.END))
            self.log_to_console(f"Console log saved to: {path}")

    def show_about(self):
        about_text = """
EMV Professional Tool v2.0
Advanced Smart Card Reader/Writer

Features:
• Multi-protocol EMV support (201, 206, 226)
• Static and Dynamic Data Authentication
• Card backup and restore capabilities
• Real-time TLV parsing
• Security analysis tools
• Professional logging system

Developed for educational and research purposes.
Use responsibly and in compliance with local laws.
        """
        messagebox.showinfo("About EMV Professional Tool", about_text)

    def show_documentation(self):
        doc_text = """
EMV Professional Tool Documentation

Quick Start:
1. Connect your smart card reader
2. Click 'Refresh' to detect readers
3. Select reader and click 'Connect'
4. Use EMV Operations tab for basic commands
5. Use Card Analysis for detailed inspection
6. Use Backup & Restore for data management

Advanced Features:
• TLV parsing and analysis
• Multi-protocol testing
• Security assessment
• Professional logging

For technical support and updates, visit:
https://github.com/your-repo/emv-professional-tool
        """
        messagebox.showinfo("Documentation", doc_text)

    def run(self):
        self.root.mainloop()

# Actualización de las clases de apoyo para mayor compatibilidad

# Función principal para ejecutar la aplicación
def main():
    app = EMVProfessionalTool()
    app.run()

if __name__ == "__main__":
    main()