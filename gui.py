import tkinter as tk
from tkinter import filedialog, messagebox, ttk, StringVar
from tkinter.font import Font
import os
import webbrowser
import logging
from PIL import Image, ImageTk

# Import the modules and their loggers
from sysgen import generate_stub, SYSCALL_MAP, add_syscall, get_all_syscalls
from encryptor import encrypt_stub, ENCRYPTION_METHODS
from outputter import save_stub, OUTPUT_FORMATS, get_output_formats

# Configure logging for gui
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("gui")

class GoWhispersApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GoWhispers – Enterprise Edition")
        self.root.geometry("850x700")  # Increased size to accommodate new elements
        self.root.configure(bg="#f5f5f5")
        
        # Set application icon
        self.set_app_icon()
        
        # Add additional syscalls to the map
        self.add_extended_syscalls()
        
        # Custom fonts
        self.title_font = Font(family="Segoe UI", size=18, weight="bold")
        self.subtitle_font = Font(family="Segoe UI", size=10, slant="italic")
        self.label_font = Font(family="Segoe UI", size=10)
        self.button_font = Font(family="Segoe UI", size=10, weight="bold")
        self.log_font = Font(family="Consolas", size=9)
        
        # Apply a modern theme to ttk widgets
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles for ttk widgets
        style.configure('TCombobox', padding=5)
        style.configure('TLabelframe', background='#f5f5f5')
        style.configure('TLabelframe.Label', background='#f5f5f5', font=self.label_font)
        
        # Main container frame
        self.main_frame = tk.Frame(root, bg="#f5f5f5", padx=25, pady=15)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header frame with logo and title
        self.header_frame = tk.Frame(self.main_frame, bg="#f5f5f5")
        self.header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Title with company look
        self.title_frame = tk.Frame(self.header_frame, bg="#f5f5f5")
        self.title_frame.pack(side=tk.LEFT)
        
        self.title_label = tk.Label(self.title_frame, 
                                  text="GoWhispers", 
                                  font=self.title_font,
                                  bg="#f5f5f5",
                                  fg="#2c3e50")
        self.title_label.pack(anchor=tk.W)
        
        self.subtitle_label = tk.Label(self.title_frame, 
                                     text="Syscall Stub Generator for Security Professionals",
                                     font=self.subtitle_font,
                                     bg="#f5f5f5",
                                     fg="#7f8c8d")
        self.subtitle_label.pack(anchor=tk.W)
        
        # Help button in the header
        self.help_button = tk.Button(self.header_frame,
                                   text="?",
                                   command=self.show_help,
                                   font=Font(family="Segoe UI", size=12, weight="bold"),
                                   bg="#3498db",
                                   fg="white",
                                   width=2,
                                   height=1,
                                   borderwidth=0,
                                   padx=5,
                                   pady=2,
                                   relief=tk.FLAT,
                                   cursor="hand2")
        self.help_button.pack(side=tk.RIGHT, padx=10)
        
        # Create a canvas and add a separator line under the header
        separator = tk.Canvas(self.main_frame, height=2, bg="#f5f5f5", highlightthickness=0)
        separator.pack(fill=tk.X, pady=(0, 15))
        separator.create_line(0, 1, 1000, 1, fill="#e0e0e0")
        
        # Syscall entry frame
        self.syscall_frame = ttk.LabelFrame(self.main_frame, 
                                         text=" Syscall Configuration ", 
                                         padding=(15, 10))
        self.syscall_frame.pack(fill=tk.X, pady=8)
        
        # Syscall selection frame
        self.syscall_selection_frame = tk.Frame(self.syscall_frame, bg="#f5f5f5")
        self.syscall_selection_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.syscall_combo_label = tk.Label(self.syscall_selection_frame, 
                                          text="Add syscall:",
                                          font=self.label_font,
                                          bg="#f5f5f5")
        self.syscall_combo_label.pack(side=tk.LEFT, padx=(0, 5))
        
        # Create a combobox with all syscalls from SYSCALL_MAP
        self.syscall_var = StringVar()
        self.syscall_combo = ttk.Combobox(self.syscall_selection_frame, 
                                        textvariable=self.syscall_var,
                                        values=sorted(list(SYSCALL_MAP.keys())),
                                        width=30)
        self.syscall_combo.pack(side=tk.LEFT, padx=(0, 10))
        
        # Add button to add the selected syscall
        self.add_syscall_btn = tk.Button(self.syscall_selection_frame,
                                       text="Add",
                                       command=self.add_syscall,
                                       font=self.label_font,
                                       bg="#3498db",
                                       fg="white",
                                       activebackground="#2980b9",
                                       relief=tk.FLAT,
                                       padx=10,
                                       pady=2)
        self.add_syscall_btn.pack(side=tk.LEFT)
        
        # Custom syscall entry
        self.custom_syscall_frame = tk.Frame(self.syscall_frame, bg="#f5f5f5")
        self.custom_syscall_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.custom_syscall_label = tk.Label(self.custom_syscall_frame, 
                                           text="Custom Syscall:",
                                           font=self.label_font,
                                           bg="#f5f5f5")
        self.custom_syscall_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.custom_syscall_entry = tk.Entry(self.custom_syscall_frame, 
                                           width=20,
                                           font=self.label_font,
                                           relief=tk.SOLID,
                                           borderwidth=1,
                                           bg="white")
        self.custom_syscall_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        self.custom_syscall_id_label = tk.Label(self.custom_syscall_frame, 
                                              text="ID (hex):",
                                              font=self.label_font,
                                              bg="#f5f5f5")
        self.custom_syscall_id_label.pack(side=tk.LEFT, padx=(5, 5))
        
        self.custom_syscall_id_entry = tk.Entry(self.custom_syscall_frame, 
                                              width=8,
                                              font=self.label_font,
                                              relief=tk.SOLID,
                                              borderwidth=1,
                                              bg="white")
        self.custom_syscall_id_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        self.add_custom_btn = tk.Button(self.custom_syscall_frame,
                                      text="Add Custom",
                                      command=self.add_custom_syscall,
                                      font=self.label_font,
                                      bg="#3498db",
                                      fg="white",
                                      activebackground="#2980b9",
                                      relief=tk.FLAT,
                                      padx=10,
                                      pady=2)
        self.add_custom_btn.pack(side=tk.LEFT)
        
        # Selected syscalls section
        self.syscall_label = tk.Label(self.syscall_frame, 
                                     text="Selected Syscalls:",
                                     font=self.label_font,
                                     bg="#f5f5f5")
        self.syscall_label.pack(anchor=tk.W, pady=(10, 5))
        
        self.syscall_entry = tk.Entry(self.syscall_frame, 
                                     width=80,
                                     font=self.label_font,
                                     relief=tk.SOLID,
                                     borderwidth=1,
                                     bg="white")
        self.syscall_entry.pack(fill=tk.X, pady=(0, 5))
        
        # Clear button
        self.clear_syscalls_btn = tk.Button(self.syscall_frame,
                                          text="Clear All",
                                          command=self.clear_syscalls,
                                          font=self.label_font,
                                          bg="#e74c3c",
                                          fg="white",
                                          activebackground="#c0392b",
                                          relief=tk.FLAT,
                                          padx=10,
                                          pady=2)
        self.clear_syscalls_btn.pack(anchor=tk.E, pady=(0, 5))
        
        # Architecture option
        self.arch_frame = tk.Frame(self.syscall_frame, bg="#f5f5f5")
        self.arch_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.arch_label = tk.Label(self.arch_frame,
                                 text="Architecture:",
                                 font=self.label_font,
                                 bg="#f5f5f5")
        self.arch_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.arch_var = tk.StringVar(value="x64")
        self.arch_x64 = tk.Radiobutton(self.arch_frame, 
                                      text="x64", 
                                      variable=self.arch_var, 
                                      value="x64",
                                      bg="#f5f5f5",
                                      font=self.label_font)
        self.arch_x64.pack(side=tk.LEFT, padx=(0, 10))
        
        self.arch_x86 = tk.Radiobutton(self.arch_frame, 
                                      text="x86", 
                                      variable=self.arch_var, 
                                      value="x86",
                                      bg="#f5f5f5",
                                      font=self.label_font)
        self.arch_x86.pack(side=tk.LEFT)
        
        # Options frame
        self.options_frame = ttk.LabelFrame(self.main_frame,
                                         text=" Output Options ",
                                         padding=(15, 10))
        self.options_frame.pack(fill=tk.X, pady=8)
        
        # Options grid layout
        self.options_frame.columnconfigure(1, weight=1)
        
        # Format selection
        self.format_label = tk.Label(self.options_frame,
                                   text="Output Format:",
                                   font=self.label_font,
                                   bg="#f5f5f5")
        self.format_label.grid(row=0, column=0, padx=5, pady=8, sticky=tk.W)
        
        # Get supported formats from outputter
        output_formats = list(get_output_formats().keys())
        self.format_var = tk.StringVar(value="go")
        self.format_menu = ttk.Combobox(self.options_frame, 
                                       textvariable=self.format_var, 
                                       values=output_formats,
                                       state="readonly",
                                       width=15)
        self.format_menu.grid(row=0, column=1, padx=5, pady=8, sticky=tk.W)
        
        # Encryption selection
        self.enc_label = tk.Label(self.options_frame,
                                 text="Encryption Method:",
                                 font=self.label_font,
                                 bg="#f5f5f5")
        self.enc_label.grid(row=1, column=0, padx=5, pady=8, sticky=tk.W)
        
        # Get encryption methods from encryptor
        encryption_methods = list(ENCRYPTION_METHODS.keys())
        self.enc_var = tk.StringVar(value="none")
        self.enc_menu = ttk.Combobox(self.options_frame, 
                                    textvariable=self.enc_var, 
                                    values=encryption_methods,
                                    state="readonly",
                                    width=15)
        self.enc_menu.grid(row=1, column=1, padx=5, pady=8, sticky=tk.W)
        
        # Encryption key entry
        self.key_label = tk.Label(self.options_frame,
                                 text="Encryption Key:",
                                 font=self.label_font,
                                 bg="#f5f5f5")
        self.key_label.grid(row=2, column=0, padx=5, pady=8, sticky=tk.W)
        
        self.key_entry = tk.Entry(self.options_frame,
                                width=50,
                                font=self.label_font,
                                relief=tk.SOLID,
                                borderwidth=1,
                                bg="white")
        self.key_entry.grid(row=2, column=1, padx=5, pady=8, sticky=tk.W+tk.E)
        
        # Variable name option (for hex/go output)
        self.var_name_label = tk.Label(self.options_frame,
                                     text="Variable Name:",
                                     font=self.label_font,
                                     bg="#f5f5f5")
        self.var_name_label.grid(row=3, column=0, padx=5, pady=8, sticky=tk.W)
        
        self.var_name_entry = tk.Entry(self.options_frame,
                                     width=20,
                                     font=self.label_font,
                                     relief=tk.SOLID,
                                     borderwidth=1,
                                     bg="white")
        self.var_name_entry.insert(0, "payload")  # Default value
        self.var_name_entry.grid(row=3, column=1, padx=5, pady=8, sticky=tk.W)
        
        # Button frame with gradient button
        self.button_frame = tk.Frame(self.main_frame, bg="#f5f5f5")
        self.button_frame.pack(pady=15)
        
        self.out_btn = tk.Button(self.button_frame,
                               text="Generate Stub",
                               command=self.build_stub,
                               font=self.button_font,
                               bg="#2ecc71",
                               fg="white",
                               activebackground="#27ae60",
                               activeforeground="white",
                               relief=tk.FLAT,
                               padx=25,
                               pady=10,
                               cursor="hand2")
        self.out_btn.pack()
        
        # Output log frame
        self.log_frame = ttk.LabelFrame(self.main_frame,
                                     text=" Activity Log ",
                                     padding=(15, 10))
        self.log_frame.pack(fill=tk.BOTH, expand=True, pady=8)
        
        # Create a frame for the log and scrollbar
        self.log_container = tk.Frame(self.log_frame, bg="#f5f5f5")
        self.log_container.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar for log
        self.scrollbar = tk.Scrollbar(self.log_container)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log = tk.Text(self.log_container,
                          height=10,
                          width=80,
                          font=self.log_font,
                          bg="white",
                          fg="#333333",
                          relief=tk.SOLID,
                          borderwidth=1,
                          padx=5,
                          pady=5)
        self.log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Connect scrollbar to text widget
        self.log.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.log.yview)
        
        # Add a tag for colorizing success messages
        self.log.tag_configure("success", foreground="#27ae60")
        self.log.tag_configure("error", foreground="#e74c3c")
        self.log.tag_configure("info", foreground="#3498db")
        self.log.tag_configure("warning", foreground="#f39c12")
        
        # Status bar
        self.status_bar = tk.Label(self.root, 
                                 text="Ready", 
                                 bd=1, 
                                 relief=tk.SUNKEN, 
                                 anchor=tk.W,
                                 font=Font(family="Segoe UI", size=8),
                                 bg="#e0e0e0",
                                 padx=5,
                                 pady=2)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Version info in status bar
        self.version_label = tk.Label(self.status_bar,
                                    text="v1.3.0 Enterprise",
                                    font=Font(family="Segoe UI", size=8),
                                    bg="#e0e0e0")
        self.version_label.pack(side=tk.RIGHT, padx=5)
        
        # Initialize log with welcome message
        self.initialize_log()

    def initialize_log(self):
        """Initialize the activity log with welcome message and system info"""
        self.log.insert(tk.END, "===================================================\n")
        self.log.insert(tk.END, "GoWhispers Enterprise Edition v1.3.0 initialized\n", "info")
        self.log.insert(tk.END, "===================================================\n")
        self.log.insert(tk.END, "System information:\n")
        self.log.insert(tk.END, f"• Total syscalls available: {len(SYSCALL_MAP)}\n")
        self.log.insert(tk.END, f"• Default architecture: {self.arch_var.get()}\n")
        self.log.insert(tk.END, f"• Default output format: {self.format_var.get()}\n")
        self.log.insert(tk.END, f"• Available output formats: {', '.join(get_output_formats().keys())}\n")
        self.log.insert(tk.END, f"• Available encryption methods: {', '.join(ENCRYPTION_METHODS.keys())}\n")
        self.log.insert(tk.END, "===================================================\n")
        self.log.insert(tk.END, "Ready to generate syscall stubs\n", "success")
        self.log.insert(tk.END, "• Select syscalls from the dropdown or add custom syscalls\n")
        self.log.insert(tk.END, "• Configure output options and encryption if needed\n")
        self.log.insert(tk.END, "• Click 'Generate Stub' when ready\n")
        self.log.insert(tk.END, "===================================================\n")
        self.log.insert(tk.END, "Use the ? button in the top-right corner for detailed help\n")
        self.log.insert(tk.END, "===================================================\n")
        
        # Make sure log scrolls to the bottom
        self.log.see(tk.END)

    def set_app_icon(self):
        """Set the application icon"""
        try:
            # Check if icon.png exists
            if os.path.exists("icon.png"):
                # For Windows and Linux
                icon = tk.PhotoImage(file="icon.png")
                self.root.iconphoto(True, icon)
                
                # Create a small version of the icon for the title bar
                icon_img = Image.open("icon.png")
                icon_img = icon_img.resize((24, 24), Image.LANCZOS)
                self.icon_image = ImageTk.PhotoImage(icon_img)
                logger.info("Loaded application icon from icon.png")
            else:
                # Log icon not found
                logger.warning("Icon file 'icon.png' not found, using default icon")
                self.log.insert(tk.END, "Icon file 'icon.png' not found, using default icon\n", "warning")
        except Exception as e:
            logger.error(f"Error setting icon: {str(e)}")
            print(f"Error setting icon: {str(e)}")

    def show_help(self):
        """Display help information"""
        # Updated help text with information about the new features
        help_text = """
GoWhispers Enterprise Edition Help

Purpose:
This tool generates Windows syscall stubs for various applications including security research, 
system programming, and malware analysis.

Usage:
1. Select syscalls from the dropdown or add custom ones
2. Choose your output format (Go, C, Hex, or Binary)
3. Select encryption method if desired
4. Optionally specify a variable name for generated code
5. Click "Generate Stub" to create and save your stub

Supported Syscalls:
- The dropdown contains all supported syscalls with their respective IDs
- Custom syscalls can be added using the "Custom Syscall" section
- Added syscalls remain available in the dropdown for the duration of the session

Architecture:
- x64: 64-bit systems (default)
- x86: 32-bit systems

Output Formats:
- go: Go language source code
- c: C language source code
- hex: Hexadecimal text representation
- bin: Raw binary output
- raw: Raw text output

Encryption:
- none: No encryption
- aes: AES-256 GCM mode encryption (requires key)
- xor: SHA-256 based XOR encryption (requires key)

Variable Name:
- For hex and go formats, you can specify a custom variable name
- Defaults to "payload" if not specified

File Handling:
- All output files are saved with UTF-8 encoding
- Binary files are saved in chunk mode for better performance
- Metadata is generated for all saved files

For more information, contact echohollow@tutamail.com
        """
        
        help_window = tk.Toplevel(self.root)
        help_window.title("GoWhispers Help")
        help_window.geometry("600x500")
        help_window.resizable(True, True)
        help_window.configure(bg="#f5f5f5")
        
        # Set same icon as main window
        if hasattr(self, 'icon_image'):
            help_window.iconphoto(True, self.icon_image)
        
        # Title
        help_title = tk.Label(help_window, 
                            text="GoWhispers Enterprise Edition Help",
                            font=self.title_font,
                            bg="#f5f5f5",
                            fg="#2c3e50")
        help_title.pack(pady=(20, 10))
        
        # Help content
        help_frame = tk.Frame(help_window, bg="#f5f5f5", padx=20, pady=10)
        help_frame.pack(fill=tk.BOTH, expand=True)
        
        # Text widget with scrollbar
        help_text_container = tk.Frame(help_frame, bg="#f5f5f5")
        help_text_container.pack(fill=tk.BOTH, expand=True)
        
        help_scrollbar = tk.Scrollbar(help_text_container)
        help_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        help_content = tk.Text(help_text_container,
                             width=70,
                             height=20,
                             font=self.label_font,
                             bg="white",
                             fg="#333333",
                             padx=10,
                             pady=10,
                             wrap=tk.WORD)
        help_content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        help_content.insert(tk.END, help_text)
        help_content.config(state=tk.DISABLED)  # Make it read-only
        
        # Connect scrollbar
        help_scrollbar.config(command=help_content.yview)
        help_content.config(yscrollcommand=help_scrollbar.set)
        
        # Close button
        close_button = tk.Button(help_window,
                               text="Close",
                               command=help_window.destroy,
                               font=self.button_font,
                               bg="#3498db",
                               fg="white",
                               activebackground="#2980b9",
                               padx=20,
                               pady=5,
                               relief=tk.FLAT)
        close_button.pack(pady=(0, 20))
        
        # Center the window
        help_window.update_idletasks()
        width = help_window.winfo_width()
        height = help_window.winfo_height()
        x = (help_window.winfo_screenwidth() // 2) - (width // 2)
        y = (help_window.winfo_screenheight() // 2) - (height // 2)
        help_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
        # Make the window modal
        help_window.transient(self.root)
        help_window.grab_set()
        self.root.wait_window(help_window)
        
        # Log help access
        logger.info("Help dialog was opened")

    def add_syscall(self):
        """Add selected syscall from dropdown to the syscall list"""
        selected = self.syscall_var.get()
        if not selected:
            return
            
        current = self.syscall_entry.get()
        if current:
            # Add comma if there are already syscalls
            self.syscall_entry.delete(0, tk.END)
            self.syscall_entry.insert(0, current + ", " + selected)
        else:
            self.syscall_entry.insert(0, selected)
            
        # Log the action
        self.log.insert(tk.END, f"Added syscall: {selected} (ID: 0x{SYSCALL_MAP[selected]:X})\n")
        logger.info(f"Added syscall: {selected} (ID: 0x{SYSCALL_MAP[selected]:X})")
        
        # Clear selection
        self.syscall_combo.set('')
        
        # Scroll log to the bottom
        self.log.see(tk.END)
    
    def add_custom_syscall(self):
        """Add custom syscall with specified ID"""
        name = self.custom_syscall_entry.get().strip()
        id_hex = self.custom_syscall_id_entry.get().strip()
        
        # Validate inputs
        if not name:
            messagebox.showerror("Error", "Please enter a syscall name.")
            return
            
        if not name.startswith("Nt") or not name[2:3].isupper():
            messagebox.showerror("Error", "Syscall name must start with 'Nt' followed by a capital letter.")
            return
            
        if not id_hex:
            messagebox.showerror("Error", "Please enter a syscall ID in hexadecimal.")
            return
            
        try:
            # Try to convert hex to int
            if id_hex.startswith("0x"):
                id_hex = id_hex[2:]
            syscall_id = int(id_hex, 16)
            
            # Use the add_syscall function from sysgen
            try:
                # Add to SYSCALL_MAP using sysgen function
                add_syscall(name, syscall_id)
                
                # Update the combobox values
                self.syscall_combo['values'] = sorted(list(SYSCALL_MAP.keys()))
                
                # Add to syscalls entry
                current = self.syscall_entry.get()
                if current:
                    self.syscall_entry.delete(0, tk.END)
                    self.syscall_entry.insert(0, current + ", " + name)
                else:
                    self.syscall_entry.insert(0, name)
                    
                # Log the action
                self.log.insert(tk.END, f"Added custom syscall: {name} (ID: 0x{syscall_id:X})\n")
                logger.info(f"Added custom syscall: {name} (ID: 0x{syscall_id:X})")
                
                # Clear entries
                self.custom_syscall_entry.delete(0, tk.END)
                self.custom_syscall_id_entry.delete(0, tk.END)
                
                # Scroll log to the bottom
                self.log.see(tk.END)
                
            except ValueError as e:
                messagebox.showerror("Error", str(e))
                
        except ValueError:
            messagebox.showerror("Error", "Invalid hexadecimal value for syscall ID.")
    
    def add_extended_syscalls(self):
        extended_syscalls = {
            "NtWaitForSingleObject": 0x4,
            "NtSetEvent": 0x9,
            "NtCreateEvent": 0x43,
            "NtDuplicateObject": 0x39,
            "NtQueryDirectoryFile": 0x47,
            "NtEnumerateKey": 0x33,
            "NtCreateKey": 0x29,
            "NtOpenKey": 0x10,
            "NtSetValueKey": 0x1A,
            "NtQueryValueKey": 0x16,
            "NtDeviceIoControlFile": 0x7,
            "NtFsControlFile": 0x39,
            "NtGetContextThread": 0xB8,
            "NtSetContextThread": 0xBE,
            "NtResumeThread": 0x51,
            "NtSuspendThread": 0x1D,
            "NtQueryInformationProcess": 0x19,
            "NtQueryInformationThread": 0x24,
            "NtSetInformationThread": 0x0A,
            "NtSetInformationProcess": 0x1C,
            "NtVirtualProtect": 0x4D,
            "NtVirtualAlloc": 0x15,
            "NtCreateUserProcess": 0xC2,
            "NtOpenThread": 0x43,
            "NtQueueApcThread": 0x44,
            "NtYieldExecution": 0x46,
            "NtCreateNamedPipeFile": 0x99,
            "NtLoadDriver": 0x60,
            "NtUnloadDriver": 0x52,
            "NtRaiseHardError": 0x42,
            "NtAdjustPrivilegesToken": 0x3E,
            "NtOpenProcessToken": 0x23,
            "NtOpenThreadToken": 0x25
        }
    
        # Update the SYSCALL_MAP with additional syscalls
        SYSCALL_MAP.update(extended_syscalls)
        
        # Log addition
        logger.info(f"Added {len(extended_syscalls)} extended syscalls")
    
        # Update the SYSCALL_MAP with additional syscalls
        for name, syscall_id in extended_syscalls.items():
            try:
                # Use add_syscall function from sysgen module if available
                if 'add_syscall' in globals():
                    add_syscall(name, syscall_id)
                else:
                    # Fall back to direct update
                    SYSCALL_MAP[name] = syscall_id
            except Exception as e:
                logger.warning(f"Could not add syscall {name}: {str(e)}")
        
    
    def clear_syscalls(self):
        """Clear all selected syscalls"""
        self.syscall_entry.delete(0, tk.END)
        self.log.insert(tk.END, "Cleared all selected syscalls\n")
        logger.info("Cleared all selected syscalls")
        
        # Scroll log to the bottom
        self.log.see(tk.END)
    
    def build_stub(self):
        """Build syscall stub based on selected parameters"""
        # Get parameters from UI
        syscalls = [x.strip() for x in self.syscall_entry.get().split(",") if x.strip()]
        fmt = self.format_var.get()
        enc = self.enc_var.get()
        key = self.key_entry.get().strip()
        arch = self.arch_var.get()
        var_name = self.var_name_entry.get().strip() if hasattr(self, 'var_name_entry') else "payload"

        # Validate input
        if not syscalls:
            messagebox.showerror("Error", "Please enter at least one syscall.")
            return

        # Update status
        self.status_bar.config(text="Processing...")
        self.log.insert(tk.END, "Starting stub generation process...\n")
        self.root.update_idletasks()

        try:
            # Step 1: Stub generation
            logger.info(f"Generating {fmt} stub for {len(syscalls)} syscalls with {arch} architecture")
            stub = generate_stub(syscalls, fmt, arch)
            self.log.insert(tk.END, f"Generated {fmt} stub for {len(syscalls)} syscalls ({arch} architecture)\n")

            # Step 2: Encryption
            try:
                logger.info(f"Applying {enc} encryption")
                encrypted = encrypt_stub(stub, enc, key)
                if enc != "none":
                    self.log.insert(tk.END, f"Applied {enc.upper()} encryption\n")
            except Exception as e:
                logger.error(f"Encryption failed: {str(e)}")
                messagebox.showerror("Encryption Error", str(e))
                self.log.insert(tk.END, f"❌ Encryption failed: {str(e)}\n", "error")
                self.status_bar.config(text="Ready")
                return

            # Step 3: Save
            extension = "." + fmt
            if fmt == "bin":
                extension = ".bin"
            elif fmt == "hex":
                extension = ".txt"
                
            out_path = filedialog.asksaveasfilename(
                defaultextension=extension,
                filetypes=[
                    ("Go Files", "*.go"),
                    ("C Files", "*.c"),
                    ("Hex Files", "*.txt"),
                    ("Binary Files", "*.bin"),
                    ("All Files", "*.*")
                ]
            )
            
            if out_path:
                try:
                    # Save with additional parameters
                    save_result = save_stub(encrypted, fmt, out_path, var_name=var_name)
                    
                    # Display metadata
                    self.log.insert(tk.END, f"✅ Stub successfully saved to {out_path}\n", "success")
                    self.log.insert(tk.END, f"   Size: {save_result['size']} bytes\n")
                    self.log.insert(tk.END, f"   SHA256: {save_result['sha256']}\n")
                    
                    # Display additional metadata if available
                    if 'size_on_disk' in save_result and save_result['size_on_disk']:
                        self.log.insert(tk.END, f"   Size on disk: {save_result['size_on_disk']} bytes\n")
                    if 'created' in save_result and save_result['created']:
                        self.log.insert(tk.END, f"   Created: {save_result['created']}\n")
                        
                    self.status_bar.config(text=f"Saved to {out_path}")
                    logger.info(f"Stub saved to {out_path}")
                except Exception as e:
                    logger.error(f"Save failed: {str(e)}")
                    messagebox.showerror("Save Error", str(e))
                    self.log.insert(tk.END, f"❌ Save failed: {str(e)}\n", "error")
                    self.status_bar.config(text="Ready")
            else:
                self.log.insert(tk.END, f"❌ Save operation canceled\n", "error")
                self.status_bar.config(text="Ready")
                logger.info("Save operation canceled by user")
                    
        except Exception as e:
            logger.error(f"Stub generation error: {str(e)}")
            messagebox.showerror("Error", str(e))
            self.log.insert(tk.END, f"❌ Error: {str(e)}\n", "error")
            self.status_bar.config(text="Ready")
        
        # Scroll log to the bottom
        self.log.see(tk.END)
        
if __name__ == "__main__":
    root = tk.Tk()
    app = GoWhispersApp(root)
    root.mainloop()