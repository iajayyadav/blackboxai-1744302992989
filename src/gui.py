import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import os
from .encryption import FileEncryptor
from .password_manager import PasswordManager
from .db_logger import HistoryLogger
import threading

class SecureFileLockerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Locker 🔐")
        self.root.geometry("900x600")
        
        # Initialize components
        self.encryptor = FileEncryptor()
        self.password_manager = PasswordManager()
        self.history_logger = HistoryLogger()
        
        # Setup GUI
        self.setup_styles()
        self.create_widgets()
        
        # Selected file path
        self.selected_file = None
        
    def setup_styles(self):
        """Configure custom styles for widgets"""
        style = ttk.Style()
        style.configure('Action.TButton',
                       padding=10,
                       font=('Helvetica', 12))
        style.configure('History.TFrame',
                       background='#f0f0f0')
        style.configure('History.Treeview',
                       font=('Helvetica', 10),
                       rowheight=25)
                       
    def create_widgets(self):
        """Create and arrange all GUI widgets"""
        # Main container
        main_container = ttk.Frame(self.root, padding="10")
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_container.columnconfigure(1, weight=1)
        main_container.rowconfigure(3, weight=1)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_container, text="File Selection", padding="10")
        file_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.file_label = ttk.Label(file_frame, text="No file selected")
        self.file_label.grid(row=0, column=0, sticky=tk.W, padx=5)
        
        select_btn = ttk.Button(file_frame, text="Select File",
                              command=self.select_file,
                              style='Action.TButton')
        select_btn.grid(row=0, column=1, padx=5)
        
        # Password frame
        pwd_frame = ttk.LabelFrame(main_container, text="Password Management", padding="10")
        pwd_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        set_pwd_btn = ttk.Button(pwd_frame, text="Set Password",
                                command=self.set_password,
                                style='Action.TButton')
        set_pwd_btn.grid(row=0, column=0, padx=5)
        
        # Action buttons frame
        action_frame = ttk.Frame(main_container, padding="10")
        action_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        encrypt_btn = ttk.Button(action_frame, text="🔒 Encrypt File",
                               command=self.encrypt_file,
                               style='Action.TButton')
        encrypt_btn.grid(row=0, column=0, padx=5)
        
        decrypt_btn = ttk.Button(action_frame, text="🔓 Decrypt File",
                               command=self.decrypt_file,
                               style='Action.TButton')
        decrypt_btn.grid(row=0, column=1, padx=5)
        
        # History frame
        history_frame = ttk.LabelFrame(main_container, text="Operation History", padding="10")
        history_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Create Treeview for history
        self.history_tree = ttk.Treeview(history_frame, style='History.Treeview',
                                       columns=('Time', 'Operation', 'File', 'Status'),
                                       show='headings')
        
        # Configure columns
        self.history_tree.heading('Time', text='Time')
        self.history_tree.heading('Operation', text='Operation')
        self.history_tree.heading('File', text='File')
        self.history_tree.heading('Status', text='Status')
        
        self.history_tree.column('Time', width=150)
        self.history_tree.column('Operation', width=100)
        self.history_tree.column('File', width=300)
        self.history_tree.column('Status', width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL,
                                command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Grid history components
        self.history_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure history frame grid
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
        
        # Load initial history
        self.update_history()
        
    def select_file(self):
        """Open file dialog and store selected file path"""
        filepath = filedialog.askopenfilename()
        if filepath:
            self.selected_file = filepath
            self.file_label.config(text=os.path.basename(filepath))
            
    def set_password(self):
        """Open dialog to set encryption password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Set Password")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        
        ttk.Label(dialog, text="Enter New Password:").pack(pady=5)
        pwd_entry = ttk.Entry(dialog, show="*")
        pwd_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Confirm Password:").pack(pady=5)
        confirm_entry = ttk.Entry(dialog, show="*")
        confirm_entry.pack(pady=5)
        
        def save_password():
            pwd = pwd_entry.get()
            confirm = confirm_entry.get()
            
            if pwd != confirm:
                messagebox.showerror("Error", "Passwords do not match!")
                return
                
            try:
                self.password_manager.set_password(pwd)
                messagebox.showinfo("Success", "Password set successfully!")
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Error", str(e))
                
        ttk.Button(dialog, text="Save Password",
                  command=save_password).pack(pady=20)
                  
    def encrypt_file(self):
        """Encrypt the selected file"""
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return
            
        # Get password
        pwd = self.get_password("Enter password for encryption:")
        if not pwd:
            return
            
        try:
            # Start encryption in a separate thread
            thread = threading.Thread(target=self._encrypt_file_thread, args=(pwd,))
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            self.history_logger.log_operation(
                self.selected_file,
                "encrypt",
                "failed",
                str(e)
            )
            self.update_history()
            
    def _encrypt_file_thread(self, password):
        """Handle file encryption in a separate thread"""
        try:
            encrypted_path = self.encryptor.encrypt_file(self.selected_file, password)
            
            # Log success
            self.history_logger.log_operation(
                self.selected_file,
                "encrypt",
                "success"
            )
            
            # Update UI in main thread
            self.root.after(0, lambda: self._show_success("File encrypted successfully!"))
            self.root.after(0, self.update_history)
            
        except Exception as e:
            # Update UI in main thread
            self.root.after(0, lambda: messagebox.showerror("Encryption Error", str(e)))
            self.history_logger.log_operation(
                self.selected_file,
                "encrypt",
                "failed",
                str(e)
            )
            self.root.after(0, self.update_history)
            
    def decrypt_file(self):
        """Decrypt the selected file"""
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return
            
        if not self.selected_file.endswith('.locked'):
            messagebox.showerror("Error", "Selected file is not an encrypted file!")
            return
            
        # Get password
        pwd = self.get_password("Enter password for decryption:")
        if not pwd:
            return
            
        try:
            # Start decryption in a separate thread
            thread = threading.Thread(target=self._decrypt_file_thread, args=(pwd,))
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            self.history_logger.log_operation(
                self.selected_file,
                "decrypt",
                "failed",
                str(e)
            )
            self.update_history()
            
    def _decrypt_file_thread(self, password):
        """Handle file decryption in a separate thread"""
        try:
            decrypted_path = self.encryptor.decrypt_file(self.selected_file, password)
            
            # Log success
            self.history_logger.log_operation(
                self.selected_file,
                "decrypt",
                "success"
            )
            
            # Update UI in main thread
            self.root.after(0, lambda: self._show_success("File decrypted successfully!"))
            self.root.after(0, self.update_history)
            
        except Exception as e:
            # Update UI in main thread
            self.root.after(0, lambda: messagebox.showerror("Decryption Error", str(e)))
            self.history_logger.log_operation(
                self.selected_file,
                "decrypt",
                "failed",
                str(e)
            )
            self.root.after(0, self.update_history)
            
    def get_password(self, prompt):
        """Show password dialog and return entered password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter Password")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        
        password = None
        
        def on_ok():
            nonlocal password
            password = pwd_entry.get()
            dialog.destroy()
            
        ttk.Label(dialog, text=prompt).pack(pady=10)
        pwd_entry = ttk.Entry(dialog, show="*")
        pwd_entry.pack(pady=10)
        
        ttk.Button(dialog, text="OK", command=on_ok).pack(pady=10)
        
        # Wait for dialog to close
        dialog.grab_set()
        self.root.wait_window(dialog)
        
        return password
        
    def _show_success(self, message):
        """Show success message"""
        messagebox.showinfo("Success", message)
        
    def update_history(self):
        """Update the history treeview with latest operations"""
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
            
        # Get history from database
        history = self.history_logger.get_history()
        
        # Add items to treeview
        for entry in history:
            self.history_tree.insert(
                '',
                'end',
                values=(
                    datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
                    entry['operation'].capitalize(),
                    os.path.basename(entry['file_path']),
                    entry['status'].capitalize()
                )
            )
