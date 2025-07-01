from tkinter import *
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import hashlib
import base64

BLOCK_SIZE = 16  # Bytes
KEY_SIZE = 32    # 256 bits

class EncryptionTool:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureCrypt - AES-256 Encryption Tool")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        self.root.configure(bg="#f0f2f5")
        
        # Set application icon
        try:
            self.root.iconbitmap("lock_icon.ico")
        except:
            pass
        
        # Create style for themed widgets
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f2f5')
        self.style.configure('TButton', font=('Arial', 10), padding=6)
        self.style.configure('Header.TLabel', background='#4a6cf7', 
                            foreground='white', font=('Arial', 14, 'bold'))
        self.style.configure('TLabel', background='#f0f2f5', font=('Arial', 10))
        self.style.configure('TEntry', font=('Arial', 10))
        self.style.configure('Status.TLabel', background='#e3e7ff', 
                            foreground='#4a6cf7', font=('Arial', 9))
        
        self.file_path = StringVar()
        self.password = StringVar()
        self.status_text = StringVar(value="Ready")
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=X, padx=10, pady=10)
        
        header_label = ttk.Label(header_frame, text="SecureCrypt - AES-256 Encryption", 
                                style='Header.TLabel')
        header_label.pack(fill=X, ipady=10)
        
        # Main content frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        # File selection section
        file_frame = ttk.LabelFrame(main_frame, text=" File Selection ")
        file_frame.pack(fill=X, pady=(0, 15))
        
        ttk.Label(file_frame, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky=W)
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path, width=50)
        file_entry.grid(row=0, column=1, padx=5, pady=5, sticky=EW)
        
        browse_btn = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Password section
        password_frame = ttk.LabelFrame(main_frame, text=" Encryption Settings ")
        password_frame.pack(fill=X, pady=(0, 15))
        
        ttk.Label(password_frame, text="Password:").grid(row=0, column=0, padx=5, pady=5, sticky=W)
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password, 
                                       show="•", width=30)
        self.password_entry.grid(row=0, column=1, padx=5, pady=5, sticky=EW)
        
        # Password strength meter
        strength_frame = ttk.Frame(password_frame)
        strength_frame.grid(row=1, column=1, sticky=W, padx=5, pady=2)
        
        ttk.Label(strength_frame, text="Strength:").pack(side=LEFT)
        self.strength_meter = ttk.Progressbar(strength_frame, length=150, mode='determinate')
        self.strength_meter.pack(side=LEFT, padx=5)
        self.strength_label = ttk.Label(strength_frame, text="")
        self.strength_label.pack(side=LEFT)
        
        # Password visibility toggle
        self.show_password = BooleanVar(value=False)
        show_pass_btn = ttk.Checkbutton(password_frame, text="Show Password", 
                                        variable=self.show_password,
                                        command=self.toggle_password_visibility)
        show_pass_btn.grid(row=2, column=1, padx=5, pady=2, sticky=W)
        
        # Password note
        ttk.Label(password_frame, text="Note: Password must be 32 characters for AES-256", 
                  foreground="#666", font=('Arial', 9)).grid(row=3, column=1, padx=5, pady=2, sticky=W)
        
        # Action buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=X, pady=15)
        
        encrypt_btn = ttk.Button(btn_frame, text="Encrypt File", 
                                command=self.do_encrypt, style='TButton')
        encrypt_btn.pack(side=LEFT, padx=10, ipadx=20)
        
        decrypt_btn = ttk.Button(btn_frame, text="Decrypt File", 
                                command=self.do_decrypt, style='TButton')
        decrypt_btn.pack(side=LEFT, padx=10, ipadx=20)
        
        clear_btn = ttk.Button(btn_frame, text="Clear All", 
                              command=self.clear_fields)
        clear_btn.pack(side=RIGHT, padx=10)
        
        # Status bar
        status_frame = ttk.Frame(self.root, height=30)
        status_frame.pack(fill=X, side=BOTTOM)
        
        status_label = ttk.Label(status_frame, textvariable=self.status_text, 
                               style='Status.TLabel', anchor=W, padding=(10, 5))
        status_label.pack(fill=X)
        
        # Set up password strength monitoring
        self.password.trace_add('write', self.update_password_strength)
        
        # Center the window
        self.center_window()
        
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)
            self.update_status(f"Selected file: {os.path.basename(file_path)}")
            
    def toggle_password_visibility(self):
        if self.show_password.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="•")
            
    def update_password_strength(self, *args):
        password = self.password.get()
        strength = 0
        
        if len(password) > 0:
            # Length contributes up to 40%
            length_strength = min(40, len(password) * 4)
            strength += length_strength
            
            # Character diversity contributes up to 60%
            diversity = 0
            if any(c.isdigit() for c in password): diversity += 10
            if any(c.islower() for c in password): diversity += 10
            if any(c.isupper() for c in password): diversity += 10
            if any(not c.isalnum() for c in password): diversity += 30
            strength += min(60, diversity)
            
        self.strength_meter['value'] = strength
        
        # Update strength label
        if strength == 0:
            strength_text = ""
        elif strength < 40:
            strength_text = "Weak"
            self.strength_label.configure(foreground="#e74c3c")
        elif strength < 70:
            strength_text = "Medium"
            self.strength_label.configure(foreground="#f39c12")
        else:
            strength_text = "Strong"
            self.strength_label.configure(foreground="#2ecc71")
            
        self.strength_label.configure(text=strength_text)
        
    def clear_fields(self):
        self.file_path.set("")
        self.password.set("")
        self.show_password.set(False)
        self.password_entry.configure(show="•")
        self.strength_meter['value'] = 0
        self.strength_label.configure(text="")
        self.update_status("Ready")
        
    def update_status(self, message):
        self.status_text.set(message)
        
    def pad(self, data):
        padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
        return data + bytes([padding]) * padding

    def unpad(self, data):
        padding = data[-1]
        return data[:-padding]
    
    def encrypt_file(self, file_path, key):
        with open(file_path, 'rb') as f:
            data = f.read()
        data = self.pad(data)
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(data)
        encrypted_file = file_path + ".enc"
        with open(encrypted_file, 'wb') as f:
            f.write(encrypted_data)
        return encrypted_file

    def decrypt_file(self, file_path, key):
        with open(file_path, 'rb') as f:
            data = f.read()
        iv = data[:BLOCK_SIZE]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = self.unpad(cipher.decrypt(data[BLOCK_SIZE:]))
        original_path = file_path.replace(".enc", "")
        if original_path == file_path:  # If file didn't have .enc extension
            original_path += ".dec"
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        return original_path

    def do_encrypt(self):
        path = self.file_path.get()
        password = self.password.get()
        
        if not path:
            self.update_status("Error: Please select a file")
            messagebox.showerror("Error", "Please select a file to encrypt.")
            return
            
        if len(password) != KEY_SIZE:
            self.update_status("Error: Password must be 32 characters")
            messagebox.showerror("Error", "Password must be exactly 32 characters for AES-256.")
            return
            
        try:
            key = password.encode('utf-8')
            encrypted_file = self.encrypt_file(path, key)
            self.update_status(f"File encrypted successfully: {os.path.basename(encrypted_file)}")
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {os.path.basename(encrypted_file)}")
        except Exception as e:
            self.update_status(f"Encryption error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def do_decrypt(self):
        path = self.file_path.get()
        password = self.password.get()
        
        if not path:
            self.update_status("Error: Please select a file")
            messagebox.showerror("Error", "Please select a file to decrypt.")
            return
            
        if len(password) != KEY_SIZE:
            self.update_status("Error: Password must be 32 characters")
            messagebox.showerror("Error", "Password must be exactly 32 characters for AES-256.")
            return
            
        try:
            key = password.encode('utf-8')
            decrypted_file = self.decrypt_file(path, key)
            self.update_status(f"File decrypted successfully: {os.path.basename(decrypted_file)}")
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {os.path.basename(decrypted_file)}")
        except Exception as e:
            self.update_status(f"Decryption error: {str(e)}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = Tk()
    app = EncryptionTool(root)
    root.mainloop()