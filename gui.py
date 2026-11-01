import main
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import random
import os
from main import (
    Grain128AEAD,
    encrypt_key_with_password,
    decrypt_key_with_password,
    hex_string_to_bits,
    bits_to_bytes,
    bits_to_hex_string,
    load_hex_bits_from_file,
    read_plaintext,
    read_ciphertext,
    text_to_bits
)


# GUI Application
class GrainGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Grain-128 AEAD v2")
        self.root.geometry("850x650")  # window size
        
        # Configure style for larger tabs
        self.style = ttk.Style()
        self.style.configure('Larger.TNotebook.Tab', padding=[20, 12], font=('TkDefaultFont', 10))
        self.style.configure('Large.TButton', font=('TkDefaultFont', 10))
        self.style.configure('Large.TLabel', font=('TkDefaultFont', 10))
        self.style.configure('Large.TLabelframe.Label', font=('TkDefaultFont', 10))
        
        self.cipher = Grain128AEAD()
        self.key_bits = []
        self.iv_bits = []
        self.key_loaded = False
        self.iv_loaded = False
        
        self.create_widgets()
    
    def create_widgets(self):
        # Create notebook for tabs with larger style
        self.notebook = ttk.Notebook(self.root, style='Larger.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)  # Increased padding
        
        # Setup Tab
        self.tab_setup = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_setup, text="Setup Key & IV")
        self.create_setup_tab(self.tab_setup)
        
        # Encryption Tab
        self.tab_encrypt = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_encrypt, text="Encryption")
        self.create_encrypt_tab(self.tab_encrypt)
        
        # Decryption Tab
        self.tab_decrypt = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_decrypt, text="Decryption")
        self.create_decrypt_tab(self.tab_decrypt)
        
        # Enhanced navigation buttons
        self.go_encrypt = tk.Button(self.tab_setup, text="Go to Encrypt Tab",
                                    command=lambda: self.notebook.select(self.tab_encrypt),
                                    font=('TkDefaultFont', 10, 'bold'),
                                    padx=15, pady=8,
                                    bg='#4CAF50', fg='white',
                                    relief='raised', bd=2)
        self.go_decrypt = tk.Button(self.tab_setup, text="Go to Decrypt Tab",
                                    command=lambda: self.notebook.select(self.tab_decrypt),
                                    font=('TkDefaultFont', 10, 'bold'),
                                    padx=15, pady=8,
                                    bg='#2196F3', fg='white',
                                    relief='raised', bd=2)
        
        # Keep them hidden at first
        self.go_encrypt.pack_forget()
        self.go_decrypt.pack_forget()

    
    def create_setup_tab(self, parent):
        # Key Section
        key_frame = ttk.LabelFrame(parent, text="Key (128 bits, hex form)", padding=12)  # Increased padding
        key_frame.pack(fill=tk.X, padx=12, pady=8)  # Increased padding
        
        self.key_entry = tk.Text(key_frame, height=3, width=50, font=('Consolas', 10))  # Added font
        self.key_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bind events for auto-loading key
        self.key_entry.bind('<KeyRelease>', self.on_key_change)
        self.key_entry.bind('<Button-1>', self.on_key_change)  # For mouse paste
        self.key_entry.bind('<Control-v>', self.on_key_paste)
        
        key_btn_frame = ttk.Frame(key_frame)
        key_btn_frame.pack(side=tk.RIGHT, padx=(12, 0))
        
        # Enhanced buttons with larger size
        ttk.Button(key_btn_frame, text="Generate", command=self.generate_key,
                  width=14).pack(pady=4)  # Increased width and padding
        ttk.Button(key_btn_frame, text="Load from File", command=self.load_key_file,
                  width=14).pack(pady=4)
        ttk.Button(key_btn_frame, text="Save to File", command=self.save_key_file,
                  width=14).pack(pady=4)
        
        # IV Section
        iv_frame = ttk.LabelFrame(parent, text="IV (96 bits, hex form)", padding=12)  # Increased padding
        iv_frame.pack(fill=tk.X, padx=12, pady=8)  # Increased padding
        
        self.iv_entry = tk.Text(iv_frame, height=3, width=50, font=('Consolas', 10))  # Added font
        self.iv_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bind events for auto-loading IV
        self.iv_entry.bind('<KeyRelease>', self.on_iv_change)
        self.iv_entry.bind('<Button-1>', self.on_iv_change)  # For mouse paste
        self.iv_entry.bind('<Control-v>', self.on_iv_paste)
        
        iv_btn_frame = ttk.Frame(iv_frame)
        iv_btn_frame.pack(side=tk.RIGHT, padx=(12, 0))
        
        # Enhanced buttons with larger size
        ttk.Button(iv_btn_frame, text="Generate", command=self.generate_iv,
                  width=14).pack(pady=4)  # Increased width and padding
        ttk.Button(iv_btn_frame, text="Load from File", command=self.load_iv_file,
                  width=14).pack(pady=4)
        ttk.Button(iv_btn_frame, text="Save to File", command=self.save_iv_file,
                  width=14).pack(pady=4)
        
        # Status
        self.status_label = ttk.Label(parent, text="Status: Key and IV not loaded", 
                                     foreground="red", font=('TkDefaultFont', 11, 'bold'))  # Enhanced font
        self.status_label.pack(pady=12)
    
    def on_key_change(self, event=None):
        """Auto-load key when text changes"""
        # Use after_idle to ensure the text change is processed first
        self.root.after_idle(self.auto_load_key)
    
    def on_key_paste(self, event=None):
        """Handle paste event for key"""
        # Use after to allow paste to complete first
        self.root.after(10, self.auto_load_key)
    
    def on_iv_change(self, event=None):
        """Auto-load IV when text changes"""
        # Use after_idle to ensure the text change is processed first
        self.root.after_idle(self.auto_load_iv)
    
    def on_iv_paste(self, event=None):
        """Handle paste event for IV"""
        # Use after to allow paste to complete first
        self.root.after(10, self.auto_load_iv)
    
    def auto_load_key(self):
        """Automatically load key from text entry"""
        try:
            key_text = self.key_entry.get(1.0, tk.END).strip()
            # Remove 0x prefix if present (case insensitive)
            if key_text.lower().startswith('0x'):
                key_text = key_text[2:]
            # Filter to only hex characters
            key_text = ''.join(c for c in key_text if c.isdigit() or c.lower() in 'abcdef')
            
            if len(key_text) == 32:  # Valid key length
                self.key_bits = hex_string_to_bits(key_text, 128)
                self.key_loaded = True
                self.update_status()
            elif len(key_text) == 0:  # Empty field
                self.key_loaded = False
                self.update_status()
            # For invalid lengths, we don't show error messages to avoid spam
            # but we also don't load the key
            elif self.key_loaded and len(key_text) != 32:
                self.key_loaded = False
                self.update_status()
        except Exception:
            # Silently handle errors during auto-loading
            if self.key_loaded:
                self.key_loaded = False
                self.update_status()
    
    def auto_load_iv(self):
        """Automatically load IV from text entry"""
        try:
            iv_text = self.iv_entry.get(1.0, tk.END).strip()
            # Remove 0x prefix if present (case insensitive)
            if iv_text.lower().startswith('0x'):
                iv_text = iv_text[2:]
            # Filter to only hex characters
            iv_text = ''.join(c for c in iv_text if c.isdigit() or c.lower() in 'abcdef')
            
            if len(iv_text) == 24:  # Valid IV length
                self.iv_bits = hex_string_to_bits(iv_text, 96)
                self.iv_loaded = True
                self.update_status()
            elif len(iv_text) == 0:  # Empty field
                self.iv_loaded = False
                self.update_status()
            # For invalid lengths, we don't show error messages to avoid spam
            # but we also don't load the IV
            elif self.iv_loaded and len(iv_text) != 24:
                self.iv_loaded = False
                self.update_status()
        except Exception:
            # Silently handle errors during auto-loading
            if self.iv_loaded:
                self.iv_loaded = False
                self.update_status()
    
    def create_encrypt_tab(self, parent):
        # Plaintext Section
        plain_frame = ttk.LabelFrame(parent, text="Plaintext", padding=12)  # Increased padding
        plain_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        
        self.plaintext_entry = tk.Text(plain_frame, height=10, font=('Consolas', 10))  # Added font
        self.plaintext_entry.pack(fill=tk.BOTH, expand=True)
        
        plain_btn_frame = ttk.Frame(plain_frame)
        plain_btn_frame.pack(fill=tk.X, pady=(12, 0))
        
        ttk.Button(plain_btn_frame, text="Load from File", command=self.load_plaintext_file,
                  width=15).pack(side=tk.LEFT)  # Increased width
        ttk.Button(plain_btn_frame, text="Encrypt and Save", command=self.encrypt_text,
                  width=15).pack(side=tk.RIGHT)  # Increased width
        
        # Ciphertext Display Section
        cipher_display_frame = ttk.LabelFrame(parent, text="Ciphertext (hex form)", padding=12)
        cipher_display_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        
        self.ciphertext_display = tk.Text(cipher_display_frame, height=8, font=('Consolas', 10), 
                                         state=tk.DISABLED, wrap=tk.WORD)
        self.ciphertext_display.pack(fill=tk.BOTH, expand=True)

        # Encrypt Key Section
        key_encrypt_frame = ttk.LabelFrame(parent, text="Encrypt Key", padding=12)  # Increased padding
        key_encrypt_frame.pack(fill=tk.X, padx=12, pady=8)
        
        ttk.Label(key_encrypt_frame, text="Filename:", font=('TkDefaultFont', 10)).grid(
            row=0, column=0, sticky=tk.W, padx=(0, 8))  # Enhanced font and padding
        self.encrypt_key_filename = ttk.Entry(key_encrypt_frame, width=35, font=('TkDefaultFont', 10))  # Increased width and font
        self.encrypt_key_filename.grid(row=0, column=1, padx=(0, 12))
        
        ttk.Label(key_encrypt_frame, text="Password:", font=('TkDefaultFont', 10)).grid(
            row=1, column=0, sticky=tk.W, padx=(0, 8), pady=(8, 0))
        self.encrypt_key_password = ttk.Entry(key_encrypt_frame, show="*", width=35, font=('TkDefaultFont', 10))  # Increased width and font
        self.encrypt_key_password.grid(row=1, column=1, padx=(0, 12), pady=(8, 0))
        
        ttk.Button(key_encrypt_frame, text="Encrypt Key", command=self.encrypt_key,
                  width=12).grid(row=0, column=2, rowspan=2, padx=(8, 0))  # Increased width
    
    def create_decrypt_tab(self, parent):
        # Decrypt Key Section
        key_decrypt_frame = ttk.LabelFrame(parent, text="Decrypt Key", padding=12)  # Increased padding
        key_decrypt_frame.pack(fill=tk.X, padx=12, pady=8)
        
        ttk.Label(key_decrypt_frame, text="Filename:", font=('TkDefaultFont', 10)).grid(
            row=0, column=0, sticky=tk.W, padx=(0, 8))  # Enhanced font and padding
        self.decrypt_key_filename = ttk.Entry(key_decrypt_frame, width=30, font=('TkDefaultFont', 10))  # Increased width and font
        self.decrypt_key_filename.grid(row=0, column=1, padx=(0, 12))
        ttk.Button(key_decrypt_frame, text="Browse", command=self.browse_decrypt_key,
                  width=10).grid(row=0, column=2)  # Increased width
        
        ttk.Label(key_decrypt_frame, text="Password:", font=('TkDefaultFont', 10)).grid(
            row=1, column=0, sticky=tk.W, padx=(0, 8), pady=(8, 0))
        self.decrypt_key_password = ttk.Entry(key_decrypt_frame, show="*", width=30, font=('TkDefaultFont', 10))  # Increased width and font
        self.decrypt_key_password.grid(row=1, column=1, padx=(0, 12), pady=(8, 0))
        ttk.Button(key_decrypt_frame, text="Decrypt Key", command=self.decrypt_key,
                  width=12).grid(row=1, column=2, padx=(8, 0), pady=(8, 0))  # Increased width
        
        # Ciphertext Section
        cipher_frame = ttk.LabelFrame(parent, text="Ciphertext (hex form)", padding=12)  # Increased padding
        cipher_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        
        cipher_input_frame = ttk.Frame(cipher_frame)
        cipher_input_frame.pack(fill=tk.X, pady=(0, 12))
        
        ttk.Label(cipher_input_frame, text="Ciphertext File:", font=('TkDefaultFont', 10)).pack(side=tk.LEFT)  # Enhanced font
        self.cipher_filename = ttk.Entry(cipher_input_frame, width=45, font=('TkDefaultFont', 10))  # Increased width and font
        self.cipher_filename.pack(side=tk.LEFT, padx=(8, 8), fill=tk.X, expand=True)
        ttk.Button(cipher_input_frame, text="Browse", command=self.browse_cipher_file,
                  width=10).pack(side=tk.RIGHT)  # Increased width
        
        ttk.Button(cipher_frame, text="Decrypt", command=self.decrypt_text,
                  width=15).pack(pady=8)  # Increased width and padding
        
        # Results
        self.result_text = tk.Text(cipher_frame, height=8, font=('Consolas', 10))  # Added font
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=(12, 0))
    
    def generate_key(self):
        try:
            hex_len = 128 // 4
            random_hex = ''.join(f"{random.randint(0, 15):X}" for _ in range(hex_len))
            self.key_entry.delete(1.0, tk.END)
            self.key_entry.insert(1.0, random_hex)
            # Auto-loading will handle the rest
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {str(e)}")
    
    def generate_iv(self):
        try:
            hex_len = 96 // 4
            random_hex = ''.join(f"{random.randint(0, 15):X}" for _ in range(hex_len))
            self.iv_entry.delete(1.0, tk.END)
            self.iv_entry.insert(1.0, random_hex)
            # Auto-loading will handle the rest
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate IV: {str(e)}")
    
    def load_key_from_text(self):
        try:
            key_text = self.key_entry.get(1.0, tk.END).strip()
            # Remove 0x prefix if present (case insensitive)
            if key_text.lower().startswith('0x'):
                key_text = key_text[2:]
            # Filter to only hex characters
            key_text = ''.join(c for c in key_text if c.isdigit() or c.lower() in 'abcdef')
            
            if len(key_text) != 32:
                raise ValueError("Key must be exactly 32 hex characters (128 bits)")
            
            self.key_bits = hex_string_to_bits(key_text, 128)
            self.key_loaded = True
            self.update_status()
        except Exception as e:
            messagebox.showerror("Error", f"Invalid key: {str(e)}")
    
    def load_iv_from_text(self):
        try:
            iv_text = self.iv_entry.get(1.0, tk.END).strip()
            # Remove 0x prefix if present (case insensitive)
            if iv_text.lower().startswith('0x'):
                iv_text = iv_text[2:]
            # Filter to only hex characters
            iv_text = ''.join(c for c in iv_text if c.isdigit() or c.lower() in 'abcdef')
            
            if len(iv_text) != 24:
                raise ValueError("IV must be exactly 24 hex characters (96 bits)")
            
            self.iv_bits = hex_string_to_bits(iv_text, 96)
            self.iv_loaded = True
            self.update_status()
        except Exception as e:
            messagebox.showerror("Error", f"Invalid IV: {str(e)}")
    
    def load_key_file(self):
        try:
            filename = filedialog.askopenfilename(title="Select Key File")
            if filename:
                self.key_bits = load_hex_bits_from_file(filename, 128)
                # Display in text box using correct bit ordering
                hex_str = bits_to_hex_string(self.key_bits)
                self.key_entry.delete(1.0, tk.END)
                self.key_entry.insert(1.0, hex_str)
                # Auto-loading will handle setting key_loaded and updating status
                messagebox.showinfo("Success", "Key loaded from file successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load key: {str(e)}")
    
    def load_iv_file(self):
        try:
            filename = filedialog.askopenfilename(title="Select IV File")
            if filename:
                self.iv_bits = load_hex_bits_from_file(filename, 96)
                # Display in text box using correct bit ordering
                hex_str = bits_to_hex_string(self.iv_bits)
                self.iv_entry.delete(1.0, tk.END)
                self.iv_entry.insert(1.0, hex_str)
                # Auto-loading will handle setting iv_loaded and updating status
                messagebox.showinfo("Success", "IV loaded from file successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load IV: {str(e)}")
    
    def save_key_file(self):
        try:
            if not self.key_loaded:
                messagebox.showerror("Error", "No valid key to save!")
                return
                
            filename = filedialog.asksaveasfilename(title="Save Key File", defaultextension=".txt")
            if filename:
                # Convert bits to hex using the same format as the original file I/O
                hex_bytes = []
                for i in range(0, len(self.key_bits), 8):
                    byte = 0
                    for j in range(8):
                        if i + j < len(self.key_bits):
                           byte |= (self.key_bits[i + j] << (7 - j))
                    hex_bytes.append(f"{byte:02X}")
                
                hex_str = ''.join(hex_bytes)
                with open(filename, 'w') as f:
                    f.write(hex_str)
                messagebox.showinfo("Success", "Key saved to file successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save key: {str(e)}")
    
    def save_iv_file(self):
        try:
            if not self.iv_loaded:
                messagebox.showerror("Error", "No valid IV to save!")
                return
                
            filename = filedialog.asksaveasfilename(title="Save IV File", defaultextension=".txt")
            if filename:
                # Convert bits to hex using the same format as the original file I/O
                hex_bytes = []
                for i in range(0, len(self.iv_bits), 8):
                    byte = 0
                    for j in range(8):
                        if i + j < len(self.iv_bits):
                            byte |= (self.iv_bits[i + j] << (7 - j))
                    hex_bytes.append(f"{byte:02X}")
                
                hex_str = ''.join(hex_bytes)
                with open(filename, 'w') as f:
                    f.write(hex_str)
                messagebox.showinfo("Success", "IV saved to file successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save IV: {str(e)}")
    
    def update_status(self):
         if self.key_loaded and self.iv_loaded:
            self.status_label.config(text="Status: Key and IV loaded successfully", foreground="green")
            self.go_encrypt.pack(pady=8)  # Increased padding
            self.go_decrypt.pack(pady=8)  # Increased padding
         elif self.key_loaded:
            self.status_label.config(text="Status: Key loaded, IV needed", foreground="orange")
            self.go_encrypt.pack_forget()
            self.go_decrypt.pack_forget()
         elif self.iv_loaded:
            self.status_label.config(text="Status: IV loaded, Key needed", foreground="orange")
            self.go_encrypt.pack_forget()
            self.go_decrypt.pack_forget()
         else:
            self.status_label.config(text="Status: Key and IV not loaded", foreground="red")
            self.go_encrypt.pack_forget()
            self.go_decrypt.pack_forget()

    def load_plaintext_file(self):
        try:
            filename = filedialog.askopenfilename(title="Select Plaintext File")
            if filename:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.plaintext_entry.delete(1.0, tk.END)
                self.plaintext_entry.insert(1.0, content)
                messagebox.showinfo("Success", "Plaintext loaded from file successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load plaintext: {str(e)}")
    
    def encrypt_text(self):
        try:
            if not self.key_loaded or not self.iv_loaded:
                messagebox.showerror("Error", "Please load key and IV first!")
                return
            
            # Get plaintext and convert to bits
            plaintext = self.plaintext_entry.get(1.0, tk.END).rstrip('\n')
            if not plaintext:
                messagebox.showerror("Error", "Please enter plaintext to encrypt!")
                return
            
            plaintext_bits = text_to_bits(plaintext)
            
            # Initialize cipher and encrypt
            self.cipher.initialize(self.key_bits, self.iv_bits)
            
            # Ask for output filename
            output_file = filedialog.asksaveasfilename(
                title="Save Encrypted File As",
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            
            if output_file:
                cipher_bits = self.cipher.encrypt(plaintext_bits, output_file)
                messagebox.showinfo("Success", f"Text encrypted and saved to {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def encrypt_text(self):
        try:
            if not self.key_loaded or not self.iv_loaded:
                messagebox.showerror("Error", "Please load key and IV first!")
                return
            
            # Get plaintext and convert to bits
            plaintext = self.plaintext_entry.get(1.0, tk.END).rstrip('\n')
            if not plaintext:
                messagebox.showerror("Error", "Please enter plaintext to encrypt!")
                return
            
            plaintext_bits = text_to_bits(plaintext)
            
            # Initialize cipher and encrypt
            self.cipher.initialize(self.key_bits, self.iv_bits)
            
            # Ask for output filename
            output_file = filedialog.asksaveasfilename(
                title="Save Encrypted File As",
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            
            if output_file:
                cipher_bits = self.cipher.encrypt(plaintext_bits, output_file)
                
                # Convert ciphertext bits to hex string for display
                cipher_hex = bits_to_hex_string(cipher_bits)
                
                # Determine if we should display the ciphertext in the text box
                # Use a reasonable threshold - if hex string is longer than what fits comfortably
                # in the text box (roughly 2000 characters), don't display it
                max_display_length = 2000
                
                # Clear the ciphertext display first
                self.ciphertext_display.config(state=tk.NORMAL)
                self.ciphertext_display.delete(1.0, tk.END)
                
                if len(cipher_hex) <= max_display_length:
                    # Display the ciphertext in the text box
                    self.ciphertext_display.insert(1.0, cipher_hex)
                    self.ciphertext_display.config(state=tk.DISABLED)
                    messagebox.showinfo("Success", f"Text encrypted and saved to {output_file}\nCiphertext displayed below.")
                else:
                    # Too long to display, just show a message
                    self.ciphertext_display.insert(1.0, f"Ciphertext too long to display ({len(cipher_hex)} characters)\nSaved to file: {output_file}")
                    self.ciphertext_display.config(state=tk.DISABLED)
                    messagebox.showinfo("Success", f"Text encrypted and saved to {output_file}\n(Ciphertext too long to display)")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def encrypt_key(self):
        try:
            if not self.key_loaded:
                messagebox.showerror("Error", "Please load key first!")
                return
            
            filename = self.encrypt_key_filename.get().strip()
            password = self.encrypt_key_password.get().strip()
            
            if not filename or not password:
                messagebox.showerror("Error", "Please enter filename and password!")
                return
            
            encrypt_key_with_password(self.key_bits, password, filename)
            messagebox.showinfo("Success", f"Key encrypted and saved to {filename}")
            
            # Clear password field
            self.encrypt_key_password.delete(0, tk.END)
        
        except Exception as e:
            messagebox.showerror("Error", f"Key encryption failed: {str(e)}")
    
    def browse_decrypt_key(self):
        filename = filedialog.askopenfilename(title="Select Encrypted Key File")
        if filename:
            self.decrypt_key_filename.delete(0, tk.END)
            self.decrypt_key_filename.insert(0, filename)
    
    def decrypt_key(self):
        try:
            filename = self.decrypt_key_filename.get().strip()
            password = self.decrypt_key_password.get().strip()
            
            if not filename or not password:
                messagebox.showerror("Error", "Please enter filename and password!")
                return
            
            self.key_bits = decrypt_key_with_password(filename, password)
            self.key_loaded = True
            
            # Display decrypted key in setup tab
            hex_str = ''.join(f"{byte:02X}" for byte in bits_to_bytes(self.key_bits))
            self.key_entry.delete(1.0, tk.END)
            self.key_entry.insert(1.0, hex_str)
            
            self.update_status()
            messagebox.showinfo("Success", "Key decrypted successfully!")
            
            # Clear password field
            self.decrypt_key_password.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Key decryption failed: {str(e)}")
    
    def browse_cipher_file(self):
        filename = filedialog.askopenfilename(
            title="Select Ciphertext File",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if filename:
            self.cipher_filename.delete(0, tk.END)
            self.cipher_filename.insert(0, filename)
    
    def decrypt_text(self):
        try:
            if not self.key_loaded or not self.iv_loaded:
                messagebox.showerror("Error", "Please load key and IV first!")
                return
            
            cipher_file = self.cipher_filename.get().strip()
            if not cipher_file:
                messagebox.showerror("Error", "Please select a ciphertext file!")
                return
            
            # Read ciphertext
            ciphertext_bits = read_ciphertext(cipher_file)
            if not ciphertext_bits:
                messagebox.showerror("Error", "Failed to read ciphertext file!")
                return
            
            # Ask for output filename
            if cipher_file.endswith('.enc'):
                default_output = cipher_file[:-4] + '.dec'
            else:
                default_output = cipher_file + '.dec'
            
            output_file = filedialog.asksaveasfilename(
                title="Save Decrypted File As",
                initialfile=default_output,
                defaultextension=".dec",
                filetypes=[("Text files", "*.dec"), ("All files", "*.*")]
            )
            
            if output_file:
                # Initialize cipher and decrypt
                self.cipher.initialize(self.key_bits, self.iv_bits)
                plaintext_bits = self.cipher.decrypt(ciphertext_bits, output_file)
                
                # Display result in text area
                try:
                    with open(output_file, 'r', encoding='utf-8') as f:
                        decrypted_text = f.read()
                    
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(1.0, decrypted_text)
                    
                    messagebox.showinfo("Success", f"Text decrypted and saved to {output_file}")
                except Exception as e:
                    messagebox.showinfo("Success", f"Text decrypted and saved to {output_file}\n(Preview not available: {str(e)})")
        
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def main():
    root = tk.Tk()
    app = GrainGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()