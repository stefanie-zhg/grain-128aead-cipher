import hashlib # for SHA256
import random #for key and iv random generation
import os

#---------------------------------------------------
# KEY ENCRYPTION AND DECRYPTION UTILITY FUNCTIONS
#---------------------------------------------------

# SHA256 Utils
def sha256_hash(data):
    """SHA256 hash function"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()

def hash_password_to_key(password):
    """Hash password using SHA256"""
    return sha256_hash(password)

def xor_encrypt_key(key_bits, hash_bytes):
    """XOR encrypt key with hash (first 16 bytes)"""
    key_bytes = bits_to_bytes(key_bits[:128])
    encrypted = bytearray()
    for i in range(16):
        encrypted.append(key_bytes[i] ^ hash_bytes[i])
    return bytes(encrypted)

def save_encrypted_key(filename, enc_key):
    """Save encrypted key to file"""
    with open(filename, 'w') as f:
        for byte in enc_key:
            f.write(f"{byte:02X} ")

def load_encrypted_key(filename):
    """Load encrypted key from file"""
    with open(filename, 'r') as f:
        hex_bytes = f.read().strip().split()
        return bytes(int(hex_byte, 16) for hex_byte in hex_bytes)

def encrypt_key_with_password(original_key_bits, password, output_file):
    """Encrypt key with password and save to file"""
    hash_bytes = hash_password_to_key(password)
    enc_key = xor_encrypt_key(original_key_bits, hash_bytes)
    save_encrypted_key(output_file, enc_key)

def decrypt_key_with_password(input_file, password):
    """Decrypt key with password from file"""
    hash_bytes = hash_password_to_key(password)
    enc_key = load_encrypted_key(input_file)
    
    decrypted_bytes = bytearray()
    for i in range(16):
        decrypted_bytes.append(enc_key[i] ^ hash_bytes[i])
    
    return bytes_to_bits(bytes(decrypted_bytes))

def hex_string_to_bits(hex_string, bit_length):
    """Convert MSB-first hex string to LSB-first bits (for internal use)"""
    hex_string = hex_string.lower().strip()
    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]

    # Keep only hex characters
    hex_string = ''.join(c for c in hex_string if c in '0123456789abcdef')
    expected_hex_len = (bit_length + 3) // 4
    if len(hex_string) < expected_hex_len:
        raise ValueError(f"Hex string too short. Expected at least {expected_hex_len} hex characters.")

    bits = []
    for i in range(0, len(hex_string), 2):  # Process each byte (2 hex chars)
        if i + 1 >= len(hex_string): break
        byte_val = int(hex_string[i:i+2], 16)
        # Convert MSB-first byte to LSB-first bits
        for j in range(8):
            bits.append((byte_val >> j) & 1)
    return bits[:bit_length]

def bits_to_bytes(bits):
    """Convert bits array to bytes (LSB-first per byte)"""
    bytes_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i + j] << j)
        bytes_array.append(byte)
    return bytes(bytes_array)

def bytes_to_bits(byte_data):
    """Convert bytes to bits array (LSB-first per byte)"""
    bits = []
    for byte in byte_data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_hex_string(bits):
    """Convert LSB-first bits to MSB-first hex string for display"""
    hex_chars = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i + j] << j)
        hex_chars.append(f"{byte:02X}")
    return ''.join(hex_chars)


def load_hex_bits_from_file(filename, expected_bits):
    """Load hex string from file and convert to bits"""
    try:
        with open(filename, 'r') as f:
            hex_str = f.read().strip()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None
    except Exception as e:
        print(f"Error reading file: {e}")
        return None
    
    if hex_str.lower().startswith("0x"):
        hex_str = hex_str[2:]

    # Filter valid hex characters
    hex_str = ''.join(c for c in hex_str if c.isdigit() or c.lower() in 'abcdef')

    if len(hex_str) % 2 != 0:
        hex_str = hex_str[:-1]
    
    if not hex_str:
        print("Error: Empty file.")
        return None
    
    bits = []
    bit_index = 0
    for i in range(0, len(hex_str), 2):
        if bit_index >= expected_bits:
            break
        byte_val = int(hex_str[i:i+2], 16)
        for b in range(8):
            if bit_index < expected_bits:
                bits.append((byte_val >> b) & 1)
                bit_index += 1
    
    if len(bits) < expected_bits:
        raise ValueError(f"Not enough bits in hex input ({len(bits)} < {expected_bits} expected)")
    
    return bits[:expected_bits]

def read_plaintext(filename):
    """Read plaintext from file and convert to bits (LSB-first)"""
    with open(filename, 'r', encoding='utf-8') as f:
        text = f.read()
    
    bits = []
    for char in text:
        char_code = ord(char)
        # FIXED: Use LSB-first bit ordering
        for i in range(8):
            bits.append((char_code >> i) & 1)
    
    return bits

def read_ciphertext(filename):
    """Read ciphertext from hex file and convert to bits (LSB-first)"""
    with open(filename, 'r') as f:
        hex_content = f.read().replace(' ', '').replace('\n', '')
    
    bits = []
    for i in range(0, len(hex_content), 2):
        if i + 1 < len(hex_content):
            byte_val = int(hex_content[i:i+2], 16)
            # FIXED: Use LSB-first bit ordering
            for j in range(8):
                bits.append((byte_val >> j) & 1)
    
    return bits

def generate_random_bits_to_file(filename, bit_len):
    """Generate random hex bits and save to file, for command line user interface"""
    hex_len = bit_len // 4
    random_hex = ''.join(f"{random.randint(0, 15):X}" for _ in range(hex_len))
    
    with open(filename, 'w') as f:
        f.write(random_hex)

def text_to_bits(text):
    """Convert text string to bits (LSB-first)"""
    bits = []
    for char in text:
        char_code = ord(char)
        # FIXED: Use LSB-first bit ordering
        for i in range(8):
            bits.append((char_code >> i) & 1)
    return bits

#----------------------------------------------
# Grain-128 AEAD Implementation
#----------------------------------------------
STATE_SIZE = 128

class Grain128AEAD:
    def __init__(self):
        self.LFSR = [0] * STATE_SIZE #128 bit LSFR
        self.NFSR = [0] * STATE_SIZE #128 bit NSFR

        #storage for key and IV
        self.key = [0] * 128 
        self.iv = [0] * 128
        
    def L(self, S):
        """LFSR update function"""
        return S[0] ^ S[7] ^ S[38] ^ S[70] ^ S[81] ^ S[96]
    
    def F(self, B):
        """NFSR update function"""
        # update function = s[127] = s[0] + s[7] + s[38] + s[70] + s[81] + s[96]
        return (B[0] ^ B[26] ^ B[56] ^ B[91] ^ B[96] ^
                (B[3] & B[67]) ^ (B[11] & B[13]) ^
                (B[17] & B[18]) ^ (B[27] & B[59]) ^
                (B[40] & B[48]) ^ (B[61] & B[65]) ^ (B[68] & B[84]) ^
                (B[22] & B[24] & B[25]) ^ (B[70] & B[78] & B[82]) ^
                (B[88] & B[92] & B[93] & B[95])) # returns new bit for position 127
    
    def h(self, S, B):
        """Nonlinear Boolean function h(x)"""
        # S (list): LFSR state, B (list): NFSR state 
        # 2 from NSFR, 7 from LSFR
        x0, x1, x2, x3, x4, x5, x6, x7, x8 = B[12], S[8], S[13], S[20], B[95], S[42], S[60], S[79], S[94]
        return (x0 & x1) ^ (x2 & x3) ^ (x4 & x5) ^ (x6 & x7) ^ (x0 & x4 & x8)
    
    def y_t(self, S, B):
        """Pre-output function -> generates the output bit"""
        #  y_t = h(S,B) + S[93] + sum(B[j] for j in A)
        # where A = {2, 15, 36, 45, 64, 73, 89}
        return (self.h(S, B) ^ S[93] ^ 
                B[2] ^ B[15] ^ B[36] ^ B[45] ^ B[64] ^ B[73] ^ B[89])
    
    def shift_left(self, reg):
        """Shift register left"""
        for i in range(STATE_SIZE - 1):
            reg[i] = reg[i + 1]
        reg[STATE_SIZE - 1] = 0   # Position 127 receives a new bit.
    
    def initialize(self, key_bits, iv_bits):
        """Initialize the cipher with key and IV

        Initialize the cipher with key and IV following the 3-phase process.
        
        The initialization process has three phases:
        1. Phase 1 (t=0-319): Clock with pre-output feedback to both registers
        2. Phase 2 (t=320-383): Clock with key feedback and pre-output feedback  
        3. Phase 3 (t=384-511): Clock without any feedback (keystream generation setup)
        
        Args:
            key_bits (list): 128-bit key as bit array
            iv_bits (list): 96-bit IV as bit array
        """
        
        self.key = key_bits[:128] # store key and IIV
        self.NFSR = key_bits[:128].copy() # load NSFR with key bits
        
        self.iv = iv_bits[:96] + [0] * 32 # load IV bits, with 0 extended
        self.LFSR = iv_bits[:96].copy()
        
        self.LFSR.extend([1] * 31 + [0]) # last 32 bits = 31 ones and 1 zero 

        # Print after loading (USE FOR TESTING/ DATA VALIDATION)
        print("\n[After Loading]")
        print("NFSR:", bits_to_hex_string(self.NFSR))
        print("LFSR:", bits_to_hex_string(self.LFSR))
        
        # Phase 1: 0-319
        # both received pre-output feedback
        for t in range(320):
            y = self.y_t(self.LFSR, self.NFSR)

            # LFSR update: s[127] = L(S) + y_t
            new_L = self.L(self.LFSR) ^ y

            # NFSR update: b[127] = s[0] + F(B) + y_t
            new_N = self.LFSR[0] ^ self.F(self.NFSR) ^ y
            
            # update both registers
            self.shift_left(self.LFSR)
            self.shift_left(self.NFSR)

            #insert new bits
            self.LFSR[127] = new_L
            self.NFSR[127] = new_N
        
        # Phase 2: 320-383
        # key bits with pre-output is fed into register
        for t in range(320, 384):
            y = self.y_t(self.LFSR, self.NFSR)

            # LFSR = s[127] = L(S) + y_t + k[t-256]
            new_L = self.L(self.LFSR) ^ y ^ self.key[t - 256]

            # NFSR gets different key bit and pre-output:
            # b[127] = s[0] + F(B) + y_t + k[t-320]
            new_N = self.LFSR[0] ^ self.F(self.NFSR) ^ y ^ self.key[t - 320]
            
            # update both registers
            self.shift_left(self.LFSR)
            self.shift_left(self.NFSR)

            # insert new bits
            self.LFSR[127] = new_L
            self.NFSR[127] = new_N
        
        # Phase 3: 384-511 (no feedback)
        for t in range(384, 512):
            # register update with no feedback
            new_L = self.L(self.LFSR)
            new_N = self.LFSR[0] ^ self.F(self.NFSR)
            
            # update both register
            self.shift_left(self.LFSR)
            self.shift_left(self.NFSR)

            # insert new bits
            self.LFSR[127] = new_L
            self.NFSR[127] = new_N
        
        # Print after initialization (USE FOR TESTING/ DATA VALIDATION)
        print("\n[After Initialization]")
        print("NFSR:", bits_to_hex_string(self.NFSR))
        print("LFSR:", bits_to_hex_string(self.LFSR))

    def update_registers(self):
        """Update the LFSR and NFSR registers by shifting and inserting new values."""
        new_L = self.L(self.LFSR)
        new_N = self.LFSR[0] ^ self.F(self.NFSR)  # S[0] ⊕ F(NFSR)

        self.shift_left(self.LFSR)
        self.shift_left(self.NFSR)
        self.LFSR[127] = new_L
        self.NFSR[127] = new_N
        
    def generate_keystream_bit(self):
        """Generate one keystream bit, takes even bit only"""
        # Generate keystream bit (even bit y512+2i)
        keystream_bit = self.y_t(self.LFSR, self.NFSR)
        
        # Update registers
        self.update_registers()

        # Generate and discard the authentication bit (odd bit y512+2i+1)
        auth_bit = self.y_t(self.LFSR, self.NFSR)  # Generate but don't use
        
        # Update registers again
        self.update_registers()
        
        return keystream_bit
      
    def encrypt(self, plaintext_bits, output_file="cipher.enc"):
        """Encrypt plaintext bits (c_i = m_i ⊕ z_i)
        
         plaintext_bits (list): Plaintext as bit array
         output_file (str): Output filename for ciphertext"""
        # encrypt bit by bit
        cipher_bits = []
        for i in range(len(plaintext_bits)): 
            keystream_bit = self.generate_keystream_bit()
            cipher_bits.append(plaintext_bits[i] ^ keystream_bit)
        
        # Convert LSB-first bits to hex output/file
        with open(output_file, "w") as f:
            for i in range(0, len(cipher_bits), 8):
                byte = 0
                # reconstruct byte from LSB-first bits
                for j in range(8):
                    if i + j < len(cipher_bits):
                        byte |= (cipher_bits[i + j] << j)  # LSB-first
                f.write(f"{byte:02X}")
        
        return cipher_bits # returns encrypted bits 
    
    def decrypt(self, ciphertext_bits, output_file):
        """Decrypt ciphertext bits (  m_i = c_i ⊕ z_i )

         ciphertext_bits (list): Ciphertext as bit array  
         output_file (str): Output filename for plaintext"""
        # Decrypt bit by bit
        plaintext_bits = []
        for i in range(len(ciphertext_bits)):
            keystream_bit = self.generate_keystream_bit()
            plaintext_bits.append(ciphertext_bits[i] ^ keystream_bit)
        
        # Convert LSB-first bits to proper characters reconstruction
        with open(output_file, "w", encoding='utf-8') as f:
            for i in range(0, len(plaintext_bits), 8):
                byte = 0
                for j in range(8):
                    if i + j < len(plaintext_bits):
                        byte |= (plaintext_bits[i + j] << j)  # LSB-first
                if byte > 0: #only write printable character
                    f.write(chr(byte))
        
        return plaintext_bits

#----------------------------------------------
# MAIN PROGRAM AND COMMAND LINE USER INTERFACE
#----------------------------------------------

# display main menu options
def menu():
    print("\n==== Grain-128AEADv2 Encryption Menu ====")
    print("1. Setup key and IV")
    print("2. Encryption")
    print("3. Decryption")
    print("0. Exit")
    choice = input("Select an option: ")
    return choice

def main():
    """Main program loop providing user interface for the Grain-128AEAD cipher.
    
    This function provides a menu-driven interface allowing users to:
    1. Set up 128-bit keys and 96-bit IVs (manually, from file, or randomly)
    2. Encrypt plaintext (manual input or from file) additionally encrypt key
    3. Decrypt ciphertext with password-protected keys"""
    cipher = Grain128AEAD()
    key_loaded = False
    iv_loaded = False
    key_bits = []
    iv_bits = []
    
    while True:
        choice = menu()
        
        if choice == '1':
            print("\nKey and IV Setup Menu:")
            print("1. Enter manually")
            print("2. Load from file")
            print("3. Generate randomly")
            sub_choice = input("Select an option: ")
            
            if sub_choice == '1':
                key_input = input("Enter 128-bit hex key (32 hex chars): ").strip().lower()
                iv_input = input("Enter 96-bit hex IV (24 hex chars): ").strip().lower()

                 # Strip 0x prefix if present
                if key_input.lower().startswith("0x"):
                    key_input = key_input[2:]
                if iv_input.lower().startswith("0x"):
                    iv_input = iv_input[2:]
                
                 # Remove whitespace and ensure only hex chars remain
                key_input = ''.join(c for c in key_input if c in '0123456789abcdef')
                iv_input = ''.join(c for c in iv_input if c in '0123456789abcdef')

                if len(key_input) != 32 or len(iv_input) != 24:
                    print("Invalid input length.")
                    continue
                
                try:
                    key_bits = hex_string_to_bits(key_input, 128)
                    iv_bits = hex_string_to_bits(iv_input, 96)
                    key_loaded = True
                    iv_loaded = True
                    print("Manual key and IV retrieved successfully.")
                except ValueError as e:
                    print(f"Error: {e}")
            
            elif sub_choice == '2':
                key_file = input("Enter filename for 128-bit key: ")
                iv_file = input("Enter filename for 96-bit IV: ")
                
                key_bits = load_hex_bits_from_file(key_file, 128)
                iv_bits = load_hex_bits_from_file(iv_file, 96)
                
                if key_bits is None or iv_bits is None:
                    print("Error loading key or IV from file.")
                    key_loaded = False
                    iv_loaded = False
                else:
                    key_loaded = True
                    iv_loaded = True
                    print("Key and IV retrieved from file successfully.")
            
            elif sub_choice == '3':
                print("Generating random 128-bit key and 96-bit IV...")
                generate_random_bits_to_file("key.txt", 128)
                generate_random_bits_to_file("iv.txt", 96)
                
                key_bits = load_hex_bits_from_file("key.txt", 128)
                iv_bits = load_hex_bits_from_file("iv.txt", 96)
                
                if key_bits is None or iv_bits is None:
                    print("Failed to load generated key/IV.")
                    key_loaded = False
                    iv_loaded = False
                else:
                    key_loaded = True
                    iv_loaded = True
                    print("Random key and IV generated and loaded successfully.")
                    print("Key saved to key.txt")
                    print("IV saved to iv.txt")

        
        elif choice == '2':
            if not key_loaded or not iv_loaded:
                print("Error: Key and IV not loaded. Please load them first.")
                continue
            
            cipher.initialize(key_bits, iv_bits)
            
            print("\nSelect plaintext input method:")
            print("1. Input manually")
            print("2. Load from file")
            method = input("Select an option: ")
            
            if method == '1':
                input_text = input("Enter plaintext: ")
                plaintext_bits = text_to_bits(input_text)
                print(f"Manual plaintext input loaded: {len(plaintext_bits)} bits")
            
            elif method == '2':
                filename = input("Enter filename (e.g., plaintext.txt): ")
                plaintext_bits = read_plaintext(filename)
                if not plaintext_bits:
                    continue
            
            else:
                print("Invalid selection.")
                continue
            
            cipher.encrypt(plaintext_bits)
            print("Plaintext encrypted using Grain-128AEADv2.")
            print("Ciphertext saved to cipher.enc (hex format).")
            
            # Encrypt key with password
            output_file = input("Enter filename to save encrypted key (e.g., encrypted.key): ")
            password = input("Enter password to encrypt the key: ")
            
            encrypt_key_with_password(key_bits, password, output_file)
            print("Key encrypted and saved successfully.")
        
        elif choice == '3':
            if not iv_loaded:
                print("Error: Please load the IV first.")
                continue
            
            # Decrypt key with password
            key_file = input("Enter filename to load encrypted key from (e.g., encrypted.key): ")
            password = input("Enter password to decrypt the key: ")
            
            try:
                key_bits = decrypt_key_with_password(key_file, password)
                key_loaded = True
            except Exception as e:
                print(f"Error decrypting key: {e}")
                continue
            
            cipher_file = input("Enter ciphertext file name (with .enc extension): ")
            ciphertext_bits = read_ciphertext(cipher_file)
            
            if not ciphertext_bits:
                continue
            
            # Create output filename
            if cipher_file.endswith('.enc'):
                output_file = cipher_file[:-4] + '.dec'
            else:
                output_file = cipher_file + '.dec'
            
            cipher.initialize(key_bits, iv_bits)
            cipher.decrypt(ciphertext_bits, output_file)
            
            print("Ciphertext decrypted successfully.")
            print(f"Decrypted text saved to {output_file}")
        
        elif choice == '0':
            print("Exiting.")
            break
        
        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    main()

