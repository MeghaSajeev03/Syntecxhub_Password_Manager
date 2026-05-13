import os
import sys
import json
import base64
import hashlib
import getpass
import secrets
import string
import threading
import time

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("Missing cryptography module. Please install it using: pip install cryptography")
    sys.exit(1)

try:
    import pyperclip
except ImportError:
    print("Missing pyperclip module. Clipboard functionalities will be disabled.")
    pyperclip = None

try:
    import requests
except ImportError:
    print("Missing requests module. Breach checking functionalities will be disabled.")
    requests = None

DB_FILE = 'passwords.vault'

# --- Cryptography Core ---

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a strong encryption key from the master password (PBKDF2HMAC with 600,000 iterations)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- Database Operations ---

def init_db(master_password: str):
    """Initializes a new, empty encrypted database."""
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    
    empty_data = json.dumps([]).encode()
    encrypted_data = fernet.encrypt(empty_data)
    
    with open(DB_FILE, 'w') as f:
        json.dump({
            'salt': base64.b64encode(salt).decode('utf-8'),
            'data': encrypted_data.decode('utf-8')
        }, f)
    print("[*] Created new secure vault.")

def load_db(master_password: str):
    """Loads and decrypts the database."""
    if not os.path.exists(DB_FILE):
        return None
        
    with open(DB_FILE, 'r') as f:
        try:
            vault = json.load(f)
            salt = base64.b64decode(vault['salt'])
            encrypted_data = vault['data'].encode('utf-8')
        except Exception:
            print("[-] Vault file is corrupted.")
            return None
            
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))
    except InvalidToken:
        return False # False indicates wrong password

def save_db(master_password: str, data: list):
    """Encrypts and syncs the data back to the disk."""
    with open(DB_FILE, 'r') as f:
        vault = json.load(f)
        salt = base64.b64decode(vault['salt'])
        
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    
    encrypted_data = fernet.encrypt(json.dumps(data).encode('utf-8'))
    
    with open(DB_FILE, 'w') as f:
        json.dump({
            'salt': base64.b64encode(salt).decode('utf-8'),
            'data': encrypted_data.decode('utf-8')
        }, f)

# --- Unique Features ---

def check_pwned(password: str):
    """Checks if the password has been exposed in data breaches via HaveIBeenPwned API (k-anonymity)."""
    if not requests:
        return "Unknown (requests mod missing)"
    
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    
    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            hashes_found = (line.split(':') for line in res.text.splitlines())
            for h, count in hashes_found:
                if h == suffix:
                    return f"Compromised ({count} times)"
            return "Clean (0 occurrences)"
        return "Check Failed (API Error)"
    except Exception:
        return "Network Error"

def assess_strength(password: str):
    """Evaluates password strength based on entropy, length, and character sets."""
    score = 0
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if len(password) >= 16: score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in string.punctuation for c in password): score += 2

    if score < 3: return "Weak"
    elif score < 6: return "Moderate"
    elif score >= 6: return "Strong"
    return "Weak"

def generate_password(length=16):
    """Generates a cryptographically strong random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in string.punctuation for c in password)):
            return password

def wait_and_clear_clipboard(original_text, delay=15):
    """Waits for an amount of time and clears the clipboard if unchanged."""
    time.sleep(delay)
    if pyperclip.paste() == original_text:
        pyperclip.copy("")
        print("\n[*] Clipboard auto-cleared for security. Press Enter to continue...")

def copy_to_clipboard(text, message="Data"):
    if pyperclip:
        pyperclip.copy(text)
        print(f"[*] {message} copied to clipboard! It will be cleared in 15 seconds.")
        # Start a background thread to clear the clipboard securely
        threading.Thread(target=wait_and_clear_clipboard, args=(text, 15), daemon=True).start()
    else:
        print(f"[*] {message}: {text} \n(Install pyperclip to enable auto-copy)")

# --- CLI Interface ---

def main():
    print("==============================================")
    print("      Secure Python DB Password Manager       ")
    print("==============================================")
    
    if not os.path.exists(DB_FILE):
        print(">> No initialized vault found.")
        while True:
            mp = getpass.getpass("Create a Master Password: ")
            mp2 = getpass.getpass("Confirm Master Password: ")
            if mp == mp2:
                if len(mp) < 8:
                    print("Master password should be at least 8 characters long.")
                    continue
                init_db(mp)
                master_password = mp
                break
            else:
                print("Passwords do not match. Try again.")
    else:
        attempts = 3
        while attempts > 0:
            mp = getpass.getpass("Enter your Master Password: ")
            data = load_db(mp)
            if data is False:
                print(f"[-] Incorrect Master Password. {attempts-1} attempts left.")
                attempts -= 1
            elif data is None:
                print("[-] Could not read the vault. The file might be corrupted.")
                return
            else:
                master_password = mp
                print("[*] Vault unlocked successfully.")
                break
        else:
            print("[CRITICAL] Too many failed unlock attempts. Locking down.")
            return

    entries = load_db(master_password)
    
    while True:
        try:
            print("\n----- Menu -----")
            print("[1] Add New Credential")
            print("[2] Retrieve Credential")
            print("[3] Search / List All")
            print("[4] Delete Credential")
            print("[5] Analyze Vault Security")
            print("[6] Exit & Lock Vault")
            cmd = input("Choice: ").strip()
            
            if cmd == '1':
                site = input("Site / App Name: ").strip()
                username = input("Username / Email: ").strip()
                gen_pass = input("Auto-generate a strong password? (y/N): ").strip().lower()
                
                if gen_pass == 'y':
                    try:
                        length_input = input("Length (default 16): ").strip()
                        length = int(length_input) if length_input else 16
                    except ValueError:
                        length = 16
                    pwd = generate_password(length)
                    print(f"[*] Selected Auto-Generated Password: {pwd}")
                else:
                    pwd = getpass.getpass("Enter Password: ")
                    
                strength = assess_strength(pwd)
                print(f"[*] Password Strength assessment: {strength}")
                
                print("[*] Checking HaveIBeenPwned API for data breaches...")
                pwn_status = check_pwned(pwd)
                print(f"[-] Data Breach Status: {pwn_status}")
                
                if "Compromised" in pwn_status:
                    if input("[!] WARNING: This password was found in a breach. Still proceed? (y/N): ").strip().lower() != 'y':
                        print(">> Operation aborted.")
                        continue
                
                notes = input("Extra Notes (optional): ").strip()
                
                next_id = max((e.get('id', 0) for e in entries), default=0) + 1
                entries.append({
                    'id': next_id,
                    'site': site,
                    'username': username,
                    'password': pwd,
                    'notes': notes
                })
                
                save_db(master_password, entries)
                print("[*] Secure entry successfully saved and encrypted.")
                
            elif cmd == '2':
                q = input("Enter Site or Username exactly to fetch (case-insensitive): ").strip().lower()
                matches = [e for e in entries if q == e['site'].lower() or q == e['username'].lower()]
                
                if not matches:
                    print("[-] No exact matching entry found.")
                else:
                    for i, match in enumerate(matches):
                        print(f"  [{i+1}] Site: {match['site']} | User: {match['username']}")
                    
                    idx = 0
                    if len(matches) > 1:
                        try:
                            idx = int(input("Multiple matches found. Select entry ID number: ").strip()) - 1
                        except ValueError:
                            print("[-] Invalid input.")
                            continue
                        
                    if 0 <= idx < len(matches):
                        selected = matches[idx]
                        copy_to_clipboard(selected['password'], "Password")
                        print(f"    (Associated Username: {selected['username']})")
                    else:
                        print("[-] Invalid selection index.")
                        
            elif cmd == '3':
                q = input("Search query (leave blank to list all): ").strip().lower()
                matches = [e for e in entries if q in e['site'].lower() or q in e['username'].lower()]
                
                if not matches:
                    print("[-] No entries found matching the query.")
                else:
                    print("\n--- Encrypted Vault Entries ---")
                    for e in matches:
                        print(f"ID: {e.get('id', '?')} | Site: {e['site']} | Username: {e['username']} | Notes: {e['notes']}")
                    print("-------------------------------")
                    
            elif cmd == '4':
                site_to_del = input("Enter Site name exactly to delete its entry: ").strip().lower()
                
                initial_len = len(entries)
                entries = [e for e in entries if e['site'].lower() != site_to_del]
                
                if len(entries) < initial_len:
                    save_db(master_password, entries)
                    print(f"[*] Operation complete. Removed {initial_len - len(entries)} entry/entries.")
                else:
                    print("[-] No matching entry found with that Site name.")
                    
            elif cmd == '5':
                print("\n--- Vault Security Diagnostic ---")
                weak_count = 0
                compromised_count = 0
                
                print(f"Analyzing {len(entries)} credentials...")
                for e in entries:
                    strength = assess_strength(e['password'])
                    if strength != "Strong":
                        print(f"  [!] Weak/Medium Password -> Site: '{e['site']}' ({strength})")
                        weak_count += 1
                        
                    pwn_status = check_pwned(e['password'])
                    if "Compromised" in pwn_status:
                        print(f"  [CRITICAL] Compromised in Breach -> Site: '{e['site']}' ({pwn_status})")
                        compromised_count += 1
                
                if weak_count == 0 and compromised_count == 0 and len(entries) > 0:
                    print("[*] All stored passwords are secure and haven't been breached!")
                print("---------------------------------")
                
            elif cmd == '6':
                print("[*] Locking database strictly and clearing memory...")
                # Best-effort to wipe variables
                master_password = "WIPED_" * 10 
                entries = []
                print("[*] Exiting. Goodbye!")
                break
            else:
                print("[-] Unrecognized selection.")
        except KeyboardInterrupt:
            print("\n[!] Emergency lock and exit. Goodbye!")
            break
        except Exception as e:
            print(f"[-] An error occurred during runtime: {str(e)}")

if __name__ == "__main__":
    main()
