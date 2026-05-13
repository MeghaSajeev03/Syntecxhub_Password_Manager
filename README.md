# Secure Python Password Manager

A locally stored, heavily encrypted custom password manager that operates entirely via CLI. It ensures your credentials are safely protected on-disk using strong symmetric encryption (AES-128 via Fernet) and state-of-the-art key derivation (PBKDF2HMAC).

## Unique Features Implementation

1. **Strong On-Disk Encryption:** Uses `cryptography.fernet` which wraps AES-128 in CBC mode with a PKCS7 padding and an HMAC authentication tag. The key is securely derived via PBKDF2HMAC with 600,000 iterations and a unique salt.
2. **K-Anonymity Breach Checking:** Seamlessly integrates with the "Have I Been Pwned" database. It hashes your passwords using SHA-1, taking only the first 5 characters of the hash to query the database, preserving complete privacy while alerting you to compromised credentials.
3. **Smart Password Strength Diagnostics:** A custom built-in engine natively evaluates the entropy of typed passwords or generated passwords, alerting you to weak/moderate selections.
4. **Auto-Clearing Clipboard Memory:** When you retrieve a password, it safely copies the password to your system's clipboard and automatically clears it precisely after 15 seconds via a background thread, preventing sensitive data from accidentally being pasted elsewhere later.
5. **Secure Cryptographic Generator:** Forget your own passwords. Built-in `secrets`-based generator that enforces complex password rules automatically.

## Requirements

Ensure you have Python 3 installed. Install the requirements via:

```sh
pip install -r requirements.txt
```

### Dependencies:
* `cryptography`: Handles key-derivation and AES operations.
* `pyperclip`: Allows secure copying to and auto-clearing from the clipboard.
* `requests`: Queries the k-anonymity API securely.

## Usage

Simply run the tool:

```sh
python password_manager.py
```

### First Launch
1. Upon running the script, since no `passwords.vault` is found, you will be prompted to create a **Master Password**.
2. **IMPORTANT**: Do not forget this master password. If lost, the encrypted data cannot be recovered.

### Available Commands
Once unlocked:
1. **[1] Add New Credential**: Enter site, username, and password. You can automatically generate a strong password and check if your manual password has ever been exposed in data breaches.
2. **[2] Retrieve Credential**: Search by site/username and have the password instantly copied to your clipboard (which auto-clears after 15 seconds).
3. **[3] Search / List All**: Display the metadata of all secured accounts without displaying their passwords out in the open terminal.
4. **[4] Delete Credential**: Permanently remove a record from the vault.
5. **[5] Analyze Vault Security**: Check all stored passwords against the "Have I Been Pwned" database and the internal strength engine to identify weak links in your vault!
6. **[6] Exit & Lock Vault**: Attempt to clear memory traces and gracefully lock down the vault file on-disk.

## Security Mechanics

- **Storage Structure**: Encrypted JSON containing a randomly generated salt.
- **Master Check**: When launching, the tool derives the key using your input master password and the database's salt. If it fails to decrypt the initial JSON structure, it detects a false password. After 3 attempts, it strictly locks down.
