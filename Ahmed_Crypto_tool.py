#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import base64
from tkinter import filedialog, messagebox
import tkinter as tk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import ARC4
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

class CryptoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Yourname_Crypto Tool")
        self.root.geometry("600x500")

        self.text_field = tk.Text(self.root, height=10, width=50)
        self.text_field.pack(pady=10)

        self.upload_btn = tk.Button(self.root, text="Upload File", command=self.upload_file)
        self.upload_btn.pack(pady=10)

        self.encrypt_btn = tk.Button(self.root, text="Encrypt", command=self.encrypt_text)
        self.encrypt_btn.pack(pady=5)

        self.decrypt_btn = tk.Button(self.root, text="Decrypt", command=self.decrypt_text)
        self.decrypt_btn.pack(pady=5)

        # Hash algorithm selection dropdown
        self.algorithm_var = tk.StringVar(value="SHA-256")  # Default to SHA-256
        self.algorithm_menu = tk.OptionMenu(self.root, self.algorithm_var, "MD5", "SHA-1", "SHA-256")
        self.algorithm_menu.pack(pady=5)

        self.hash_btn = tk.Button(self.root, text="Generate Hash", command=self.hash_text)
        self.hash_btn.pack(pady=5)

        self.rsa_encrypt_btn = tk.Button(self.root, text="RSA Encrypt", command=self.rsa_encrypt)
        self.rsa_encrypt_btn.pack(pady=5)

        self.rc4_encrypt_btn = tk.Button(self.root, text="RC4 Encrypt", command=self.rc4_encrypt)
        self.rc4_encrypt_btn.pack(pady=5)

        self.digital_sign_btn = tk.Button(self.root, text="Generate Digital Signature", command=self.generate_digital_signature)
        self.digital_sign_btn.pack(pady=5)

        self.blind_sign_btn = tk.Button(self.root, text="Generate Blind Signature", command=self.generate_blind_signature)
        self.blind_sign_btn.pack(pady=5)

        self.verify_sign_btn = tk.Button(self.root, text="Verify Signature", command=self.verify_signature)
        self.verify_sign_btn.pack(pady=5)

        self.output_text = tk.Text(self.root, height=10, width=50)
        self.output_text.pack(pady=10)

        self.save_btn = tk.Button(self.root, text="Save Output", command=self.save_output)
        self.save_btn.pack(pady=5)

        # Generate RSA keys on initialization (for signing)
        self.private_key, self.public_key = self.generate_rsa_keys()

    def generate_rsa_keys(self):
        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Generate the public key from the private key
        public_key = private_key.public_key()

        return private_key, public_key

    def upload_file(self):
        file_path = filedialog.askopenfilename(title="Select a File", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
        
        if file_path:  # If a file is selected
            with open(file_path, 'r') as file:
                # Clear the text field and insert the file contents
                self.text_field.delete(1.0, tk.END)
                self.text_field.insert(tk.END, file.read())

    def encrypt_text(self):
        text = self.text_field.get(1.0, tk.END).strip()
        key = b'Sixteen byte key'
        iv = b'16 byte iv123456'  # Initialization Vector (IV)
        
        # Apply padding to the plaintext
        padder = PKCS7(128).padder()
        padded_data = padder.update(text.encode()) + padder.finalize()
        
        # Create the AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
        
        # Display encrypted text in hexadecimal format
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, encrypted_text.hex())

    def decrypt_text(self):
        text = self.text_field.get(1.0, tk.END).strip()
        key = b'Sixteen byte key'
        iv = b'16 byte iv123456'  # Initialization Vector (IV)
        
        # Convert hex-encoded encrypted text back to bytes
        encrypted_data = bytes.fromhex(text)
        
        # Create the AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_text = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        unpadder = PKCS7(128).unpadder()
        decrypted_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()
        
        # Display decrypted text
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, decrypted_text.decode())

    def hash_text(self):
        text = self.text_field.get(1.0, tk.END).strip()

        # Get the selected hashing algorithm from the dropdown
        selected_algorithm = self.algorithm_var.get()

        if selected_algorithm == "MD5":
            hashed_text = hashlib.md5(text.encode()).hexdigest()
        elif selected_algorithm == "SHA-1":
            hashed_text = hashlib.sha1(text.encode()).hexdigest()
        elif selected_algorithm == "SHA-256":
            hashed_text = hashlib.sha256(text.encode()).hexdigest()

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, hashed_text)

    def rsa_encrypt(self):
        text = self.text_field.get(1.0, tk.END).strip()
        key = RSA.generate(2048)
        public_key = key.publickey()
        encryptor = PKCS1_OAEP.new(public_key)
        encrypted_text = encryptor.encrypt(text.encode())
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, encrypted_text.hex())

    def rc4_encrypt(self):
        key = b'YourSecretKey'
        text = self.text_field.get(1.0, tk.END).strip()
        cipher = ARC4.new(key)
        encrypted_text = cipher.encrypt(text.encode())
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, encrypted_text.hex())

    def generate_digital_signature(self):
        text = self.text_field.get(1.0, tk.END).strip()

        # Hash the message first (SHA-256 by default)
        message_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        message_hash.update(text.encode())
        digest = message_hash.finalize()

        # Sign the hash of the message with the private key
        signature = self.private_key.sign(
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Output the Base64-encoded signature
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, base64.b64encode(signature).decode())

    def generate_blind_signature(self):
        text = self.text_field.get(1.0, tk.END).strip()

        # Generate a random "blinding" factor
        blind_factor = get_random_bytes(32)

        # Hash the message first (SHA-256 by default)
        message_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        message_hash.update(text.encode())
        digest = message_hash.finalize()

        # Blind the message hash by multiplying it with the blind factor (mod the RSA key modulus)
        blinded_digest = (int.from_bytes(digest, 'big') * int.from_bytes(blind_factor, 'big')) % self.private_key.public_key().public_numbers().n

        # Sign the blinded digest with the private key
        signature = self.private_key.sign(
            blinded_digest.to_bytes((blinded_digest.bit_length() + 7) // 8, 'big'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Unblind the signature by multiplying with the inverse of the blinding factor
        unblinded_signature = int.from_bytes(signature, 'big') * pow(int.from_bytes(blind_factor, 'big'), -1, self.private_key.public_key().public_numbers().n)

        # Output the Base64-encoded unblinded signature
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, base64.b64encode(unblinded_signature.to_bytes((unblinded_signature.bit_length() + 7) // 8, 'big')).decode())

    def verify_signature(self):
        text = self.text_field.get(1.0, tk.END).strip()

        # Get the signature from the user input (Base64-encoded)
        signature_b64 = self.output_text.get(1.0, tk.END).strip()

        try:
            # Decode the Base64 signature
            signature = base64.b64decode(signature_b64)

            # Hash the message first (SHA-256 by default)
            message_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            message_hash.update(text.encode())
            digest = message_hash.finalize()

            # Verify the signature using the public key
            self.public_key.verify(
                signature,
                digest,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            messagebox.showinfo("Verification", "Signature is valid!")
        except Exception as e:
            messagebox.showerror("Verification", f"Signature verification failed: {str(e)}")

    def save_output(self):
        output = self.output_text.get(1.0, tk.END).strip()
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        with open(file_path, 'w') as file:
            file.write(output)
        messagebox.showinfo("Saved", "Output saved successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoTool(root)
    root.mainloop()


# In[ ]:




