import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import requests
import hmac
import hashlib
import json

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Demo")
        self.root.geometry("1000x700")  # Set initial window size, larger width and height

        # Algorithm selection dropdown for symmetric algorithms
        self.symmetric_label = ttk.Label(root, text="Select Symmetric Encryption Algorithm:")
        self.symmetric_label.grid(row=0, column=0, padx=10, pady=5)
        self.symmetric_var = tk.StringVar()
        self.symmetric_combobox = ttk.Combobox(root, textvariable=self.symmetric_var, values=["AES", "DES", "3DES", "None"])
        self.symmetric_combobox.grid(row=0, column=1, padx=10, pady=5)
        self.symmetric_combobox.current(0)
        self.symmetric_combobox.bind("<<ComboboxSelected>>", self.symmetric_selected)

        # Algorithm selection dropdown for asymmetric algorithms
        self.asymmetric_label = ttk.Label(root, text="Select Asymmetric Encryption Algorithm:")
        self.asymmetric_label.grid(row=1, column=0, padx=10, pady=5)
        self.asymmetric_var = tk.StringVar()
        self.asymmetric_combobox = ttk.Combobox(root, textvariable=self.asymmetric_var, values=["RSA", "ECC", "None"])
        self.asymmetric_combobox.grid(row=1, column=1, padx=10, pady=5)
        self.asymmetric_combobox.current(0)
        self.asymmetric_combobox.bind("<<ComboboxSelected>>", self.asymmetric_selected)

        # Hashing algorithm selection dropdown
        self.hash_algorithm_label = ttk.Label(root, text="Select Hashing Algorithm:")
        self.hash_algorithm_label.grid(row=2, column=0, padx=10, pady=5)
        self.hash_algorithm_var = tk.StringVar()
        self.hash_algorithm_combobox = ttk.Combobox(root, textvariable=self.hash_algorithm_var, values=["SHA1", "SHA256", "MD5"])
        self.hash_algorithm_combobox.grid(row=2, column=1, padx=10, pady=5)
        self.hash_algorithm_combobox.current(0)

        # Authentication method selection dropdown
        self.auth_method_label = ttk.Label(root, text="Select Authentication Method:")
        self.auth_method_label.grid(row=3, column=0, padx=10, pady=5)
        self.auth_method_var = tk.StringVar()
        self.auth_method_combobox = ttk.Combobox(root, textvariable=self.auth_method_var, values=["HMAC"])
        self.auth_method_combobox.grid(row=3, column=1, padx=10, pady=5)
        self.auth_method_combobox.current(0)

        # Plaintext entry
        self.plaintext_label = ttk.Label(root, text="Enter Plaintext:")
        self.plaintext_label.grid(row=4, column=0, padx=10, pady=5)
        self.plaintext_entry = ttk.Entry(root, width=50)  # Increased width of the entry
        self.plaintext_entry.grid(row=4, column=1, padx=10, pady=5)

        # Button to trigger encryption and hashing
        self.encrypt_button = ttk.Button(root, text="Encrypt & Hash", command=self.encrypt_and_hash)
        self.encrypt_button.grid(row=5, column=0, columnspan=2, padx=10, pady=5)

        # Result display
        self.result_label = ttk.Label(root, text="Result:")
        self.result_label.grid(row=6, column=0, padx=10, pady=5)
        self.result_text = tk.Text(root, width=80, height=30)  # Adjusted width and height of the text box
        self.result_text.grid(row=6, column=1, padx=10, pady=5)

        # Add horizontal scrollbar to result text box
        self.result_scrollbar = ttk.Scrollbar(root, orient="horizontal", command=self.result_text.xview)
        self.result_scrollbar.grid(row=7, column=1, sticky="ew")
        self.result_text.config(xscrollcommand=self.result_scrollbar.set)

        # Secret key for HMAC
        self.secret_key = b'12345'  # Replace with your secret key

    def symmetric_selected(self, event):
        if self.symmetric_var.get() != "None":
            self.asymmetric_combobox.config(state="disabled")
            self.auth_method_combobox.config(values=["HMAC"], state="readonly")
        else:
            self.asymmetric_combobox.config(state="readonly")
            self.update_auth_method_values()

    def asymmetric_selected(self, event):
        if self.asymmetric_var.get() != "None":
            self.symmetric_combobox.config(state="disabled")
            self.auth_method_combobox.config(values=["DSA"], state="readonly")
        else:
            self.symmetric_combobox.config(state="readonly")
            self.update_auth_method_values()

    def update_auth_method_values(self):
        self.auth_method_combobox.config(values=["HMAC", "DSA"])

    def generate_hmac(self, data):
        return hmac.new(self.secret_key, data.encode(), hashlib.sha256).hexdigest()

    def encrypt_and_hash(self):
        auth_method = self.auth_method_var.get()
        symmetric_algorithm = self.symmetric_var.get()
        asymmetric_algorithm = self.asymmetric_var.get()
        hash_algorithm = self.hash_algorithm_var.get()
        plaintext = self.plaintext_entry.get()

        print('authmethod is ', auth_method)

        data = {
            'algorithm': symmetric_algorithm if symmetric_algorithm != "None" else asymmetric_algorithm,
            'hash_algorithm': hash_algorithm,
            'plaintext': plaintext
        }

        if symmetric_algorithm != "None":
            algorithm = symmetric_algorithm
        elif asymmetric_algorithm != "None":
            algorithm = asymmetric_algorithm
        else:
            messagebox.showwarning("No Algorithm Selected", "Please select at least one encryption algorithm.")
            return

        if algorithm not in ["AES", "DES", "3DES", "RSA", "ECC"]:
            messagebox.showwarning("Invalid Algorithm", "Please select a valid encryption algorithm.")
            return

        if auth_method in ["HMAC","DSA"] or auth_method == "DSA":
            hmac_signature = self.generate_hmac(json.dumps(data))
            headers = {'Authentication-Method': auth_method, 'HMAC': hmac_signature}
        else:
            messagebox.showwarning("Invalid Authentication Method", "Please select a valid authentication method.")
            return

        # Send request to the server
        url = 'http://localhost:5000/encrypt_and_hash'
        try:
            response = requests.post(url, json=data, headers=headers)
            response_data = response.json()

            # Display the result on the frontend
            self.result_text.delete(1.0, tk.END)

            if 'error' in response_data:
                self.result_text.insert(tk.END, f"Error: {response_data['error']}\n")
            else:
                if 'encrypted_text' in response_data:
                    self.result_text.insert(tk.END, f"Encrypted Text: {response_data['encrypted_text']}\n")
                if 'hashed_text' in response_data:
                    self.result_text.insert(tk.END, f"Hashed Text: {response_data['hashed_text']}\n")
                if 'key' in response_data and 'iv' in response_data:
                    self.result_text.insert(tk.END, f"Key: {response_data['key']}\n")
                if 'private_key' in response_data:
                    if response_data['private_key'] is None:
                        self.result_text.insert(tk.END, f"{auth_method} verification: Successful\n")
                    else:
                        self.result_text.insert(tk.END, f"Private Key: {response_data['private_key']}\n")
                        self.result_text.insert(tk.END, "DSA verification: Successful\n")
                if 'decrypted_text' in response_data:
                    self.result_text.insert(tk.END, f"Decrypted Text: {response_data['decrypted_text']}\n")


        except requests.RequestException as e:
            messagebox.showerror("Error", f"Failed to communicate with server: {e}")



if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
