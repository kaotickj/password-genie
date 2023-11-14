import tkinter as tk
from tkinter import messagebox
import secrets
import string
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# Key derivation function setup
def derive_key(master_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(master_key.encode())
    return key

# GUI Setup
app = tk.Tk()
app.title("Password Genie")  # Keep the application name as "Password Genie"

# Set the size of the main window
app.geometry("300x400")

# Set the system icon
app.iconbitmap("icon.ico")

# Entry for the user's master pass-key
label_master_key = tk.Label(app, text="Master Pass-Key:")
entry_master_key = tk.Entry(app, show="*")  # Use show="*" to hide the entered characters

# Entry for the password (for hashing and verification)
label_password = tk.Label(app, text="Password:")
entry_password = tk.Entry(app, show="*")

# Entry for the password length (for generating passwords)
label_length = tk.Label(app, text="Password Length:")
entry_length = tk.Entry(app)
entry_length.insert(0, "12")  # Default value

# Entry for character requirements (for generating passwords)
label_requirements = tk.Label(app, text="Character Requirements:")
entry_requirements = tk.Entry(app)
entry_requirements.insert(0, "letters,digits,punctuation")  # Default value

# Entry for the platform (for saving and retrieving passwords)
label_platform = tk.Label(app, text="Platform:")
entry_platform = tk.Entry(app)

# Label for displaying the generated password
label_password_text = tk.Label(app, text="Generated Password:")

# Textbox to display the generated password
password_text = tk.Entry(app, state='readonly', width=20)

# Button to copy the generated password to the clipboard
def copy_to_clipboard():
    app.clipboard_clear()
    app.clipboard_append(password_text.get())
    app.update()

# Flag to check if the master password is set
master_password_set = None  # Initialize as None

# Function to verify the master password
def verify_master_password():
    global master_password_set

    try:
        with open('master_key.txt', 'r') as file:
            line = file.readline()
            if line:
                parts = line.split(':')
                salt_hex = parts[0].strip()
                hashed_master_key_stored = parts[1].strip()

                # Check if the master password file is found and has data
                if salt_hex and hashed_master_key_stored:
                    master_password_set = True
                else:
                    master_password_set = False
                    messagebox.showinfo("Master Password Not Set", "The master password is not set. Please set the initial master password.")
                    return
            else:
                master_password_set = False
                messagebox.showinfo("Master Password Not Set", "The master password is not set. Please set the initial master password.")
                return
    except Exception as e:
        master_password_set = False
        messagebox.showerror("Error", f"An error occurred while verifying the master password: {str(e)}")

    master_key = entry_master_key.get()

    if not master_password_set:
        # If not set, prompt the user to set it
        messagebox.showinfo("Master Password Not Set", "The master password is not set. Please set the initial master password.")
        return

    # Continue with the existing verification logic
    try:
        with open('master_key.txt', 'r') as file:
            line = file.readline()
            if line:
                parts = line.split(':')
                salt_hex = parts[0].strip()
                hashed_master_key_stored = parts[1].strip()

                salt = bytes.fromhex(salt_hex)
                hashed_master_key_entered = derive_key(master_key, salt).hex()

                if hashed_master_key_stored == hashed_master_key_entered:
                    messagebox.showinfo("Master Password Verified", "Master password verified successfully.")
                else:
                    messagebox.showerror("Error", "Incorrect master password.")
                    master_password_set = False  # Set to False if verification fails
            else:
                messagebox.showerror("Error", "Master password not set. Please set the initial master password.")
                master_password_set = False  # Set to False if file is empty
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while verifying the master password: {str(e)}")
        master_password_set = False  # Set to False if an error occurs

# Function to handle password generation
def generate_password():
    global master_password_set

    if not master_password_set:
        messagebox.showerror("Error", "Please set the initial master password first.")
        return

    length_str = entry_length.get()
    requirements = entry_requirements.get()

    try:
        length = int(length_str)
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid numeric value for password length.")
        return

    if length <= 0:
        messagebox.showerror("Error", "Password length must be greater than 0.")
        return

    try:
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(length))
        password_text.config(state='normal')  # Enable editing
        password_text.delete(0, tk.END)  # Clear previous content
        password_text.insert(tk.END, password)
        password_text.config(state='readonly')  # Disable editing
        messagebox.showinfo("Generated Password", f"Your password is: {password}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while generating the password: {str(e)}")

# Function to handle password hashing
def hash_password():
    global master_password_set

    if not master_password_set:
        messagebox.showerror("Error", "Please set the initial master password first.")
        return

    password = entry_password.get()

    if not password:
        messagebox.showerror("Error", "Please enter a password to hash.")
        return

    # Hash the password using SHA-256
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password.encode())
    hashed_password = digest.finalize()

    messagebox.showinfo("Hashed Password", f"The hashed password is: {hashed_password.hex()}")

# Function to handle saving the password
def save_password():
    global master_password_set

    if not master_password_set:
        messagebox.showerror("Error", "Please set the initial master password first.")
        return

    master_key = entry_master_key.get()
    password = entry_password.get()
    platform = entry_platform.get()

    if not master_key or not password or not platform:
        messagebox.showerror("Error", "Please fill in all fields.")
        return

    salt = secrets.token_bytes(16)  # Generate a random salt
    key = derive_key(master_key, salt)

    # Ensure key is 32 bytes and base64-encoded
    key = base64.urlsafe_b64encode(key)
    key = key.ljust(32, b'=')

    # Encrypt and save the password
    try:
        cipher_suite = Fernet(key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        with open('passwords.txt', 'a') as file:
            file.write(f"{platform}: {salt.hex()}:{encrypted_password.decode()}\n")
        messagebox.showinfo("Password Saved", "Password saved successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while saving the password: {str(e)}")

# Function to handle retrieving and decrypting the password
def retrieve_password():
    global master_password_set

    if not master_password_set:
        messagebox.showerror("Error", "Please set the initial master password first.")
        return

    master_key = entry_master_key.get()
    platform = entry_platform.get()

    if not master_key or not platform:
        messagebox.showerror("Error", "Please enter a master pass-key and platform.")
        return

    try:
        with open('passwords.txt', 'r') as file:
            for line in file:
                if platform in line:
                    parts = line.split(':')
                    salt_hex = parts[1].strip()
                    encrypted_password = parts[2].strip()

                    salt = bytes.fromhex(salt_hex)
                    key = derive_key(master_key, salt)

                    # Ensure key is 32 bytes
                    key = key[:32]

                    cipher_suite = Fernet(base64.urlsafe_b64encode(key))
                    decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()

                    messagebox.showinfo("Decrypted Password", f"Your password for {platform} is: {decrypted_password}")
                    return

            messagebox.showerror("Error", f"No password found for the platform: {platform}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while retrieving the password: {str(e)}")

# Function to set the initial master password
def set_master_password():
    global master_password_set

    # Check if the master password is already set
    if master_password_set:
        messagebox.showinfo("Master Password Set", "Master password is already set.")
        return

    master_key = entry_master_key.get()

    if not master_key:
        messagebox.showerror("Error", "Please enter a master pass-key.")
        return

    salt = secrets.token_bytes(16)  # Generate a random salt
    hashed_master_key = derive_key(master_key, salt)

    # Save the hashed master key for later verification
    with open('master_key.txt', 'w') as file:
        file.write(f"{salt.hex()}:{hashed_master_key.hex()}")

    master_password_set = True
    messagebox.showinfo("Master Password Set", "Initial master password set successfully.")

    # Disable the "Set Master Password" button once the master password is set
    button_set_master_password['state'] = 'disabled'

# ToolTip class for adding tooltips to widgets
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)

    def enter(self, event):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")

        label = tk.Label(self.tooltip, text=self.text, background="#ffffe0", relief="solid", borderwidth=1)
        label.pack(ipadx=1)

    def leave(self, event):
        if self.tooltip:
            self.tooltip.destroy()

# Function to display the About dialog
def show_about_dialog():
    about_text = (
        "Password Genie\n"
        "Version 1.0.12\n"
        "Created by Kaotick Jay\n"
        "License: GNU/GPL3\n"
        "Copyright (c) 2023 by Kaotick Jay\n"
        "GitHub: https://github.com/kaotickj"
    )
    messagebox.showinfo("About", about_text)

# Menu bar
menu_bar = tk.Menu(app)
app.config(menu=menu_bar)

# About menu
about_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="About", menu=about_menu)
about_menu.add_command(label="About Password Genie", command=show_about_dialog)

# Place widgets using the place method
label_master_key.place(x=10, y=10)
entry_master_key.place(x=150, y=10)
ToolTip(entry_master_key, "Enter your master pass-key")

label_password.place(x=10, y=40)
entry_password.place(x=150, y=40)
ToolTip(entry_password, "Enter a password for hashing or leave it blank")

label_length.place(x=10, y=70)
entry_length.place(x=150, y=70)
ToolTip(entry_length, "Enter the desired password length (default is 12)")

label_requirements.place(x=10, y=100)
entry_requirements.place(x=150, y=100)
ToolTip(entry_requirements, "Enter character requirements (default is letters, digits, punctuation)")

label_platform.place(x=10, y=130)
entry_platform.place(x=150, y=130)
ToolTip(entry_platform, "Enter the platform for saving or retrieving the password")

button_generate = tk.Button(app, text="Generate Password", command=generate_password)
ToolTip(button_generate, "Generate a random password")
button_generate.place(x=10, y=160)

button_hash = tk.Button(app, text="Hash Password", command=hash_password)
ToolTip(button_hash, "Hash the entered password")
button_hash.place(x=150, y=160)

button_save = tk.Button(app, text="Save Password", command=save_password)
ToolTip(button_save, "Save the password for the specified platform")
button_save.place(x=10, y=190)

button_retrieve = tk.Button(app, text="Retrieve Password", command=retrieve_password)
ToolTip(button_retrieve, "Retrieve and decrypt the password for the specified platform")
button_retrieve.place(x=150, y=190)

#button_set_master_password = tk.Button(app, text="Set Master Password", command=set_master_password)
#ToolTip(button_set_master_password, "Set the initial master password")
#button_set_master_password.place(x=10, y=220)

button_verify_master_password = tk.Button(app, text="Verify Master Password", command=verify_master_password)
ToolTip(button_verify_master_password, "Verify the entered master password")
#button_verify_master_password.place(x=150, y=220)
button_verify_master_password.place(x=10, y=220)

# Textbox to display the generated password
label_password_text.place(x=10, y=260)
password_text.place(x=150, y=260)

# Button to copy generated password to clipboard
copy_button = tk.Button(app, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.place(x=10, y=290)

# Main Event Loop
app.mainloop()
