import tkinter as tk
from tkinter import messagebox
import secrets
import string
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import webbrowser
import sys
import os

# Key derivation
def derive_key(master_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    return kdf.derive(master_key.encode())

# GUI setup
app = tk.Tk()
app.title("Password Genie")
app.geometry("300x400")
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

app.iconbitmap(resource_path("icon.ico"))
label_master_key = tk.Label(app, text="Master Pass-Key:")
entry_master_key = tk.Entry(app, show="*")

label_password = tk.Label(app, text="Password:")
entry_password = tk.Entry(app, show="*")

label_length = tk.Label(app, text="Password Length:")
entry_length = tk.Entry(app)
entry_length.insert(0, "12")

label_requirements = tk.Label(app, text="Character Requirements:")
entry_requirements = tk.Entry(app)
entry_requirements.insert(0, "letters,digits,punctuation")

label_platform = tk.Label(app, text="Platform:")
entry_platform = tk.Entry(app)

label_password_text = tk.Label(app, text="Generated Password:")
password_text = tk.Entry(app, state='readonly', width=20)

master_password_set = None

def set_master_password():
    global master_password_set
    master_key = entry_master_key.get()
    if not master_key:
        messagebox.showerror("Error", "Please enter a master pass-key.")
        return
    if not messagebox.askyesno("Set Master Password", "This will set the initial master password. Proceed?"):
        return
    salt = secrets.token_bytes(16)
    hashed_master_key = derive_key(master_key, salt)
    try:
        with open('master_key.txt', 'w') as file:
            file.write(f"{salt.hex()}:{hashed_master_key.hex()}")
        master_password_set = True
        button_set_master_password.place_forget()
        messagebox.showinfo("Success", "Initial master password set successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to set master password: {str(e)}")

def verify_master_password():
    global master_password_set
    master_key = entry_master_key.get()
    if not master_key:
        messagebox.showerror("Error", "Please enter your master pass-key.")
        return
    try:
        with open('master_key.txt', 'r') as file:
            line = file.readline()
            if not line or ':' not in line:
                raise ValueError("Master password file is corrupted or empty.")
            salt_hex, hashed_master_key_stored = map(str.strip, line.split(':'))
            salt = bytes.fromhex(salt_hex)
    except FileNotFoundError:
        button_set_master_password.place(x=150, y=220)
        messagebox.showinfo("Setup Required", "No master password set. Please set one now.")
        return
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
        return
    try:
        hashed_master_key_entered = derive_key(master_key, salt).hex()
        if hashed_master_key_entered == hashed_master_key_stored:
            master_password_set = True
            messagebox.showinfo("Master Password Verified", "Master password verified successfully.")
        else:
            master_password_set = False
            messagebox.showerror("Error", "Incorrect master password.")
    except Exception as e:
        messagebox.showerror("Error", f"Verification error: {str(e)}")
        master_password_set = False

def generate_password():
    if not master_password_set:
        messagebox.showerror("Error", "Please verify or set the master password first.")
        return
    try:
        length = int(entry_length.get())
        if length <= 0:
            raise ValueError()
    except ValueError:
        messagebox.showerror("Error", "Enter a valid positive number for password length.")
        return
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    password_text.config(state='normal')
    password_text.delete(0, tk.END)
    password_text.insert(tk.END, password)
    password_text.config(state='readonly')
    label_password_text.config(text="Generated Password:")
    messagebox.showinfo("Generated Password", f"Your password is: {password}")

def hash_password():
    if not master_password_set:
        messagebox.showerror("Error", "Please verify or set the master password first.")
        return
    password = entry_password.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password to hash.")
        return
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password.encode())
    hashed_password = digest.finalize()
    messagebox.showinfo("Hashed Password", f"The hashed password is: {hashed_password.hex()}")

def save_password():
    if not master_password_set:
        messagebox.showerror("Error", "Please verify or set the master password first.")
        return

    master_key = entry_master_key.get()
    password = entry_password.get()
    platform = entry_platform.get().strip()

    if not master_key or not password or not platform:
        messagebox.showerror("Error", "Please fill in all fields.")
        return

    salt = secrets.token_bytes(16)
    key = derive_key(master_key, salt)
    key = base64.urlsafe_b64encode(key).ljust(32, b'=')

    try:
        cipher_suite = Fernet(key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        new_entry = f"{platform}: {salt.hex()}:{encrypted_password.decode()}\n"

        updated_lines = []
        platform_found = False

        try:
            with open('passwords.txt', 'r') as file:
                for line in file:
                    if line.startswith(f"{platform}:"):
                        updated_lines.append(new_entry)
                        platform_found = True
                    else:
                        updated_lines.append(line)
        except FileNotFoundError:
            pass

        if not platform_found:
            updated_lines.append(new_entry)

        with open('passwords.txt', 'w') as file:
            file.writelines(updated_lines)

        if platform_found:
            messagebox.showinfo("Password Updated", f"Password for '{platform}' updated successfully.")
        else:
            messagebox.showinfo("Password Saved", f"Password for '{platform}' saved successfully.")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while saving the password: {str(e)}")

def retrieve_password():
    if not master_password_set:
        messagebox.showerror("Error", "Please verify or set the master password first.")
        return
    master_key = entry_master_key.get()
    platform = entry_platform.get()
    if not master_key or not platform:
        messagebox.showerror("Error", "Please enter both master key and platform.")
        return
    try:
        with open('passwords.txt', 'r') as file:
            for line in file:
                if line.startswith(f"{platform}:"):
                    parts = line.split(':')
                    salt = bytes.fromhex(parts[1].strip())
                    encrypted_password = parts[2].strip()
                    key = derive_key(master_key, salt)
                    key = key[:32]
                    cipher_suite = Fernet(base64.urlsafe_b64encode(key))
                    decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
                    password_text.config(state='normal')
                    password_text.delete(0, tk.END)
                    password_text.insert(tk.END, decrypted_password)
                    label_password_text.config(text="Retrieved Password:")
                    messagebox.showinfo("Decrypted Password", f"Your password for {platform} is: {decrypted_password}")
                    return
            messagebox.showerror("Error", f"No password found for platform: {platform}")
    except Exception as e:
        messagebox.showerror("Error", f"Error retrieving password: {str(e)}")

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

def show_about_dialog():
    about_window = tk.Toplevel(app)
    about_window.title("About Password Genie")
    about_window.geometry("300x200")
    about_window.resizable(False, False)

    tk.Label(about_window, text="Password Genie", font=("Helvetica", 14, "bold")).pack(pady=(10, 0))
    tk.Label(about_window, text="Version 1.2.0").pack()
    tk.Label(about_window, text="Created by Kaotick Jay").pack()
    tk.Label(about_window, text="License: GNU/GPL3").pack()
    tk.Label(about_window, text="© 2023 Kaotick Jay").pack()

    def open_github(event):
        webbrowser.open_new("https://github.com/kaotickj")

    link = tk.Label(about_window, text="GitHub: https://github.com/kaotickj", fg="blue", cursor="hand2")
    link.pack(pady=10)
    link.bind("<Button-1>", open_github)

def show_instructions():
    instructions = (
        "INSTRUCTIONS FOR USE:\n\n"
        "1. Enter your Master Pass-Key.\n"
        "2. If not set, click 'Set Master Password'.\n"
        "3. Otherwise, click 'Verify Master Password'.\n"
        "4. Use 'Generate', 'Hash', 'Save', or 'Retrieve' as needed.\n"
        "5. To update a password, enter the platform again and click 'Save'.\n"
        "6. 'Copy to Clipboard' copies the password shown.\n"
    )
    messagebox.showinfo("Instructions for Use", instructions)

def open_donation_link(url):
    webbrowser.open_new(url)

def check_and_initialize_master_password():
    global master_password_set
    try:
        with open('master_key.txt', 'r') as file:
            line = file.readline()
            if line and ':' in line:
                master_password_set = True
                button_set_master_password.place_forget()
            else:
                raise ValueError("Corrupt or empty master_key.txt")
    except FileNotFoundError:
        master_password_set = False
        button_set_master_password.place(x=150, y=220)
    except Exception as e:
        master_password_set = False
        messagebox.showerror("Startup Error", f"An error occurred: {str(e)}")
        button_set_master_password.place(x=150, y=220)

# Layout
label_master_key.place(x=10, y=10)
entry_master_key.place(x=150, y=10)
label_password.place(x=10, y=40)
entry_password.place(x=150, y=40)
label_length.place(x=10, y=70)
entry_length.place(x=150, y=70)
label_requirements.place(x=10, y=100)
entry_requirements.place(x=150, y=100)
label_platform.place(x=10, y=130)
entry_platform.place(x=150, y=130)
label_password_text.place(x=10, y=260)
password_text.place(x=150, y=260)

button_generate = tk.Button(app, text="Generate Password", command=generate_password)
button_generate.place(x=10, y=160)
button_hash = tk.Button(app, text="Hash Password", command=hash_password)
button_hash.place(x=170, y=160)
button_save = tk.Button(app, text="Save Password", command=save_password)
button_save.place(x=10, y=190)
button_retrieve = tk.Button(app, text="Retrieve Password", command=retrieve_password)
button_retrieve.place(x=170, y=190)
button_verify_master_password = tk.Button(app, text="Verify Master Password", command=verify_master_password)
button_verify_master_password.place(x=10, y=220)
button_set_master_password = tk.Button(app, text="Set Master Password", command=set_master_password)

copy_button = tk.Button(app, text="Copy to Clipboard", command=lambda: (
    app.clipboard_clear(),
    app.clipboard_append(password_text.get()),
    app.update(),
    messagebox.showinfo("Copied", "Password copied to clipboard.")
))
copy_button.place(x=10, y=290)

menu_bar = tk.Menu(app)
app.config(menu=menu_bar)
about_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Help", menu=about_menu)
about_menu.add_command(label="Instructions for Use", command=show_instructions)
about_menu.add_separator()
about_menu.add_command(label="About Password Genie", command=show_about_dialog)
donate_menu = tk.Menu(about_menu, tearoff=0)
donate_menu.add_command(label="GitHub: @kaotickj", command=lambda: open_donation_link("https://github.com/sponsors/kaotickj"))
donate_menu.add_command(label="Patreon: KaotickJay", command=lambda: open_donation_link("https://patreon.com/KaotickJay"))
donate_menu.add_command(label="PayPal: Donate Here", command=lambda: open_donation_link("https://paypal.me/kaotickj"))

about_menu.add_cascade(label="Donate", menu=donate_menu)

check_and_initialize_master_password()
app.mainloop()
