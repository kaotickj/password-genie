import tkinter as tk
from tkinter import messagebox
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
app.geometry("300x100")

# Entry for the user's master pass-key
label_master_key = tk.Label(app, text="Master Pass-Key:")
entry_master_key = tk.Entry(app, show="*")  # Use show="*" to hide the entered characters




# Flag to check if the master password is set
master_password_set = None  # Initialize as None


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



# Place widgets using the place method
label_master_key.place(x=10, y=10)
entry_master_key.place(x=150, y=10)
ToolTip(entry_master_key, "Enter your master pass-key")

button_set_master_password = tk.Button(app, text="Set Master Password", command=set_master_password)
ToolTip(button_set_master_password, "Set the initial master password")
button_set_master_password.place(x=10, y=40)



# Main Event Loop
app.mainloop()
