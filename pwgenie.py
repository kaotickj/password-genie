import tkinter as tk
from tkinter import messagebox, ttk, Toplevel, Text, Scrollbar, RIGHT, Y, BOTH, END
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
from datetime import datetime
import sqlite3

SCHEMA_VERSION = 1

# === Database connection helper ===
if getattr(sys, 'frozen', False):
    # Running as a PyInstaller bundle
    APP_DIR = os.path.dirname(sys.executable)
else:
    # Running in normal Python environment
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(APP_DIR, "vault.db")


def get_db_connection():
    return sqlite3.connect(DB_PATH)


def initialize_db():
    print(f"Generating Database: First run - Vault database tables are being generated.")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Create schema_version table
    c.execute('''
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        )
    ''')

    # Set initial schema version only if table is empty
    c.execute("SELECT COUNT(*) FROM schema_version")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))

    # Other tables
    c.execute('''
        CREATE TABLE IF NOT EXISTS master_key (
            id INTEGER PRIMARY KEY,
            salt BLOB NOT NULL,
            hashed_master_key BLOB NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password_encrypted BLOB NOT NULL
        )
    ''')

    conn.commit()
    conn.close()


def check_schema_version():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT version FROM schema_version LIMIT 1")
        row = c.fetchone()
        conn.close()

        if not row:
            raise Exception("Missing schema version entry.")

        current_version = row[0]
        if current_version != SCHEMA_VERSION:
            messagebox.showerror(
                "Schema Version Error",
                f"Expected schema version {SCHEMA_VERSION}, but found version {current_version}.\n"
                f"Please update the database or application."
            )
            sys.exit(1)
    except sqlite3.OperationalError as e:
        messagebox.showerror("Database Error", f"Missing schema_version table.\n\nError: {e}")
        sys.exit(1)
    except Exception as e:
        messagebox.showerror("Schema Check Error", str(e))
        sys.exit(1)


# === Key derivation ===
def derive_key(master_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    return kdf.derive(master_key.encode())


if not os.path.exists(DB_PATH):
    initialize_db()
else:
    check_schema_version()

# === GUI setup ===
app = tk.Tk()
app.title("Password Genie")
if sys.platform.startswith("linux"):
    app.geometry("440x500")
else:
    app.geometry("420x480")


def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


def set_window_icon():
    icon_ico = resource_path("icon.ico")
    icon_png = resource_path("icon.png")
    if sys.platform.startswith("win"):
        if os.path.exists(icon_ico):
            try:
                app.iconbitmap(icon_ico)
            except Exception as e:
                print(f"Warning: Failed to set Windows .ico icon: {e}")
        else:
            print("Notice: icon.ico not found. Skipping icon set on Windows.")
    else:
        try:
            from tkinter import PhotoImage
            if os.path.exists(icon_png):
                icon_image = PhotoImage(file=icon_png)
                app.iconphoto(False, icon_image)
            else:
                print("Notice: icon.png not found. Skipping icon set on non-Windows platform.")
        except Exception as e:
            print(f"Warning: Failed to set PNG window icon: {e}")


set_window_icon()

# === Widgets ===
label_master_key = tk.Label(app, text="Master Passkey:")
entry_master_key = tk.Entry(app, show="*")

label_password = tk.Label(app, text="Password to Save:")
entry_password = tk.Entry(app, show="*")

label_length = tk.Label(app, text="Password Length:")
entry_length = tk.Entry(app)
entry_length.insert(0, "16")

label_requirements = tk.Label(app, text="Character Requirements:")
label_requirements.place(x=10, y=110)

# Create a frame to hold checkboxes horizontally
frame_requirements = tk.Frame(app)
frame_requirements.place(x=150, y=110)

# Boolean variables for each checkbox
var_letters = tk.BooleanVar(value=True)
var_digits = tk.BooleanVar(value=True)
var_punctuation = tk.BooleanVar(value=True)

# Create the checkboxes
chk_letters = tk.Checkbutton(frame_requirements, text="Letters", variable=var_letters)
chk_letters.pack(side=tk.LEFT, padx=(0, 10))  # Add some padding between checkboxes

chk_digits = tk.Checkbutton(frame_requirements, text="Digits", variable=var_digits)
chk_digits.pack(side=tk.LEFT, padx=(0, 10))

chk_punctuation = tk.Checkbutton(frame_requirements, text="Punctuation", variable=var_punctuation)
chk_punctuation.pack(side=tk.LEFT)
label_platform = tk.Label(app, text="Platform:")
entry_platform = tk.Entry(app)

# Added Username field
label_username = tk.Label(app, text="Username:")
entry_username = tk.Entry(app)

# Saved platforms combobox and label
label_saved_platforms = tk.Label(app, text="Saved Platforms:")
combo_platforms = ttk.Combobox(app, state="readonly")

label_password_text = tk.Label(app, text="Generated Password:")
password_text = tk.Entry(app, state='readonly', width=20)

master_password_set = None


# === Functions ===
def set_master_password():
    global master_password_set
    master_key = entry_master_key.get()
    if not master_key:
        messagebox.showerror("Error", "Please enter a master passkey.")
        return
    if not messagebox.askyesno("Set Master Password", "This will set the initial master password. Proceed?"):
        return
    salt = secrets.token_bytes(16)
    hashed_master_key = derive_key(master_key, salt)
    try:
        conn = get_db_connection()
        c = conn.cursor()
        # Check if already set
        c.execute("SELECT COUNT(*) FROM master_key")
        if c.fetchone()[0] > 0:
            messagebox.showerror("Error", "Master password already exists. Use 'Verify' instead.")
            conn.close()
            return
        c.execute("INSERT INTO master_key (salt, hashed_master_key) VALUES (?, ?)", (salt, hashed_master_key))
        conn.commit()
        conn.close()
        master_password_set = True
        button_set_master_password.place_forget()
        messagebox.showinfo("Success", "Master password set successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to set master password: {str(e)}")


def verify_master_password():
    global master_password_set
    master_key = entry_master_key.get()
    if not master_key:
        messagebox.showerror("Error", "Please enter your master passkey.")
        return
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT salt, hashed_master_key FROM master_key LIMIT 1")
        row = c.fetchone()
        conn.close()
        if not row:
            messagebox.showinfo("Setup Required", "No master password set. Please set one now.")
            button_set_master_password.place(x=10, y=40)
            return
        salt, stored_hashed_master_key = row
        derived_key = derive_key(master_key, salt)
        if derived_key == stored_hashed_master_key:
            master_password_set = True
            messagebox.showinfo("Success", "Master password verified successfully.")
            button_set_master_password.place_forget()
            # Populate platforms now that master password is verified
            update_platform_combobox()
        else:
            master_password_set = False
            messagebox.showerror("Error", "Incorrect master password.")
            combo_platforms['values'] = []
            combo_platforms.place_forget()
            label_saved_platforms.place_forget()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during verification: {str(e)}")


# Define the problematic special characters to exclude
PROBLEMATIC_PUNCTUATION = set('<>:"/\\|?*~`')


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

    # Build character set based on checkbox selections
    characters = ""
    if var_letters.get():
        characters += string.ascii_letters
    if var_digits.get():
        characters += string.digits
    if var_punctuation.get():
        characters += string.punctuation

    if not characters:
        messagebox.showerror("Error", "Please select at least one character type.")
        return

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
    username = entry_username.get().strip()
    if not master_key or not password or not platform or not username:
        messagebox.showerror("Error", "Please fill in all fields including Username.")
        return
    salt = secrets.token_bytes(16)
    key = derive_key(master_key, salt)
    key_b64 = base64.urlsafe_b64encode(key)
    try:
        cipher_suite = Fernet(key_b64)
        encrypted_password = cipher_suite.encrypt(password.encode())
        # Store as: salt + b':' + encrypted_password blob
        stored_blob = salt + b':' + encrypted_password
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM credentials WHERE service = ?", (platform,))
        row = c.fetchone()
        if row:
            c.execute(
                "UPDATE credentials SET username = ?, password_encrypted = ? WHERE service = ?",
                (username, stored_blob, platform)
            )
            messagebox.showinfo("Password Updated", f"Username and password for '{platform}' updated successfully.")
        else:
            c.execute(
                "INSERT INTO credentials (service, username, password_encrypted) VALUES (?, ?, ?)",
                (platform, username, stored_blob)
            )
            messagebox.showinfo("Password Saved", f"Username and password for '{platform}' saved successfully.")
        conn.commit()
        conn.close()
        update_platform_combobox()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while saving: {str(e)}")


def retrieve_password():
    if not master_password_set:
        messagebox.showerror("Error", "Please verify or set the master password first.")
        return
    master_key = entry_master_key.get()
    platform = entry_platform.get().strip()
    if not master_key or not platform:
        messagebox.showerror("Error", "Please enter both master key and platform.")
        return
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT username, password_encrypted FROM credentials WHERE service = ?", (platform,))
        row = c.fetchone()
        conn.close()
        if not row:
            messagebox.showerror("Error", f"No credentials found for platform: {platform}")
            return
        username, encrypted_blob = row

        if isinstance(encrypted_blob, memoryview):
            encrypted_blob = encrypted_blob.tobytes()

        salt, encrypted_password = encrypted_blob.split(b':', 1)

        key = derive_key(master_key, salt)
        key_b64 = base64.urlsafe_b64encode(key)
        cipher_suite = Fernet(key_b64)
        decrypted_password = cipher_suite.decrypt(encrypted_password).decode()

        # Update GUI fields for username and password
        entry_username.delete(0, tk.END)
        entry_username.insert(0, username)

        password_text.config(state='normal')
        password_text.delete(0, tk.END)
        password_text.insert(tk.END, decrypted_password)
        password_text.config(state='readonly')

        label_password_text.config(text="Retrieved Password:")
        messagebox.showinfo("Decrypted Password",
                            f"Credentials for {platform}:\n\nUsername: {username}\nPassword: {decrypted_password}")
    except Exception as e:
        messagebox.showerror("Error", f"Error retrieving credentials: {str(e)}")


def update_platform_combobox():
    try:
        platforms = []
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT DISTINCT service FROM credentials")
        rows = c.fetchall()
        conn.close()
        for row in rows:
            platform_name = row[0]
            if platform_name and platform_name not in platforms:
                platforms.append(platform_name)
        platforms.sort()
        combo_platforms['values'] = platforms
        if platforms:
            combo_platforms.current(0)
            label_saved_platforms.place(x=10, y=230)
            combo_platforms.place(x=150, y=230)
        else:
            label_saved_platforms.place_forget()
            combo_platforms.place_forget()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while loading saved platforms: {str(e)}")
        label_saved_platforms.place_forget()
        combo_platforms.place_forget()


def on_platform_selected(event):
    selected = combo_platforms.get()
    if selected:
        entry_platform.delete(0, tk.END)
        entry_platform.insert(0, selected)
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT username FROM credentials WHERE service = ?", (selected,))
            row = c.fetchone()
            conn.close()
            if row:
                entry_username.delete(0, tk.END)
                entry_username.insert(0, row[0])
            else:
                entry_username.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Error fetching username: {str(e)}")
            entry_username.delete(0, tk.END)


def list_saved_platforms():
    if not master_password_set:
        messagebox.showerror("Error", "Please verify or set the master password first.")
        return
    update_platform_combobox()
    if combo_platforms.winfo_ismapped():
        combo_platforms.focus_set()


def show_about_dialog():
    about_window = tk.Toplevel(app)
    about_window.title("About Password Genie")
    about_window.geometry("300x200")
    about_window.resizable(False, False)
    tk.Label(about_window, text="Password Genie", font=("Helvetica", 14, "bold")).pack(pady=(10, 0))
    tk.Label(about_window, text="Version 1.2.0").pack()
    tk.Label(about_window, text="Created by Kaotick Jay").pack()
    tk.Label(about_window, text="License: GNU/GPL3").pack()
    start_year = 2023
    current_year = datetime.now().year
    year_display = f"{start_year}–{current_year}" if current_year > start_year else str(start_year)
    tk.Label(about_window, text=f"© {year_display} Kaotick Jay").pack()

    def open_github(event):
        webbrowser.open_new("https://github.com/kaotickj")

    link = tk.Label(about_window, text="GitHub: https://github.com/kaotickj", fg="blue", cursor="hand2")
    link.pack(pady=10)
    link.bind("<Button-1>", open_github)


def show_instructions():
    instructions = (
        "🔐 INSTRUCTIONS FOR USING PASSWORD GENIE 🔐\n\n"
        "1. Enter Your Master Passkey:\n"
        "   - Required to access any vault features.\n"
        "   - If this is your first time, proceed to Step 2.\n\n"
        "2. Set Master Password:\n"
        "   - Click 'Set Master Password' to create your key.\n"
        "   - This passkey encrypts and protects all stored data.\n\n"
        "3. Verify Passkey:\n"
        "   - If you’ve set your key already, click to unlock the vault.\n"
        "   - Once verified, all features are enabled.\n\n"
        "4. Using the Vault:\n"
        "   - Generate: Create a secure random password.\n"
        "   - Hash: Hash anything in the 'Password to Save' field.\n"
        "   - Save: Store/update a record (platform + username).\n"
        "       • To update, re-enter platform and username, then click Save.\n"
        "   - Retrieve: Load and display stored credentials.\n\n"
        "5. Copy to Clipboard:\n"
        "   - After generating or retrieving a password, copy it instantly.\n"
        "   - Paste it where needed without retyping.\n\n"
        "⚠️  NOTE:\n"
        "   - Remember your master password — it's unrecoverable if lost.\n"
        "   - Always close the app securely to prevent tampering.\n"
    )

    # Create a scrollable Toplevel window
    win = Toplevel()
    win.title("Instructions for Use")
    win.geometry("600x500")
    win.resizable(True, True)

    # Configure fonts and text display
    text_frame = Text(win, wrap='word', padx=10, pady=10, font=("Courier New", 11))
    text_frame.insert(END, instructions)
    text_frame.config(state='disabled')  # Make read-only
    text_frame.pack(expand=True, fill=BOTH)

    # Add vertical scrollbar
    scrollbar = Scrollbar(text_frame, command=text_frame.yview)
    text_frame['yscrollcommand'] = scrollbar.set
    scrollbar.pack(side=RIGHT, fill=Y)

def open_donation_link(url):
    webbrowser.open_new(url)


def check_and_initialize_master_password():
    global master_password_set
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM master_key")
        count = c.fetchone()[0]
        conn.close()
        if count > 0:
            master_password_set = False
            button_set_master_password.place_forget()
            combo_platforms['values'] = []
            combo_platforms.place_forget()
            label_saved_platforms.place_forget()
        else:
            master_password_set = False
            button_set_master_password.place(x=10, y=40)
            combo_platforms['values'] = []
            combo_platforms.place_forget()
            label_saved_platforms.place_forget()
    except Exception as e:
        messagebox.showerror("Startup Error", f"Database error: {str(e)}")
        master_password_set = False
        button_set_master_password.place(x=150, y=270)
        combo_platforms['values'] = []
        combo_platforms.place_forget()
        label_saved_platforms.place_forget()


# === Layout placements ===
label_master_key.place(x=10, y=10)
entry_master_key.place(x=150, y=10)

button_verify_master_password = tk.Button(app, text="Verify Passkey", command=verify_master_password)
button_verify_master_password.place(x=290, y=10)

label_length.place(x=10, y=80)
entry_length.place(x=150, y=80)

# label_requirements.place(x=10, y=110)
# entry_requirements.place(x=150, y=110)

label_platform.place(x=10, y=140)
entry_platform.place(x=150, y=140)

label_username.place(x=10, y=170)
entry_username.place(x=150, y=170)

label_password.place(x=10, y=200)
entry_password.place(x=150, y=200)

label_saved_platforms.place(x=10, y=230)
combo_platforms.place(x=150, y=230)

label_password_text.place(x=10, y=350)
password_text.place(x=150, y=350)

button_generate = tk.Button(app, text="Generate Password", command=generate_password)
button_generate.place(x=10, y=270)

button_hash = tk.Button(app, text="Hash Password", command=hash_password)
button_hash.place(x=170, y=270)

button_save = tk.Button(app, text="Save Password", command=save_password)
button_save.place(x=10, y=310)

button_retrieve = tk.Button(app, text="Retrieve Password", command=retrieve_password)
button_retrieve.place(x=170, y=310)

button_set_master_password = tk.Button(app, text="Set Master Password", command=set_master_password)

copy_button = tk.Button(app, text="Copy Password to Clipboard", command=lambda: (
    app.clipboard_clear(),
    app.clipboard_append(password_text.get()),
    app.update(),
    messagebox.showinfo("Copied", "Password copied to clipboard.")
))
copy_button.place(x=10, y=390)

combo_platforms.bind("<<ComboboxSelected>>", on_platform_selected)

# Menu Bar
menu_bar = tk.Menu(app)
app.config(menu=menu_bar)
about_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Help", menu=about_menu)
about_menu.add_command(label="Instructions for Use", command=show_instructions)
# about_menu.add_command(label="List Saved Platforms", command=list_saved_platforms)
about_menu.add_command(label="About Password Genie", command=show_about_dialog)
about_menu.add_separator()
donate_menu = tk.Menu(about_menu, tearoff=0)
donate_menu.add_command(label="GitHub: @kaotickj",
                        command=lambda: open_donation_link("https://github.com/sponsors/kaotickj"))
donate_menu.add_command(label="Patreon: KaotickJay",
                        command=lambda: open_donation_link("https://patreon.com/KaotickJay"))
donate_menu.add_command(label="PayPal: Donate Here", command=lambda: open_donation_link("https://paypal.me/kaotickj"))
about_menu.add_cascade(label="Donate", menu=donate_menu)

check_and_initialize_master_password()
app.mainloop()
