import tkinter as tk
from tkinter import messagebox, filedialog
import json
import logging
import os
import random
import string
from cryptography.fernet import Fernet
from PIL import Image
import numpy as np
import smtplib
from email.message import EmailMessage
import tempfile

# Configure logging
logging.basicConfig(filename="password_manager.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Generate a key for encryption
KEY_FILE = "encryption.key"
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
else:
    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read()
fernet = Fernet(key)

# JSON file to store user data
DATA_FILE = "users.json"
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w") as file:
        json.dump({}, file)

# Function to generate a random password
def generate_password():
    return "".join(random.choices(string.ascii_letters + string.digits, k=12))

# Function to generate OTP
def generate_otp():
    return random.randint(100000, 999999)

# Function to send email with OTP
def send_otp_email(receiver_email, otp):
    sender_email = "batch10.csec@gmail.com"
    sender_password = "gptr dvcl qruz gakz"  # Use your app-specific password
    subject = "Your Registration OTP"
    
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg.set_content(f"Your OTP for registration is: {otp}")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        logging.info(f"OTP sent to {receiver_email}")
    except Exception as e:
        logging.error(f"Error sending OTP to {receiver_email}: {e}")

# Function to generate visual shares
def generate_visual_shares(password, num_users):
    img_size = (200, 50)
    shares = []
    base_share = np.random.randint(0, 2, img_size, dtype=np.uint8) * 255
    
    for _ in range(num_users - 1):
        share = np.random.randint(0, 2, img_size, dtype=np.uint8) * 255
        shares.append(share)
    
    final_share = base_share.copy()
    for share in shares:
        final_share = np.bitwise_xor(final_share, share)
    shares.append(final_share)
    
    share_paths = []  # Store paths to shares
    for i, share in enumerate(shares):
        img = Image.fromarray(share, mode="L")
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temp_file:
            img.save(temp_file.name)
            share_paths.append(temp_file.name)
    
    return share_paths

# Function to send email with password share
def send_email(receiver_email, share_path):
    sender_email = "batch10.csec@gmail.com"
    sender_password = "gptr dvcl qruz gakz"  # Use your app-specific password
    subject = "Your Password Share"
    
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg.set_content("Attached is your password share. Keep it safe for future unlocking of the tool. Please do not reply to this email.")

    with open(share_path, "rb") as f:
        file_data = f.read()
        msg.add_attachment(file_data, maintype="image", subtype="png", filename=os.path.basename(share_path))
    
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        logging.info(f"Share sent to {receiver_email}")
    except Exception as e:
        logging.error(f"Error sending email to {receiver_email}: {e}")

# Function to send alert email
def send_alert_email(receiver_email, subject, content):
    sender_email = "batch10.csec@gmail.com"
    sender_password = "gptr dvcl qruz gakz"  # Use your app-specific password

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg.set_content(content)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        logging.info(f"Alert sent to {receiver_email}")
    except Exception as e:
        logging.error(f"Error sending alert email to {receiver_email}: {e}")

# GUI Application
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.geometry("600x600")
        self.root.title("Multi-User Password Manager")
        self.root.configure(bg="#181818")  # Dark background
        
        # Title
        self.title_label = tk.Label(root, text="⚡️ MULTI-USER PASSWORD MANAGER ⚡️", font=("Helvetica", 16, "bold"), bg="#181818", fg="#FF4081")
        self.title_label.pack(pady=30)

        with open(DATA_FILE, "r") as file:
            data = json.load(file)
            self.registration_complete = "users" in data
        
        self.create_widgets()

    def create_widgets(self):
        if not self.registration_complete:
            self.num_users_label = tk.Label(self.root, text="Number of Users:", font=("Arial", 14), bg="#181818", fg="white")
            self.num_users_label.pack(pady=(10, 0))
            self.num_users_entry = tk.Entry(self.root, width=25, font=("Arial", 12))
            self.num_users_entry.pack(pady=(0, 20))
            
            self.email_entries = []
            self.otps = {}  # Dictionary to store OTPs for each email
            self.register_button = tk.Button(self.root, text="Set Users", command=self.create_email_fields, font=("Arial", 14, "bold"), width=15, bg="#FF4081", fg="white", borderwidth=0, activebackground="#FF5983")
            self.register_button.pack(pady=(10, 0))
        else:
            self.upload_button = tk.Button(self.root, text="Upload Shares", command=self.upload_shares, font=("Arial", 14, "bold"), width=15, bg="#FF4081", fg="white", borderwidth=0, activebackground="#FF5983")
            self.upload_button.pack(pady=(60, 0))
        
        self.help_button = tk.Button(self.root, text="Help", command=self.show_help, font=("Arial", 14, "bold"), width=15, bg="#FF4081", fg="white", borderwidth=0, activebackground="#FF5983")
        self.help_button.pack(pady=(10, 0))
        
    def create_email_fields(self):
        try:
            self.num_users = int(self.num_users_entry.get())
            if self.num_users < 2:
                messagebox.showerror("Error", "At least two users are required.")
                return
            self.num_users_label.pack_forget()
            self.num_users_entry.pack_forget()
            self.register_button.pack_forget()
            
            for i in range(self.num_users):
                label = tk.Label(self.root, text=f"User {i + 1} Email:", bg="#181818", fg="white")
                label.pack(pady=(10, 0))
                entry = tk.Entry(self.root, width=25, font=("Arial", 12))
                entry.pack(pady=(0, 20))
                self.email_entries.append(entry)
            
            self.final_register_button = tk.Button(self.root, text="Register", command=self.register_users, font=("Arial", 14, "bold"), width=15, bg="#FF4081", fg="white", borderwidth=0, activebackground="#FF5983")
            self.final_register_button.pack(pady=(20, 0))
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number.")
    
    def register_users(self):
        emails = [entry.get() for entry in self.email_entries]
        if any(not email for email in emails):
            messagebox.showerror("Error", "All email fields are required.")
            return
        
        self.otps = {}  # Resetting the OTP dictionary
        
        for email in emails:
            otp = generate_otp()  # Generate the OTP for each user
            self.otps[email] = otp
            send_otp_email(email, otp)  # Send OTP to each user 

        # Open a new window for OTP verification
        self.open_otp_verification_window(emails)
        
    def open_otp_verification_window(self, emails):
        # Create a new Toplevel window
        self.otp_window = tk.Toplevel(self.root)
        self.otp_window.title("OTP Verification")
        self.otp_window.geometry("400x300")
        self.otp_window.configure(bg="#181818")

        self.otp_label = tk.Label(self.otp_window, text="Enter OTP for each user email:", bg="#181818", fg="white", font=("Arial", 14))
        self.otp_label.pack(pady=(10, 20))

        self.otp_entries = []  # Create a list for OTP entries
        for email in emails:
            otp_label = tk.Label(self.otp_window, text=f"Enter OTP sent to {email}", bg="#181818", fg="white")
            otp_label.pack(pady=(5, 0))
            otp_entry = tk.Entry(self.otp_window, width=25, font=("Arial", 12))
            otp_entry.pack(pady=(0, 10))
            self.otp_entries.append((email, otp_entry))  # Store tuple of (email, entry)

        self.verify_button = tk.Button(self.otp_window, text="Verify OTPs", command=self.verify_otps, font=("Arial", 14, "bold"), width=15, bg="#FF4081", fg="white", borderwidth=0, activebackground="#FF5983")
        self.verify_button.pack(pady=(20, 0))
        
    def verify_otps(self):
        all_verified = True
        for email, entry in self.otp_entries:
            entered_otp = entry.get()
            if str(self.otps[email]) != entered_otp:
                messagebox.showerror("Error", f"OTP for {email} is invalid!")
                all_verified = False
                break
        
        if all_verified:
            # Close the OTP window once verified
            self.otp_window.destroy()

            # Create a loading animation
            self.show_loading_animation("Generating...")
            
            password = generate_password()
            encrypted_password = fernet.encrypt(password.encode()).decode()
            share_paths = generate_visual_shares(password, self.num_users)
            
            with open(DATA_FILE, "r+") as file:
                data = json.load(file)
                data["users"] = {"emails": [entry[0] for entry in self.otp_entries], "password": encrypted_password}
                file.seek(0)
                json.dump(data, file, indent=4)

            for email, share_path in zip([entry[0] for entry in self.otp_entries], share_paths):
                send_email(email, share_path)
                os.remove(share_path)
                
            messagebox.showinfo("Success", "Users registered and shares sent!")
            logging.info("Users registered successfully.")
            self.root.after(1000, self.root.destroy)  # Destroy window after 1 second
        
    def show_loading_animation(self, message):
        self.loading_label = tk.Label(self.root, text=message, font=("Arial", 14, "bold"), bg="#181818", fg="#FF4081")
        self.loading_label.pack(pady=(20, 0))
        
        # Optionally, you can implement a basic animation here
        self.animate_loading()

    def animate_loading(self):
        dots = ['.', '..', '...']
        for i in range(5):  # Show 'Generating...' for 5 seconds
            for dot in dots:
                self.root.after(i * 1000, self.update_loading_text, dot)
        
    def update_loading_text(self, dots):
        self.loading_label.config(text=f"Generating{dots}")

    def upload_shares(self):
        file_paths = [filedialog.askopenfilename(title=f"Upload Share {i + 1}") for i in range(len(json.load(open(DATA_FILE))["users"]["emails"]))]
        if any(not path for path in file_paths):
            messagebox.showerror("Error", "All shares are required.")
            return

        with open(DATA_FILE, "r") as file:
            data = json.load(file)
            encrypted_password = data["users"]["password"]
            emails = data["users"]["emails"]

        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
        messagebox.showinfo("Success", f"Verification succeeded! Password retrieved successfully.")
        logging.info("Password successfully retrieved.")

        alert_subject = "Alert!!!"
        alert_content = "The tool was unlocked successfully using all shares. Please do not reply to this email."

        for email in emails:
            send_alert_email(email, alert_subject, alert_content)

        self.root.destroy()

    def show_help(self):
        messagebox.showinfo("Help", "Register by entering the number of users and their emails. Then, check your email for an OTP to confirm the registration.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()