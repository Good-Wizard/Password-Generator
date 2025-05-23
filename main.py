import os
import sqlite3
import argparse
import hashlib
import random
import string
import csv
import bcrypt
import re
from cryptography.fernet import Fernet
from datetime import datetime
from fuzzywuzzy import process

def validate_password(password):
    issues = []
    
    if len(password) < 12:
        issues.append("⛔ The password is too short! At least 12 characters are recommended.")
    
    if not re.search(r"[A-Z]", password):
        issues.append("🔹 The password must contain at least one uppercase letter.")
    
    if not re.search(r"[a-z]", password):
        issues.append("🔹 The password must contain at least one lowercase letter.")
    
    if not re.search(r"\d", password):
        issues.append("🔹 The password must include at least one number.")
    
    if not re.search(r"[!@#$%^&*()_+=\-{}[\]:;\"'<>,.?/]", password):
        issues.append("🔹 The password must include at least one special character.")
    
    if issues:
        print("\n🔍 **Password Issues:**")
        for issue in issues:
            print(issue)
        print("\nSuggestions for Improvement:")
        print("- Use a mix of uppercase and lowercase letters, numbers, and special characters.")
        print("- Choose a longer and more complex password.")
    else:
        print("\n✅ The password is secure!")


def load_or_create_key():
    key_file = "secret.key"
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    else:
        key = open(key_file, "rb").read()
    return key

def encrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data.encode()).decode()

def init_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            title TEXT,
            password TEXT,
            hash TEXT,
            date TEXT
        )
    """)
    conn.commit()
    conn.close()

# بازیابی رمزهای ذخیره‌شده
def get_passwords(key):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT title, password, hash, date FROM passwords")
    rows = cursor.fetchall()
    conn.close()
    
    decrypted_passwords = [(title, decrypt_data(password, key), hash_value, date) for title, password, hash_value, date in rows]
    return decrypted_passwords

# تولید رمز عبور
def generate_password(length=12, special_chars=True, numbers=True):
    chars = string.ascii_letters
    if special_chars:
        chars += string.punctuation
    if numbers:
        chars += string.digits
    return ''.join(random.choice(chars) for _ in range(length))

# تولید هش
def generate_hash(password, algorithm='sha256'):
    if algorithm == 'bcrypt':
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()
    
    hash_func = getattr(hashlib, algorithm, None)
    if not hash_func:
        raise ValueError("Unsupported hash algorithm")
    
    return hash_func(password.encode()).hexdigest()

def add_password(title, password, hash_value, key):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    encrypted_password = encrypt_data(password, key)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO passwords (title, password, hash, date) VALUES (?, ?, ?, ?)", (title, encrypted_password, hash_value, current_time))
    conn.commit()
    conn.close()

def get_passwords(key):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT title, password, hash, date FROM passwords")
    rows = cursor.fetchall()
    conn.close()
    
    decrypted_passwords = [(title, decrypt_data(password, key), hash_value, date) for title, password, hash_value, date in rows]
    return decrypted_passwords

def validate_csv_filename(filename):
    if filename.endswith(".csv"):
        return filename
    elif "." not in filename:
        return filename + ".csv"
    else:
        raise ValueError("Invalid file extension. Please use a .csv file.")

def save_to_csv(passwords, filename):
    try:
        filename = validate_csv_filename(filename)
        with open(filename, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Title", "Password", "Hash", "Date"])
            writer.writerows(passwords)
        print(f"Saved to {filename}")
    except ValueError as e:
        print(f"Error: {e}")

def delete_password(title):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE title = ?", (title,))
    if cursor.fetchone():
        confirm = input(f"⚠️ Are you sure you want to delete '{title}'? (yes/no): ")
        if confirm.lower() == "yes":
            cursor.execute("DELETE FROM passwords WHERE title = ?", (title,))
            conn.commit()
            print(f"✅ Password for '{title}' deleted successfully.")
        else:
            print("❌ Operation canceled.")
    else:
        print(f"🔍 No password found for '{title}'.")
    conn.close()

def interactive_mode():
    print("\n🔐 Welcome to Interactive Password Manager!")
    print("Follow the steps below to generate and manage your passwords.")
    
    length = int(input("\n🔹 Enter password length (recommended: 12+): "))
    special_chars = input("🔹 Include special characters? (yes/no): ").strip().lower() == "yes"
    numbers = input("🔹 Include numbers? (yes/no): ").strip().lower() == "yes"
    title = input("🔹 Enter title for password storage (or leave blank): ").strip() or "Untitled"
    
    password = generate_password(length, special_chars, numbers)
    hash_value = hashlib.sha256(password.encode()).hexdigest()
    
    print(f"\n✅ Generated Password: {password}")
    print(f"🔹 SHA-256 Hash: {hash_value}")
    
    save_option = input("\n🔹 Do you want to save the password? (yes/no): ").strip().lower()
    if save_option == "yes":
        add_password(title, password, hash_value, key)
        print(f"✅ Password stored securely under '{title}'!")

    csv_option = input("\n🔹 Do you want to save it to a CSV file? (yes/no): ").strip().lower()
    if csv_option == "yes":
        csv_filename = input("🔹 Enter CSV filename: ").strip()
        save_to_csv([(title, password, hash_value, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))], csv_filename)

    print("\n🎉 Password management complete!")

def search_password(title, key):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT title FROM passwords")
    all_titles = [row[0] for row in cursor.fetchall()]
    
    best_match, confidence = process.extractOne(title, all_titles)
    
    if confidence > 60:  # حداقل درصد تطابق مورد نیاز
        cursor.execute("SELECT title, password, hash, date FROM passwords WHERE title = ?", (best_match,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            title, encrypted_password, hash_value, date = row
            decrypted_password = decrypt_data(encrypted_password, key)
            print(f"\n🔍 Best Match Found ({confidence}% Similarity):")
            print(f"Title: {title}")
            print(f"Password: {decrypted_password}")
            print(f"Hash: {hash_value}")
            print(f"Date Stored: {date}")
        else:
            print(f"❌ No password found for '{title}'.")
    else:
        print(f"❌ No close matches found for '{title}'.")

def update_password(title, new_password, key):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE title = ?", (title,))
    if cursor.fetchone():
        encrypted_password = encrypt_data(new_password, key)
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        cursor.execute("UPDATE passwords SET password = ?, hash = ? WHERE title = ?", (encrypted_password, new_hash, title))
        conn.commit()
        print(f"✅ Password for '{title}' updated successfully.")
    else:
        print(f"❌ No password found for '{title}'.")
    conn.close()

key = load_or_create_key()
init_db()

def main():
    parser = argparse.ArgumentParser(description="Password & Hash Generator CLI")
    parser.add_argument("-l", "--length", type=int, help="Password length")
    parser.add_argument("-s", "--special", action="store_true", help="Include special characters")
    parser.add_argument("-n", "--numbers", action="store_true", help="Include numbers")
    parser.add_argument("-csv", "--csv", type=str, help="Save passwords to CSV file")
    parser.add_argument("-sv", "--save", type=str, help="Store password with title")
    
    args = parser.parse_args()
    
    # اگر هیچ آرگومانی وارد نشده باشد، وارد حالت تعاملی می‌شود
    if not any(vars(args).values()):
        interactive_mode()
        return
    
    # حالت خط فرمان (Command-Line Mode)
    length = args.length or 12
    special_chars = args.special
    numbers = args.numbers
    title = args.save or "Untitled"
    
    password = generate_password(length, special_chars, numbers)
    hash_value = hashlib.sha256(password.encode()).hexdigest()

    print(f"\n✅ Generated Password: {password}")
    print(f"🔹 SHA-256 Hash: {hash_value}")

    if args.csv:
        save_to_csv([(title, password, hash_value, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))], args.csv)

    if args.save:
        add_password(title, password, hash_value, key)
        print(f"✅ Password stored securely under '{title}'!")

if __name__ == "__main__":
    main()