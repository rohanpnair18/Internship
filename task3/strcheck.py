import hashlib
import re
import os

def check(password):
    length_ok = len(password) >= 8
    upper_ok = bool(re.search(r"[A-Z]", password))
    lower_ok = bool(re.search(r"[a-z]", password))
    digit_ok = bool(re.search(r"[0-9]", password))
    special_ok = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password))

    print("Password Complexity Check:")
    print(f" - Minimum length (8):       {'OK' if length_ok else 'FAIL'}")
    print(f" - Contains uppercase:       {'OK' if upper_ok else 'FAIL'}")
    print(f" - Contains lowercase:       {'OK' if lower_ok else 'FAIL'}")
    print(f" - Contains digits:          {'OK' if digit_ok else 'FAIL'}")
    print(f" - Contains special char:    {'OK' if special_ok else 'FAIL'}")

    if all([length_ok, upper_ok, lower_ok, digit_ok, special_ok]):
       strength="Strong"
       return strength
    else:
       strength="Weak"
       return strength

def hash_password(password):
    salt = os.urandom(16)
    hashed = hashlib.sha256(salt + password.encode()).hexdigest()
    return salt.hex(), hashed


password = input("Enter a password to check: ")

if check(password) == "Strong":
    salt, hashed_pw = hash_password(password)
    print(f"\nSalt (hex): {salt}")
    print(f"Salted Hash (SHA-256): {hashed_pw}")
else:
 print("Weak Password")
