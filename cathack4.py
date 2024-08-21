import hashlib
import pyotp
import getpass

# In-memory user database
users_db = {}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_user():
    print("\n--- User Registration ---")
    username = input("Enter a username: ")
    
    if username in users_db:
        print("Username already exists. Please choose a different username.")
        return

    password = getpass.getpass("Enter a password: ")
    confirm_password = getpass.getpass("Confirm your password: ")
    
    if password != confirm_password:
        print("Passwords do not match. Registration failed.")
        return
    
    print("Choose a graphical password (e.g., a sequence of numbers like 1234)")
    graphical_pass = input("Enter graphical password sequence: ")

    otp_secret = pyotp.random_base32()  # Generate a random base32 secret for OTP
    users_db[username] = {
        'password': hash_password(password),
        'graphical_pass': graphical_pass,
        'otp_secret': otp_secret
    }
    print(f"User '{username}' registered successfully!")

def verify_textual_password(username, password):
    if username in users_db:
        return users_db[username]['password'] == hash_password(password)
    return False

def verify_graphical_password(username, input_sequence):
    if username in users_db:
        return users_db[username]['graphical_pass'] == input_sequence
    return False

def generate_otp(username):
    otp_secret = users_db[username]['otp_secret']
    totp = pyotp.TOTP(otp_secret)
    return totp.now()

def verify_otp(username, otp):
    otp_secret = users_db[username]['otp_secret']
    totp = pyotp.TOTP(otp_secret)
    return totp.verify(otp)

def login_user():
    print("\n--- User Login ---")
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    
    if verify_textual_password(username, password):
        print("Textual password verified!")
        
        # Level 2: Graphical Password
        graphical_pass = input("Enter your graphical password sequence (e.g., 123): ")
        
        if verify_graphical_password(username, graphical_pass):
            print("Graphical password verified!")
            
            # Level 3: OTP
            otp = generate_otp(username)
            print(f"Your OTP is: {otp}")  # In real applications, send this via email/SMS
            
            user_otp = input("Enter the OTP: ")
            if verify_otp(username, user_otp):
                print("Authentication successful!")
            else:
                print("Invalid OTP.")
        else:
            print("Invalid graphical password.")
    else:
        print("Invalid username or password.")

def main():
    while True:
        print("\n--- Main Menu ---")
        print("1. Register a new user")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            create_user()
        elif choice == '2':
            login_user()
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid option. Please choose again.")

if __name__ == '__main__':
    main()

