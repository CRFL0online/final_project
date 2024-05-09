from faker import Faker
import secrets as secret
import hashlib
faker = Faker()
# Open credential txt files to add new accounts
file = open("credentials.txt", 'a')
hashes = open("hash_passwords.txt",'a')

# Create ten new user accounts
for a in range(10):
    # Create a random username
    username = faker.name()
    username = (username.replace(" ","")).lower()
    # Create a secure and random password, length 16
    password = secret.token_urlsafe(16)
    # Hash password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    # Store the credentials in the respective txt files
    file.write(f"{username},{password}\n")
    hashes.write(f"{username},{hashed_password}\n")

file.close()
hashes.close()
