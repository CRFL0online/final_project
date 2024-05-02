from faker import Faker
import secrets as secret
import hashlib
faker = Faker()
file = open("credentials.txt", 'a')
hashes = open("hash_passwords.txt",'a')

for a in range(10):
    username = faker.name()
    username = (username.replace(" ","")).lower()
    password = secret.token_urlsafe(16)
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    file.write(f"{username},{password}\n")
    hashes.write(f"{username},{hashed_password}\n")

file.close()
hashes.close()
