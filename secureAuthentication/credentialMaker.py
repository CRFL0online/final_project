from faker import Faker
import secrets as secret

faker = Faker()
file = open("credentials.txt", 'a')

for a in range(10):
    u_name = faker.name()
    u_name = (u_name.replace(" ","")).lower()
    password = secret.token_urlsafe(15)
    file.write(u_name + "," + password + "\n")

file.close()
