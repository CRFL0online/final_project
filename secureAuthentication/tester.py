import Cryptodome
from Cryptodome.Cipher import AES

data = "hello my good sir"
data = data.encode("utf-8")
key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_EAX)

nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data)

print(ciphertext)

cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)

plaintext = plaintext.decode("utf-8")
print(plaintext)

