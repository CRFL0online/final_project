import socket
import random
import ssl
from Cryptodome.Cipher import AES

def start_diffie(client):
    p = client.recv(1024).decode("utf-8")
    g = client.recv(1024).decode("utf-8")
    p = int(p)
    g = int(g)

    private_key = random.randrange(p - 1)
    public_key = (g ** private_key) % p

    server_key = client.recv(1024).decode("utf-8")
    server_key = int(server_key)
    client.send(str(public_key).encode("utf-8"))

    shared_key = (server_key ** private_key) % p
    peer_shared_key = client.recv(1024).decode("utf-8")
    peer_shared_key = int(peer_shared_key)
    client.send(str(shared_key).encode("utf-8"))

    if (shared_key == peer_shared_key):
        key = shared_key.to_bytes(32, byteorder='big')
        return (key, True)
    else:
        return (None, False)

def client_start():

    HOST = "127.0.0.1"
    port = 54321

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, port))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('selfsigned.crt')
    context.check_hostname = False
    client = context.wrap_socket(client, server_hostname=HOST)

    try:
        #secure_client = context.wrap_socket(client, server_hostname=HOST)
        #client_socket = socket.create_connection((HOST, port))
        #secure_client = context.wrap_socket(client_socket, server_hostname=HOST)
        print("Socket successfully created")
    except socket.error as err:
        print("socket creation failed with error %s" % (err))

    key, authenticated = start_diffie(client)
    if not authenticated:
        print("Issue Authenticating")
        return 0
    print("Authenticated")

    flag = False
    while True:
        if flag:
            break
        #Three states
        #1. Login state/2 successful login(user can use the server)/3 login failure (user is kicked out from the server)
        prompt = client.recv(1024).decode("utf-8")
        if (prompt == "Insert Username:"):
            """
            print(prompt)
            data = input()
            client.send(data.encode("utf-8"))
            prompt = client.recv(1024).decode("utf-8")
            print(prompt)  
            data = input()
            client.send(data.encode("utf-8"))
            prompt = client.recv(1024).decode("utf-8")

            """
            print(prompt)
            data = input()
            data = data.encode("utf-8")
            cipher = AES.new(key, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(data)
            client.send(ciphertext)
            client.send(tag)
            client.send(nonce)

            prompt = client.recv(1024).decode("utf-8")
            print(prompt)
            data = input()
            data = data.encode("utf-8")
            cipher = AES.new(key, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(data)
            client.send(ciphertext)
            client.send(tag)
            client.send(nonce)
        if (prompt == "exists"):
            print("Client is already connected")
        if (prompt == "Login successful"):
            while True:
                data = input("Enter message  -  ('Close' to close connection):  ")
                client.send(data.encode("utf-8"))
                if (data.lower() == "close"):
                    flag = True
                    break
                response = client.recv(1024)
                response = response.decode("utf-8")
                if response == "Timed out":
                    print("Session expiration, connection closed")
                    flag = True
                    break
                print(response)
        elif (prompt == "Login failure"):
            print("Login Failure")
            print("Would you like to register? (y/n):  ")
            response = input().lower()
            client.send(response.encode("utf-8"))
            if response == 'y':
                print("Insert Username: ")
                data = input()
                client.send(data.encode("utf-8"))
                print("Insert Password: ")
                data = input()
                client.send(data.encode("utf-8"))
                print("User Registered")
            else:
                break
    # close client socket (connection to the server)
    client.close()
    print("Connection to server closed")
    return 0

if __name__ == '__main__':
    client_start()