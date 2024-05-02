import socket
import threading
import random
import hashlib
import Cryptodome
from Cryptodome.Cipher import AES


HOST = "127.0.0.1"
port = 54321
g= 423
p = 1299827


def start_dh(client_socket):
    client_socket.send(str(p).encode("utf-8"))
    client_socket.send(str(g).encode("utf-8"))

    private_key = random.randrange(p-1)
    public_key = (g ** private_key) % p

    client_socket.send(str(public_key).encode("utf-8"))
    client_key = client_socket.recv(1024).decode("utf-8")
    client_key = int(client_key)

    shared_key = (client_key ** private_key) % p
    client_socket.send(str(shared_key).encode("utf-8"))
    peer_shared_key = client_socket.recv(1024).decode("utf-8")
    peer_shared_key = int(peer_shared_key)

    if (shared_key == peer_shared_key):
        #key = hashlib.sha256(shared_key.to_bytes(32, byteorder = 'big')).hexdigest()
        key = shared_key.to_bytes(32, byteorder='big')
        return (key, True)
    else:
        return (None, False)

# define function to initialize socket connection
def server_loop():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, port))
        print("Socket successfully created")
    except socket.error as err:
        print("socket creation failed with error %s" % err)
        return
    server.listen(5)
    print("Server accepting connections\n")

    while True :
        client_socket, addr = server.accept()
        print(f"Accepted Connection from client address {addr}")
        client_thread = threading.Thread(target=main_client, args=(client_socket, addr))
        client_thread.start()


def main_client(client_socket, addr):
    """
    HOST = "127.0.0.1"
    port = 54321

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_verify_locations('selfsigned.crt')
    context.check_hostname = False

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, port))
        print("Socket successfully created")
    except socket.error as err:
        print("socket creation failed with error %s" % (err))
        return

    server.listen(5)
    client_socket, addr = server.accept()

    print("Server accepting connections\n")
    print(f"Accepted Connection from client address {addr}")
    #secure_server = context.wrap_socket(client_socket, server_side=True)
    """
    key, authenticated = start_dh(client_socket)
    if not authenticated:
        print("Issue authenticating")
        return 0
    print("Client Authenticated")

    while True:
        try:
            client_socket.send("Insert Username:".encode("utf-8"))
            username = client_socket.recv(1024).decode("utf-8")
            client_socket.send("Insert Password:".encode("utf-8"))
            password = client_socket.recv(1024).decode("utf-8")
            """
            client_socket.send("Insert Username:".encode("utf-8"))
            username_cipher= client_socket.recv(1024)
            tag = client_socket.recv(1024)
            nonce = client_socket.recv(1024)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt(username_cipher)
            username = plaintext.decode("utf-8")
            #print(username)
            #password = 'test'
            #print(password)
            
            client_socket.send("Insert Password:".encode("utf-8"))
            password_cipher = client_socket.recv(1024)
            tag = client_socket.recv(1024)
            nonce = client_socket.recv(1024)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt(password_cipher)
            password = plaintext.decode("utf-8")
            """
            if check_credentials(username, password):
                print("Client connected")
                client_socket.send("Login successful".encode("utf-8"))
                handle_client(client_socket, addr)
                break
            else:
                client_socket.send("Login failure".encode("utf-8"))
                register = client_socket.recv(1024).decode("utf-8")
                if register == 'y':
                    new_username = client_socket.recv(1024).decode("utf-8")
                    new_password = client_socket.recv(1024).decode("utf-8")
                    add_user(new_username, new_password)
                else:
                    print(f"Client connection at address {addr} closed")
                    break
        except Exception as e:
            print(f"Error handling connection from {addr}: {e}")
        break

    client_socket.close()
    print("Server Closed")

    return 0


def add_user(username, password):
    file = open("credentials.txt", "a")
    hashes = open("hash_passwords.txt", "a")

    file.write(f"{username},{password}\n")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    hashes.write(f"{username},{hashed_password}\n")

    file.close()
    hashes.close()

    return 0

# def function that checks for the user credential
def check_credentials(username, password):
    with open("hash_passwords.txt", "r") as file:
        for line in file:
            stored_username, stored_password = line.strip().split(',')
            password = hashlib.sha256(password.encode()).hexdigest()
            if stored_username == username and stored_password == password:
                file.close()
                return True
            line=""
        file.close()
    return False


def handle_client(client_socket, addr):

    while True:
        response = client_socket.recv(1024)
        response = response.decode("utf-8")
        if response.lower() == "close":
            #client_socket.close()
            print(f"Client connection at address {addr} closed")
            return 0
        else:
            print(response)
            data = "Message Received".encode("utf-8")
            client_socket.send(data)


if __name__ == '__main__':
    server_loop()
