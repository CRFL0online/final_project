# -------------------------------------------------
# Final Project: Option 3 - Server Program for client authentication
#
# Authors: Christopher Rodriguez, Matheus Pereira
#
# NOTE: If there are issues with Cryptodome or AES, the import statement can be commented out
# ADDITIONALLY: Lines at 92-95 should be uncommented; lines at 100-115 should be commented out
# -------------------------------------------------
import socket
import threading
import random
import hashlib
import ssl
import time
from Cryptodome.Cipher import AES

# HOST and port values for socket connections
HOST = "127.0.0.1"
port = 54321

# Values used for the DH Algorithm
g= 423
p = 1299827

# Stores a list of the currently connected clients
connected_clients = []

# Function to create a shared key using Diffie-Hellman
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
        # Final shared key in a 32 byte string
        key = shared_key.to_bytes(32, byteorder='big')
        return (key, True)
    else:
        return (None, False)


# define function to initialize socket connection threads
def server_loop():
    # define the context using the self-signed certificates
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='selfsigned.crt', keyfile='private.key')

    # creation of an unsecure socket connection
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, port))
        print("Socket successfully created")
    except socket.error as err:
        print("socket creation failed with error %s" % err)
        return
    server.listen(5)
    print("Server accepting connections\n")

    # The created sockets are wrapped under SSL and launch a new client thread
    while True :
        client_socket, addr = server.accept()
        print(f"Accepted Connection from client address {addr}")
        secure_socket = context.wrap_socket(client_socket, server_side=True)
        client_thread = threading.Thread(target=main_client, args=(secure_socket, addr))
        client_thread.start()


def main_client(client_socket, addr):

    # Functional call to create a shared key with the connected client
    key, authenticated = start_dh(client_socket)
    if not authenticated:
        print("Issue authenticating")
        return 0
    print(f"Client at address {addr} Authenticated")

    while True:
        try:
            # NOTE: The next four lines can be uncommented if no AES encryption is used during initial transmission
            """
            client_socket.send("Insert Username:".encode("utf-8"))
            username = client_socket.recv(1024).decode("utf-8")
            client_socket.send("Insert Password:".encode("utf-8"))
            password = client_socket.recv(1024).decode("utf-8")
            """

            # NOTE: These two code blocks can be commented out if no AES encryption is used for initial transmission
            # Encrypted Username is received and unencrypted using AES and the shared key
            client_socket.send("Insert Username:".encode("utf-8"))
            username_cipher= client_socket.recv(1024)
            tag = client_socket.recv(1024)
            nonce = client_socket.recv(1024)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt(username_cipher)
            username = plaintext.decode("utf-8")

            # Encrypted Password is received and unencrypted using AES and the shared key
            client_socket.send("Insert Password:".encode("utf-8"))
            password_cipher = client_socket.recv(1024)
            tag = client_socket.recv(1024)
            nonce = client_socket.recv(1024)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt(password_cipher)
            password = plaintext.decode("utf-8")

            # Function to authorize the user
            # Check if it already connected or if the credentials are true
            state = check_credentials(username, password)

            # Client is already connected; prompts for new credentials
            if state == "exists":
                client_socket.send("exists".encode("utf-8"))

            # The credentials are true and the client can continue communicating
            elif state == True:
                print("Client connected")
                client_socket.send("Login successful".encode("utf-8"))
                # Start the communication with the client
                handle_client(client_socket, addr)
                # The client closed the connection; the account is removed from the currently connected clients list
                connected_clients.remove(username)
                break
            # The credentials are false; the client can register or close the connection
            else:
                client_socket.send("Login failure".encode("utf-8"))
                register = client_socket.recv(1024).decode("utf-8")
                # Client wishes to register; server receives new username and password
                if register == 'y':
                    new_username = client_socket.recv(1024).decode("utf-8")
                    new_password = client_socket.recv(1024).decode("utf-8")
                    # Function to register the new user
                    add_user(new_username, new_password)
                    print(f"Client at address {addr} registered")
                else:
                    print(f"Client connection at address {addr} closed")
                    break
        except Exception as e:
            print(f"Error handling connection from {addr}: {e}")

    # The current client connection is closed but server remains open for more connections
    client_socket.close()
    print("... Waiting for more connections ... ")
    return 0

# Function to store the credentials of the user who wishes to register
def add_user(username, password):
    # Open both text files that store credentials to append the new credentials
    file = open("credentials.txt", "a")
    hashes = open("hash_passwords.txt", "a")

    # Add unencrypted credentials to the text file
    file.write(f"{username},{password}\n")
    # Hash the passwords and add it to the hashed text file
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    hashes.write(f"{username},{hashed_password}\n")

    file.close()
    hashes.close()

    return 0


# def function that checks for the user credential
def check_credentials(username, password):
    # Check if the user is already connected to the server
    if username in connected_clients:
        return "exists"
    with open("hash_passwords.txt", "r") as file:
        for line in file:
            stored_username, stored_password = line.strip().split(',')
            sample = hashlib.sha256(password.encode()).hexdigest()
            # Check if the credential pair is stored in the hashed passwords file
            if stored_username == username and stored_password == sample:
                connected_clients.append(username)
                file.close()
                return True
    return False


# Function to allow continuous communication with the client
def handle_client(client_socket, addr):
    # Start time used to see how long the current client has been connected
    start_time = time.time()
    while True:
        # Get the current time everytime the server receives a client message
        current_time = time.time()
        response = client_socket.recv(1024)
        response = response.decode("utf-8")
        # Close means the client sent the message to end the socket connection
        if response.lower() == "close":
            print(f"Client connection at address {addr} closed")
            return 0
        # If the client is connected for more than 5 minutes, the connection is closed
        # This can be reduced to smaller values for testing purposes
        if (current_time - start_time) > 60*5:
            data = "Timed out".encode("utf-8")
            # Notify the client of the connection expiration
            client_socket.send(data)
            print(f"Client connection at address {addr} expired")
            return 0
        # Receive and print the client message on server terminal
        else:
            print(f"Client at address {addr} message:", response)
            data = "Message Received".encode("utf-8")
            client_socket.send(data)


# Start the function to create client threads
if __name__ == '__main__':
    server_loop()
