# -------------------------------------------------
# Final Project: Option 3 - Client Program for client authentication
#
# Authors: Christopher Rodriguez, Matheus Pereira
#
# NOTE: If there are issues with Cryptodome or AES, the import statement can be commented out
# ADDITIONALLY: Lines at 79-86 should be uncommented; lines at 90-111 should be commented out
# -------------------------------------------------
import socket
import random
import ssl
from Cryptodome.Cipher import AES

# Function to create a shared key using Diffie-Hellman
def start_diffie(client):
    # The global values for the DH algorithm are received from the server
    p = client.recv(1024).decode("utf-8")
    g = client.recv(1024).decode("utf-8")
    p = int(p)
    g = int(g)

    # Randomly generate the client private key
    private_key = random.randrange(p - 1)
    public_key = (g ** private_key) % p

    server_key = client.recv(1024).decode("utf-8")
    server_key = int(server_key)
    client.send(str(public_key).encode("utf-8"))

    # Calculate the shared key using the server public key
    shared_key = (server_key ** private_key) % p
    peer_shared_key = client.recv(1024).decode("utf-8")
    peer_shared_key = int(peer_shared_key)
    client.send(str(shared_key).encode("utf-8"))

    if (shared_key == peer_shared_key):
        # Shared key stored as a 32 byte string
        key = shared_key.to_bytes(32, byteorder='big')
        return (key, True)
    else:
        return (None, False)

def client_start():

    # HOST and port values for socket connections
    HOST = "127.0.0.1"
    port = 54321

    # First create and connect to an unsecure socket
    # Create the context and wrap the socket in an SSL connection
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, port))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations('selfsigned.crt')
        context.check_hostname = False
        client = context.wrap_socket(client, server_hostname=HOST)
        print("Socket successfully created")
    except socket.error as err:
        print("socket creation failed with error %s" % (err))

    # Function call to create the shared key
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
            # NOTE: The next eight lines can be uncommented if no AES encryption is used during initial transmission
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
            # Receive prompt to insert username
            # Username is encrypted using AES and the shared key and is sent to the server over SSL
            print(prompt)
            data = input()
            data = data.encode("utf-8")
            cipher = AES.new(key, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(data)
            client.send(ciphertext)
            client.send(tag)
            client.send(nonce)

            # Receive prompt to insert password; user inputs password
            # Password is encrypted using AES and the shared key and is sent to the server over SSL
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
        # Client may receive response that account is already logged in; another pair of credentials will be entered
        if (prompt == "exists"):
            print("Client is already connected")
        # Server authorized the credentials
        if (prompt == "Login successful"):
            while True:
                # Client is prompted to enter messages
                # If the message is 'close' then the socket connection is closed
                data = input("Enter message  -  ('Close' to close connection):  ")
                client.send(data.encode("utf-8"))
                if (data.lower() == "close"):
                    flag = True
                    break
                response = client.recv(1024)
                response = response.decode("utf-8")
                # Client may receive a session expiration message after sending a message
                # Socket connection is closed if the session expires
                if response == "Timed out":
                    print("Session expiration, connection closed")
                    flag = True
                    break
                print(response)
        # Credentials were rejected; user can register or close the connection
        elif (prompt == "Login failure"):
            print("Login Failure")
            print("Would you like to register? (y/n):  ")
            response = input().lower()
            client.send(response.encode("utf-8"))
            # User decides to register; provides the new credentials
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

# Function to call the main function for client communication
if __name__ == '__main__':
    client_start()