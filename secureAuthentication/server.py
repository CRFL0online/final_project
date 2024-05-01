import socket
import ssl

#define function to initialize socket connection
def server_start():
    HOST = "127.0.0.1"
    port = 443

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
    secure_server = context.wrap_socket(server, server_side=True)

    #secure_server = context.wrap_socket(server, server_side=True)
    while True:
    
        try:
            client_socket.send("Insert Username:".encode("utf-8"))
            username = client_socket.recv(1024).decode("utf-8")
            client_socket.send("Insert Password:".encode("utf-8"))
            password = client_socket.recv(1024).decode("utf-8")
            if (check_credentials(username,password)):
                print("Client connected")
                client_socket.send("Login successful".encode("utf-8"))
                handle_client(client_socket, addr)
                break
            else:
                client_socket.send("Login failure".encode("utf-8"))
                print(f"Client connection at address {addr} closed")
                break

        except Exception as e:
                print(f"Error handling connection from {addr}: {e}")

        break

    client_socket.close()
    secure_server.close()
    print("Server Closed")

    return 0
    
#def function that checks for the user credential (no hash yet)
def check_credentials(username, password):
    with open("credentials.txt", "r") as file:
        for line in file:
            stored_username, stored_password = line.strip().split(',')
            if stored_username == username and stored_password == password:
                return True 
    return False

def handle_client(client_socket, addr):

    while True:
        response = client_socket.recv(1024)
        response = response.decode("utf-8")
        if (response.lower == "close"):
            client_socket.close()
            print(f"Client connection at address {addr} closed")
            return 0
        else:
            print(response)
            data = "Message Received".encode("utf-8")
            client_socket.send(data)

        

if __name__ == '__main__':
    server_start()