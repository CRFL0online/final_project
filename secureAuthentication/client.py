import socket
import ssl

def client_start():

    HOST = "127.0.0.1"
    port = 54321

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    #context = ssl.create_default_context()
    context.load_verify_locations('selfsigned.crt')
    context.check_hostname = False
    print(ssl.OPENSSL_VERSION)

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, port))
        secure_client = context.wrap_socket(client, server_hostname=HOST)
        #client_socket = socket.create_connection((HOST, port))
        #secure_client = context.wrap_socket(client_socket, server_hostname=HOST)
        print("Socket successfully created")
    except socket.error as err:
        print("socket creation failed with error %s" % (err))

    while True:
        #Three states
        #1. Login state/2 successful login(user can use the server)/3 login failure (user is kicked out from the server)
        prompt = secure_client.recv(1024).decode("utf-8")
        if(prompt == "Insert Username:"):
            print(prompt)             
            data = input()
            secure_client.send(data.encode("utf-8"))
            prompt = secure_client.recv(1024).decode("utf-8")
            print(prompt)  
            data = input()
            secure_client.send(data.encode("utf-8"))
            prompt = secure_client.recv(1024).decode("utf-8")

        if (prompt == "Login successful"):
            while True:
                data = input("Enter message  -  ('Close' to close connection):  ")
                secure_client.send(data.encode("utf-8"))
                if (data.lower() == "close"):
                    break
                response = secure_client.recv(1024)
                response = response.decode("utf-8")
                print(response)
        elif (prompt == "Login failure"):
            print("Login Failure")
            break
        break
    # close client socket (connection to the server)
    secure_client.close()
    print("Connection to server closed")
    return 0

if __name__ == '__main__':
    client_start()