import socket


def client_start():

    HOST = "127.0.0.1"
    port = 54321

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, port))
        print("Socket successfully created")
    except socket.error as err:
        print("socket creation failed with error %s" % (err))

    while True:
        #Three states
        #1. Login state/2 successful login(user can use the server)/3 login failure (user is kicked out from the server)
        prompt = client.recv(1024).decode("utf-8")
        if(prompt == "Insert Username:"):
            print(prompt)             
            data = input()
            client.send(data.encode("utf-8"))
            prompt = client.recv(1024).decode("utf-8")
            print(prompt)  
            data = input()
            client.send(data.encode("utf-8"))
            prompt = client.recv(1024).decode("utf-8")
        if(prompt == "Login successful"):    
            while True:
                data = input("Enter message  -  ('Close' to close connection):  ")
                client.send(data.encode("utf-8"))
                if (data.lower() == "close"):
                    client.close()
                    print("Connection to server closed")
        if(prompt == "Login failure"):  
            client.close()
        
        else:
            response = client.recv(1024)
            response = response.decode("utf-8")
            print(response)


    # close client socket (connection to the server)
    

    return 0

if __name__ == '__main__':
    client_start()