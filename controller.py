import socket
import _thread
import struct

switches = {}  #store per-switch state

def handle_switch(connection, address):
    print(f"New connection from {address}")

    #receive data from switch
    while True:
        try:
            data = connection.recv(1024)
            if not data:
                print(f"Switch {address} disconnected")
                break

            print(f"Received {len(data)} bytes from {address}:{data.hex()}")

            #todo: parse openflow message

        except Exception as e:
            print(f"Error with {address}:{e}")
            break
    
    connection.close()



if __name__ == '__main__':
    #localhost
    HOST = '127.0.0.1'
    #default port in mininet for controller to listen to
    PORT = 6653

    #create a TCP socket
    server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    server_details = (HOST,PORT)

    print(f"Starting server on port:{PORT}")

    #bind the socket to the defined port
    server_socket.bind(server_details)

    #listen for incoming connections
    server_socket.listen()

    print(f"Controller listening on {HOST}:{PORT}")

    while True:
        connection, client = server_socket.accept()
        # #new instance for new thread
        _thread.start_new_thread(handle_switch,(connection,client))

