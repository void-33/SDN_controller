import socket
import _thread
from handlers import handle_switch_connection, start_lldp_sender

if __name__ == "__main__":
    # localhost
    HOST = "127.0.0.1"
    # default port in mininet for controller to listen to
    PORT = 6653

    # create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Add this line BEFORE bind
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_details = (HOST, PORT)

    print(f"Starting server on port:{PORT}")

    # bind the socket to the defined port
    server_socket.bind(server_details)

    # listen for incoming connections
    server_socket.listen()

    print(f"Controller listening on {HOST}:{PORT}")

    # Start background LLDP probe thread
    start_lldp_sender()

    while True:
        connection, client = server_socket.accept()
        # #new instance for new thread
        _thread.start_new_thread(handle_switch_connection, (connection, client))
