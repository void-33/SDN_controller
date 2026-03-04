import socket
import _thread
import struct

#constants from the openflow specs
OF_VERSION_1_3 = 0x04
OFPT_HELLO = 0
OFPT_ERROR = 1
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_EXPERIMENTER = 4
OFPT_FEATURES_REQUEST = 5

# OpenFlow 1.3 Header Format: !BBHI
# ! = Network Byte Order (Big-Endian)
# B = uint8_t (1 byte)  -> version
# B = uint8_t (1 byte)  -> type
# H = uint16_t (2 bytes) -> length
# I = uint32_t (4 bytes) -> xid


switches = {}  #store per-switch state

def safe_recv(connection, size):
    # ensures we receive exactly "size" bytes
    blocks = []
    recieved = 0

    #this is done because sometimes not all 8 bytes may have arrived at the socket buffer
    while recieved < size:
        block = connection.recv(size-recieved)
        if not block:
            #connection closed by the switch
            return None
        blocks.append(block)
        recieved += len(block)

    #join blocks with b'' which is an empty byte string
    return b''.join(blocks)

def handle_switch(connection, address):
    print(f"New connection from {address}")

    #receive data from switch
    while True:
        try:
            header_raw = safe_recv(connection,8)
            if not header_raw:
                break

            print(f"Received {len(header_raw)} bytes from {address}:{header_raw.hex()}")

            #todo: parse openflow message
            version, msg_type , msg_len, xid = struct.unpack('!BBHI', header_raw)

            print(f"Header: Ver {version}, Type {msg_type}, TotalLen {msg_len}, xid {xid}")


            #read the rest of the message
            body_data = b''
            
            if msg_len > 8:
            #     # read remaining bytes after header
                body_data = safe_recv(connection, msg_len-8)

            #process further based on the TYPE in header
            if msg_type == OFPT_HELLO:
                print("Received HELLO")
                #send hello back
                connection.sendall(struct.pack('!BBHI',OF_VERSION_1_3,OFPT_HELLO,8, xid))

                #immediately ask for Features
                connection.sendall(struct.pack('!BBHI', OF_VERSION_1_3, OFPT_FEATURES_REQUEST, 8, xid+1))
                print('Feature Request Sent')


        except Exception as e:
            print(f"Error with {address}:{e}")
            break
    
    connection.close()
    print(f"Switch {address} disconnected")



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

