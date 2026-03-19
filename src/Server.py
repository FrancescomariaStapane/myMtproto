import socket
import argparse
from src.utils import *

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--silent", default=socket.gethostname())
    args = parser.parse_args()
    return args

def c_print(string, silent):
    if not silent:
        print(string)
def server_program():
    silent = get_args().silent

    # get the hostname
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together
    print("bound to: " + host + ":",port)
    # configure how many client the server can listen simultaneously
    server_socket.listen(5)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024).decode()
        if not data:
            # if data is not received break
            break
        print("from connected user: " + str(data))
        data = input(' -> ')
        conn.send(data.encode())  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()