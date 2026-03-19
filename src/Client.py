import argparse
import math
import socket
import json
from src.utils import *



def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", default=socket.gethostname())
    parser.add_argument("-p", "--port", default=5000)
    parser.add_argument("-u", "--username", default="user1")
    parser.add_argument("-s", "--silent", default=socket.gethostname())

    args = parser.parse_args()
    return args


def c_print(string, silent):
    if not silent:
        print(string)


def client_program():
    args = get_args()
    host = args.host
    port = args.port
    silent = args.silent
    username = args.username
    user = load_user_data(username)
    auth_key = bytearray.fromhex(user["auth_key"])
    mtproto = MyMTProto2_session(auth_key)
    int_key = int.from_bytes(auth_key, byteorder='big', signed=False)
    print(int_key)
    print(math.log2(int_key))
    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    message = input(" -> ")  # take input

    message = mtproto.encrypt_message(message)

    while message.lower().strip() != 'bye':
        client_socket.send(message.encode())  # send message
        data = client_socket.recv(1024).decode()  # receive response
        data = mtproto.decrypt_message(data)
        print('Received from server: ' + data)  # show in terminal

        message = input(" -> ")  # again take input

    client_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()