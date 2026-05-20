import argparse
import errno
import fcntl
import math
import socket
import json
import re

from TGMessage import TGMessage, MsgCheckFailedException
from src.MtprotoSession import MtprotoSession
from src.utils import *



def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", default='127.0.0.1')
    parser.add_argument("-p", "--port", default=65432)
    parser.add_argument("-u", "--username", default="user1")
    parser.add_argument("-s", "--silent" , action='store_true')
    parser.add_argument("-c", "--colored", action='store_true')
    parser.add_argument("-i", "--instant", action='store_true')

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

    user = load_user_data_client()
    auth_key = bytearray.fromhex(user["auth_key"])
    mtprotoSession = MtprotoSession(auth_key)
    int_key = int.from_bytes(auth_key, byteorder='big', signed=False)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
    client_socket.connect((host, port))  # connect to the server
    fcntl.fcntl(client_socket, fcntl.F_SETFL, os.O_NONBLOCK)
    # message = input(" -> ")  # take input
    # print()
    # message = mtproto.encrypt_message(message)
    introductionTgMessage = TGMessage(plaintext_bytes=bytearray("00000000:".encode()), session=mtprotoSession,
                                      msg_type="client_msg", silent=args.silent, colored=args.colored,
                                      instant=args.instant)
    # tg_message_dec = TGMessage(ciphertext_bytes=introductionTgMessage.get_encrypted_data(), msg_type="client_msg",
    #                            session = mtprotoSession,
    #                            silent=get_args().silent,
    #                            colored=get_args().colored,
    #                            instant=get_args().instant)
    client_socket.send(introductionTgMessage.get_encrypted_data())  # send message

    message = ""
    print("enter -> receive messages;")
    print("<32bit-hex-user_id-of-recipiant>:<human-readable-message> -> send message;")
    print("exit: -> exit;")
    while message.lower().strip() != 'exit':

        # if not message.__contains__(":") or message == "":
        #     print("error: invalid format")
        #     continue

        user_id = message.split(":")[0]
        text = message.split(":")[1:]
        regex = '^[a-fA-F0-9]+$'
        # if not (not len(text) % 2 and re.match(regex, text) and re.match(regex, user_id)):
        #     print("error: invalid format")
        #     continue
        if message == "":
            message = "00000000:0"
        tg_message_to_send = TGMessage(plaintext_bytes=bytearray(message.encode()), session=mtprotoSession, msg_type="client_msg", silent=args.silent, colored=args.colored, instant=args.instant)
        client_socket.send(tg_message_to_send.get_encrypted_data())  # send message

        try:
            data = client_socket.recv(4096) # receive response
            print('Received from server, decrypting:')  # show in terminal
            print()
            received_tg_message = TGMessage(ciphertext_bytes=data, msg_type="server_unsolicited", silent=get_args().silent,
                                            colored=get_args().colored,
                                            instant=get_args().instant, session=tg_message_to_send.session)  # we decrypt
            print('Received from server:')
            print(f"sender: {received_tg_message.get_decrypted_data().decode().split(":")[0]}")
            print(f"message: {received_tg_message.get_decrypted_data().decode().split(":")[1:]}")
        except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                print('No data available')
        except MsgCheckFailedException as e:
            print("Impossible to decrypt received message: msg_key check failed.")
        # data = mtproto.decrypt_message(data)

        message = input(" -> ")  # again take input

    client_socket.close()  # close the connection


def prompt_for_user_id():
    username = input("input username: ")
    username.replace(":","")
    return username


def load_user_data_client():
    try:
        with open('user.json', 'r') as file:
            user = json.load(file)
            return user
    except FileNotFoundError:
        with open('users.json', 'w') as file:
            user_id = prompt_for_user_id()
            auth_key = TGMessage.create_auth_key(user_id)




if __name__ == '__main__':
    client_program()