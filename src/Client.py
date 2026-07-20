import argparse
import errno
import fcntl
import math
import socket
import json
import re
import time

import utils
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

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
    while(True):
        try:
            client_socket.connect((host, port))  # connect to the server
            break
        except ConnectionRefusedError:
            print("Connection refused, trying again . . .")
            time.sleep(2)
    fcntl.fcntl(client_socket, fcntl.F_SETFL, os.O_NONBLOCK)
    user = load_user_data_client(client_socket=client_socket, args=args)
    auth_key = bytearray.fromhex(user["auth_key"])
    mtproto_session = MtprotoSession(auth_key)
    int_key = int.from_bytes(auth_key, byteorder='big', signed=False)


    # message = input(" -> ")  # take input
    # print()
    # message = mtproto.encrypt_message(message)


    # introductionTgMessage = TGMessage(plaintext_bytes=bytearray("00000000:".encode()), session=mtprotoSession,
    #                                   msg_type="client_msg", silent=args.silent, colored=args.colored,
    #                                   instant=args.instant)
    # # tg_message_dec = TGMessage(ciphertext_bytes=introductionTgMessage.get_encrypted_data(), msg_type="client_msg",
    # #                            session = mtprotoSession,
    # #                            silent=get_args().silent,
    # #                            colored=get_args().colored,
    # #                            instant=get_args().instant)
    # client_socket.send(introductionTgMessage.get_encrypted_data())  # send message

    message = ""
    print("enter -> receive messages;")
    print("<user_id of recipient>:<message> -> send message;")
    print("exit: -> exit;")
    mtproto_session.n_content_related = 0
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
            contentRelated = False
        else:
            contentRelated = True
        tg_message_to_send = TGMessage(plaintext_bytes=bytearray(message.encode()), session=mtproto_session, msg_type="client_msg", contentRelated=contentRelated, silent=args.silent, colored=args.colored, instant=args.instant)


        # if message is not "" and message is not "00000000:0":

        client_socket.send(tg_message_to_send.get_encrypted_data())  # send message
        time.sleep(3)
        try:
            data = client_socket.recv(4096) # receive response
            print('Received from server, decrypting:')  # show in terminal
            print()
            received_tg_message = TGMessage(ciphertext_bytes=bytearray(data), msg_type="server_unsolicited", silent=get_args().silent,
                                            colored=get_args().colored,
                                            instant=get_args().instant, session=tg_message_to_send.session)  # we decrypt
            print('Received from server:')
            print(f"sender: {received_tg_message.get_decrypted_data().decode().split(":")[0]}")
            print(f"message: {received_tg_message.get_decrypted_data().decode().split(":")[1:]}")
        except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN:
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

def reset_user_file(client_socket, args):
    with open('user.json', 'w') as file:
        user_id = prompt_for_user_id()
        auth_key = exchange_DH_client(user_id, client_socket, args)
        user = {
            "auth_key": auth_key,
            "user_id": user_id,
        }
        json.dump(user,file)



def load_user_data_client(client_socket, args):
    while True:
        try:
            with open('user.json', 'r') as file:
                user = json.load(file)
                if user["user_id"] is None or user["auth_key"] is None:
                    raise Exception
                # user["auth_key"] = bytearray.fromhex(user["auth_key"])
                return user
        except Exception as e:
            print("Log in:")
            reset_user_file(client_socket, args)


def exchange_DH_client(user_id,client_socket, args):
    client_socket.setblocking(True)

    null_auth_key_id = MtprotoSession.NULL_AUTH_KEY_ID
    session: MtprotoSession = MtprotoSession(null_auth_key_id)
    # we skip steps 1 to 4 from the official documentation and go straight to DH exchange
    # in the actual client, the auth key exchange is done before login/registration, here we don't implement those, and so we just send the user_id at the start of the DH exchange
    request_DH_params_code = bytes.fromhex(MtprotoSession.REQ_DH_PARAMS_CODE) + bytearray(user_id.encode())

    tg_message_rqeuest_DH = TGMessage(plaintext_bytes=bytearray(request_DH_params_code), session=session,
                                   msg_type="client_msg", silent=args.silent, colored=args.colored,
                                   instant=args.instant)
    if not args.silent:
        print("sending DH key exchange request to server . . .")
        wait_input(args.instant)

    client_socket.send(tg_message_rqeuest_DH.get_encrypted_data())

    data = client_socket.recv(4096)
    tg_message_p_g_A = TGMessage(ciphertext_bytes=data, msg_type="server_response_msg", silent=get_args().silent,
                           colored=get_args().colored,
                           instant=get_args().instant)
    p_g_A = tg_message_p_g_A.get_decrypted_data()
    p = bytes_to_int(p_g_A[:256])
    g = p_g_A[256]
    A = bytes_to_int(p_g_A[257:513])
    b = random.randrange(1<<2047, 1<<2048)
    B = pow(g, b, p)

    auth_key_int = pow(A, b, p)
    auth_key = to_bytes(auth_key_int, 256)

    if not args.silent:
        print("Received DH parameters from server:")
        wait_input(args.instant)
        print("p (2048 bit safe prime)")
        print(p)
        print()
        wait_input(args.instant)
        print("g (can be 2, 3, 4, 5, 6 or 7)")
        print(g)
        print()

        wait_input(args.instant)
        print("A (Public key of Server)")
        print(A)
        print()

        wait_input(args.instant)
        print("Generating Client private key b and public key B . . .")
        print()

        wait_input(args.instant)
        print("b (random 2048 bit number bigger than 2^2048 - 1)")
        print(b)
        print()

        wait_input(args.instant)
        print("B (computed as g^b % p)")
        print(B)
        print()

        wait_input(args.instant)
        print("auth_key (computed as A^b % p)")
        print(to_hex_str(auth_key))
        print()

        wait_input(args.instant)
        print("sending public key B to server . . .")
    resposne_B = to_bytes(B, 256)

    tg_message_resosne_B = TGMessage(plaintext_bytes=bytearray(resposne_B), session=session,
                                      msg_type="client_msg", silent=args.silent, colored=args.colored,
                                      instant=args.instant)
    client_socket.send(tg_message_resosne_B.get_encrypted_data())



    client_socket.setblocking(False)
    if not  args.silent:
        print("DH key exchange completed")
    return to_hex_str(auth_key, False)


if __name__ == '__main__':
    client_program()