import argparse
import hashlib
import json
import math
import requests
from Crypto.Util import number
from requests import session

from Client import exchange_DH_client
from MtprotoSession import MtprotoSession
from TGMessage import TGMessage, MsgCheckFailedException
from src.utils import *
import socket
import threading
from Crypto.Random import random

HOST = '127.0.0.1'  # Server IP (localhost)
PORT = 65432        # Port for client connections
messages ={}

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--silent", action='store_true')
    parser.add_argument("-c", "--colored", action='store_true')
    parser.add_argument("-i", "--instant", action='store_true')

    args = parser.parse_args()
    return args

def c_print(string, silent):
    if not silent:
        print(string)

def send_messages_in_inbox(session: MtprotoSession, conn, n_content_related):
    auth_key_id = to_hex_str(session.auth_key_id, spaces=False)
    # we create an emppty list of messages (inbox) for the connected user' auth_key_id if he doesnt have one
    if auth_key_id not in messages.keys():
        messages[auth_key_id] = []

    # we send all pending messages in client's inbox
    for message in messages[auth_key_id]:  # in this demo, messages are stored in plaintext and re-encrypted when sending, then deleted
        tg_message = TGMessage(plaintext_bytes=bytearray(message), session=session,
                               msg_type="server_unsolicited", silent=get_args().silent,
                               colored=get_args().colored,
                               instant=get_args().instant)  # message is re-encrypted with recipient auth_key before sending
        tg_message.session.n_content_related = n_content_related
        n_content_related+=1
        conn.send(tg_message.get_encrypted_data())
        messages[auth_key_id] = []
    return n_content_related

def get_safe_prime_and_g():
    url = "https://2ton.com.au/getprimes/random/2048"
    data = json.loads(requests.get(url).content.decode())
    p = int((data["p"]["base10"]))
    g = int(data["g"]["base10"])
    return p, g

def exchange_DH_server(conn, tg_message_req_DH):
    print("Received DH exchange request")
    p, g = get_safe_prime_and_g()
    a =  random.randrange(1<<2047, 1<<2048) # random integer of exactly 2048 bit
    A = pow(g, a, p) # g^a % p
    # message p + g + A
    args = get_args()
    p_g_A = bytearray(to_bytes(p,256) + to_bytes(g,1) + to_bytes(A, 256))
    if not args.silent:
        print("Received DH parameters request from client. Generating p, g, private key a and public key A")
        wait_input(args.instant)
        print("p (2048 bit safe prime, meaning (p-1)/2 is also prime and 2^2047 < p < 2^2048)")
        print(p)
        print()
        wait_input(args.instant)
        print("g (can be 2, 3, 4, 5, 6 or 7)")
        print(g)
        print()

        wait_input(args.instant)
        print("a (random 2048 bit number bigger than 2^2047)")
        print(a)
        print()

        wait_input(args.instant)
        print("A (computed as g^a % p)")
        print(A)
        print()
        wait_input(args.instant)
        print("Sending all to client . . .")

    tg_message_p_g_A = TGMessage(plaintext_bytes=p_g_A, msg_type="server_response_msg", silent=args.silent, session = tg_message_req_DH.session,
                           colored=args.colored,
                           instant=args.instant)
    conn.send(tg_message_p_g_A.get_encrypted_data())
    response_B = conn.recv(2048)
    tg_message_resposne_B = TGMessage(ciphertext_bytes=bytearray(response_B), session=tg_message_req_DH.session,
                                     msg_type="client_msg", silent=args.silent, colored=args.colored,
                                     instant=args.instant)
    B = bytes_to_int(tg_message_resposne_B.get_decrypted_data())
    auth_key_int = pow(B, a, p)

    # print("A: ")
    # print(A)
    # print("B")
    # print(B)

    if not args.silent:
        print("B (client's public key, just received)")
        print(B)
        wait_input(args.instant)
        print("auth_key (computed as A^b % p)")
        print(to_hex_str(to_bytes(auth_key_int, 256)))
        print("DH key exchange completed")

    auth_key = to_hex_str(to_bytes(auth_key_int, 256), spaces = False)
    return auth_key

def handle_client(conn, addr):

    print(f"Connection established with {addr}.")
    n_content_related = 0
    while True: # until client disconnects
        try:

            data = conn.recv(4096)
            if not data or len(data) == 0:
                continue
            try:
                tg_message = TGMessage(
                    ciphertext_bytes= data, msg_type="client_msg", silent=get_args().silent, colored=get_args().colored,
                                       instant=get_args().instant) # we decrypt
            except MsgCheckFailedException as e: # an exception is thrown when msg_key check on decryption fails
                continue
            # for the first message in the session, the session object is built based on the data in the message
            # if session is None:
            #     session: MtprotoSession = tg_message.session
            # auth_key_id = to_hex_str(session.auth_key_id, spaces=False)


            # after all pending messages are sent, inbox is cleared
            decrypted_data = tg_message.get_decrypted_data()
            if bytearray(tg_message.session.auth_key_id) == bytearray(MtprotoSession.NULL_AUTH_KEY_ID):
                if bytearray(tg_message.message_data_plaintext[:4]) == bytearray(bytes.fromhex(MtprotoSession.REQ_DH_PARAMS_CODE)):
                    auth_key = exchange_DH_server(conn, tg_message)
                    auth_key_id = to_hex_str(get_auth_key_id(bytearray(bytes.fromhex(auth_key))), False)
                    user_id = (str(tg_message.message_data_plaintext[4:].decode()))
                    users = {}
                    users_reverse = {}
                    with open("users.json", "r") as file:
                        users = json.load(file)
                    with open("users.json", "w") as file:
                        users[auth_key_id] = {
                            "auth_key": auth_key,
                            "user_id": user_id
                        }
                        json.dump(users, file)
                    with open("users_reverse.json", "r") as file:
                        users_reverse : dict[str, dict[str, list[str]]] = json.load(file)
                    with open("users_reverse.json", "w") as file:
                        if user_id not in users_reverse.keys():
                            users_reverse[user_id] = {"auth_keys" : []}
                        users_reverse[user_id]["auth_keys"].append(auth_key)
                        json.dump(users_reverse, file)


            else:
                recipient_id = decrypted_data.decode().split(":")[0]
                payload = decrypted_data.decode().split(":")[1]
                if recipient_id != "00000000" : # dummy value for recipient, I use it on the first message that starts the session or to receive messages, in reality it's done in a different way
                    print("received data: ")
                    print(decrypted_data.decode())
                    stored_message = (load_user_data_server(auth_key_id=tg_message.session.auth_key_id)["user_id"]).encode() + b":" + payload.encode()
                    recipient_auth_key_ids = (get_auth_key_id(bytearray(bytes.fromhex(auth_key))) for auth_key in get_auth_keys(recipient_id))
                    for recipient_auth_key_id in recipient_auth_key_ids: # for each auth_key (one per logged device) associated with the recipients' account we store the message
                        str_auth_key_id = to_hex_str(recipient_auth_key_id, spaces=False)
                        if str_auth_key_id not in messages.keys():
                            messages[str_auth_key_id] = []
                        messages[str_auth_key_id].append(stored_message) # messages are stored in plaintext
                else:
                    print("received blank message")
                assert  tg_message.session is not None
                tg_message.session.n_content_related = n_content_related
                n_content_related = send_messages_in_inbox(tg_message.session, conn, n_content_related)

        except ConnectionResetError:
            print(f"Client {addr} has disconnected.")
            break
    conn.close()
    print(f"Connection with {addr} closed.")

def get_auth_keys(user_id: str):
    user = load_user_data_server(user_id=user_id)
    if user is not None:
        auth_keys = user["auth_keys"]
        return auth_keys
    return []

def get_auth_key_id(auth_key: bytearray):
    return bytearray(hashlib.sha1(auth_key).digest())[12:]

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}...")

        while True:
            conn, addr = server_socket.accept()  # Accept a client connection
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()  # Start a new thread for each client
            print(f"Active connections: {threading.active_count() - 1}")


if __name__ == "__main__":
    start_server()





