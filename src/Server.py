import argparse
import hashlib

from MtprotoSession import MtprotoSession
from TGMessage import TGMessage, MsgCheckFailedException
from src.utils import *
import socket
import threading

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

def send_messages_in_inbox(session, conn):
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
        conn.send(tg_message.get_encrypted_data())
        messages[auth_key_id] = []


def handle_client(conn, addr):

    print(f"Connection established with {addr}.")

    while True: # until client disconnects
        try:

            data = conn.recv(4096)
            if not data or len(data) == 0:
                continue
            try:
                tg_message = TGMessage(ciphertext_bytes= data, msg_type="client_msg", silent=get_args().silent, colored=get_args().colored,
                                       instant=get_args().instant) # we decrypt
            except MsgCheckFailedException as e: # an exception is thrown when msg_key check on decryption fails
                continue

            # for the first message in the session, the session object is built based on the data in the message
            # if session is None:
            #     session: MtprotoSession = tg_message.session
            # auth_key_id = to_hex_str(session.auth_key_id, spaces=False)


            # after all pending messages are sent, inbox is cleared
            decrypted_data = tg_message.get_decrypted_data()
            recipient_id = decrypted_data[:8]
            payload = decrypted_data[9:]
            if recipient_id != b"00000000" : # dummy value for recipient, I use it on the first message that starts the session or to receive messages, in reality it's done in a different way
                print("received data: ")
                print(decrypted_data.decode())
                stored_message = (load_user_data_server(auth_key_id=tg_message.session.auth_key_id)["user_id"]).encode() + b":" + payload
                recipient_auth_key_ids = (get_auth_key_id(bytearray(bytes.fromhex(auth_key))) for auth_key in get_auth_keys(recipient_id.decode()))
                for recipient_auth_key_id in recipient_auth_key_ids: # for each auth_key (one per logged device) associated with the recipients' account we store the message
                    str_auth_key_id = to_hex_str(recipient_auth_key_id, spaces=False)
                    if str_auth_key_id not in messages.keys():
                        messages[str_auth_key_id] = []
                    messages[str_auth_key_id].append(stored_message) # messages are stored in plaintext
            else:
                print("received blank message")
            send_messages_in_inbox(tg_message.session, conn)

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
    return bytearray(hashlib.sha1(auth_key).digest())

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
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
    messages = {}
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(4086).decode()
        if not data:
            # if data is not received break
            break
        # print("from connected user: " + str(data))
        recipient_id = data[:8]
        payload = data[9:]

        print("id: ", recipient_id)
        print("payload: ", payload)

        data = '' # derypt and reencrypt emssage, put sender-user_id in front of payload
        conn.send(data.encode())  # send data to the client

    conn.close()  # close the connection


