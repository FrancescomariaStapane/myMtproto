import os
import random
import socket
from tempfile import template
import hashlib
from time import time, sleep
import time

from Crypto.Cipher import AES
from Crypto.Cipher._mode_ctr import CtrMode
from Crypto.Util import Counter
from telethon.tl.core import MessageContainer

import TGMessage
from MtprotoSession import MtprotoSession
import utils
from TGMessage import TGMessage
from utils import to_hex_str, colored_st, bytes_to_int, rand_bytes, deserialize_TL_message


def merge_outgoing_incoming_messages(outgoing_messages, incoming_messages):
    merged_messages = []
    i, j = 0, 0
    while i < len(outgoing_messages) and j < len(incoming_messages):
        if outgoing_messages[i].get_total_time() < incoming_messages[j].get_total_time():
            merged_messages.append(outgoing_messages[i])
            i += 1
        else:
            merged_messages.append(incoming_messages[j])
            j += 1
    merged_messages.extend(outgoing_messages[i:])
    merged_messages.extend(incoming_messages[j:])
    return merged_messages





    # print(decoded_message)


def derive_deobfuscation_ciphers(outgoing_stream : bytes, decryptInit = True):
    # outgoing_stream: first 64 bytes or more of the outgoing stream
    init = outgoing_stream[8:56]

    obf_enc_key = init[:32]
    obf_enc_iv = init[32:]
    obf_enc_ivInt = int.from_bytes(obf_enc_iv, 'big')
    counter_obf_enc = Counter.new(128, initial_value=obf_enc_ivInt)
    cipher_obf_enc = AES.new(obf_enc_key, AES.MODE_CTR, counter=counter_obf_enc)

    obf_dec_key = init[::-1][:32]
    obf_dec_iv = init[::-1][32:]
    obf_dec_ivInt = int.from_bytes(obf_dec_iv, 'big')
    counter_obf_dec = Counter.new(128, initial_value=obf_dec_ivInt)
    cipher_obf_dec = AES.new(obf_dec_key, AES.MODE_CTR, counter=counter_obf_dec)

    if decryptInit:
        transport_protocol_tag = cipher_obf_enc.decrypt(outgoing_stream[:64])[56:]
    else:
        transport_protocol_tag = bytes()
    # for outgoing data, first 64 bytes must be skipped with the returned cipher
    return cipher_obf_enc, cipher_obf_dec, transport_protocol_tag

def create_obfuscation_ciphers(protocol_code):
    protocol_bytes = bytearray()
    for _ in range(4):
        protocol_bytes.append(protocol_code)  # single byte protocol identifier x 4
    protocol_bytes.extend(rand_bytes(4))

    init = rand_bytes(64)
    init = init[:56] + protocol_bytes
    cipher_obf_enc, cipher_obf_dec, transport_protocol_tag = derive_deobfuscation_ciphers(init, decryptInit=False)
    encrypted_init = cipher_obf_enc.encrypt(init)
    encrypted_init = init[:56] + encrypted_init[56:]
    return  cipher_obf_enc, cipher_obf_dec, encrypted_init

def read_stream(outgoing_traffic_file, ingoing_traffic_file, loud = True, louder=False):
    # indexes: 0 -> ougoing, 1 -> incoming
    strings = ["outgoing", "incoming"]
    msg_types = ["client_msg", "server_msg"]
    obfuscated_bytes = [bytes(),bytes()]
    with open(outgoing_traffic_file, "rb") as file:
        obfuscated_bytes[0] = (bytes.fromhex(file.read().decode()))
    with open(ingoing_traffic_file, "rb") as file:
        obfuscated_bytes[1] = (bytes.fromhex(file.read().decode()))
    ciphers = [None, None]
    ciphers[0], ciphers[1], tag = derive_deobfuscation_ciphers(obfuscated_bytes[0])
    # ciphers[0] is cipher_obf_enc, for deobfuscating outgoing bytes,
    # ciphers[1] is cipher_obf_dec, for deobfuscating incoming bytes
    deobfuscated_bytes = list((ciphers[0].decrypt(obfuscated_bytes[0][64:]), ciphers[1].decrypt(obfuscated_bytes[1])))
    messages = [[],[]]
    if loud: print("tag:", tag.hex())
    for i in range(2):
        if loud and louder:
            print()
            print(f"Deobfuscated {strings[i]} bytes:")
            print(to_hex_str(deobfuscated_bytes[i]))
        while len(deobfuscated_bytes[i]) > 0:
            message = TGMessage(ciphertext_bytes=deobfuscated_bytes[i], msg_type=msg_types[i], silent=True, colored=True, instant=True, fetch=True)
            tcp_len = (len(message.abridged_transport_header) + message.n_bytes_tcp_payload)
            this_message_obfuscated_bytes = obfuscated_bytes[i][:tcp_len]
            this_message_deobfuscated_bytes = deobfuscated_bytes[i][:tcp_len]
            deobfuscated_bytes[i] = deobfuscated_bytes[i][tcp_len:]
            obfuscated_bytes[i] = obfuscated_bytes[i][tcp_len:]
            messages[i].append(message)
    return messages


def main():
    pass
    # n_capture = "15"
    # with open(str("capture/out" + n_capture), "rb") as file:
    #     obfuscated_outgoing_bytes = (bytes.fromhex(file.read().decode()))
    # with open(str("capture/in" + n_capture), "rb") as file:
    #     obfuscated_incoming_bytes = (bytes.fromhex(file.read().decode()))
    #
    # cipher_obf_enc, cipher_obf_dec, tag = derive_deobfuscation_ciphers(obfuscated_outgoing_bytes)
    # print("tag:", tag.hex())
    # deobfuscated_outgoing_traffic = cipher_obf_enc.decrypt(obfuscated_outgoing_bytes[64:])
    #
    #
    # deobfuscated_incoming_traffic = cipher_obf_dec.decrypt(obfuscated_incoming_bytes)
    # # tg = Tgnet('/home/franc/Desktop/tgnets/tgnet3.dat')
    # # dc = tg.get_current_datacenter()
    # # auth_key = dc.get_auth_key_temp()
    #
    # deobfuscated_outgoing_bytes = bytearray(bytes.fromhex(utils.to_hex_str(deobfuscated_outgoing_traffic, False)))
    # deobfuscated_incoming_bytes = bytearray(bytes.fromhex(utils.to_hex_str(deobfuscated_incoming_traffic, False)))
    # obfuscated_outgoing_bytes = obfuscated_outgoing_bytes[64:] #skipping already analyzed bytes
    # print(to_hex_str(deobfuscated_outgoing_bytes))
    #
    # outgoing_messages = []
    # incoming_messages = []
    #
    # template_send_message = None
    #
    #
    # print("OUTGOING TRAFFIC\n")
    # while len(deobfuscated_outgoing_bytes) > 0:
    #     message = TGMessage(ciphertext_bytes = deobfuscated_outgoing_bytes, msg_type="client_msg", silent=True, colored=True, instant=True, fetch=True)
    #     tcp_len = (len(message.abridged_transport_header) + message.n_bytes_tcp_payload)
    #
    #     # print(f"Deobfuscated bytes from {to_hex_str(deobfuscated_outgoing_bytes[:4])} to {to_hex_str(deobfuscated_outgoing_bytes[tcp_len -4 : tcp_len])}")
    #     # print(f"Obfuscated bytes from {to_hex_str(bytearray(obfuscated_outgoing_traffic[:4]), False)} to {to_hex_str(bytearray(obfuscated_outgoing_traffic[tcp_len -4 : tcp_len]), False)}")
    #     this_message_obfuscated_bytes = obfuscated_outgoing_bytes[:tcp_len]
    #     this_message_deobfuscated_bytes = deobfuscated_outgoing_bytes[:tcp_len]
    #     deobfuscated_outgoing_bytes = deobfuscated_outgoing_bytes[tcp_len:]
    #     obfuscated_outgoing_bytes = obfuscated_outgoing_bytes[tcp_len:]
    #     outgoing_messages.append(message)
    #     decoded_TL_message = deserialize_TL_message(message.message_data_plaintext)
    #     print(decoded_TL_message.to_dict())
    #     if isinstance(decoded_TL_message, MessageContainer):
    #         print("Submessages objects")
    #         for sub_message in decoded_TL_message.messages:
    #             print(sub_message.obj.to_dict())
    #     print()
    #     print("ObfuscatedBytes")
    #     print(to_hex_str(this_message_obfuscated_bytes, False))
    #     print("Salt:")
    #     print(to_hex_str(message.session.salt))
    #     print("Session ID:")
    #     print(to_hex_str(message.session.session_id))
    #     print("SeqNo:")
    #     print(bytes_to_int(message.seqNo, little= True))
    #     print()
    #     if "message" in deserialize_TL_message(message.message_data_plaintext).to_dict().keys():
    #         template_send_message = message
    #     #     print("plaintext bytes:")
    #     #     print(to_hex_str(message.message_data_plaintext))
    #     #     print(decode_TL_message(message.message_data_plaintext).to_dict())
    #     # if len(outgoing_messages) > 1: print("delta = ", bytes_to_int(message.seqNo, little=True) -bytes_to_int(outgoing_messages[len(outgoing_messages)-2].seqNo, little=True), "CR:",message.contentRelated)
    #     print(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(message.unix_s)))
    #
    #
    # print("\n\nINCOMING TRAFFIC\n")
    #
    # while len(deobfuscated_incoming_bytes) > 0:
    #     if deobfuscated_incoming_bytes[0] & 128 == 128:
    #         deobfuscated_incoming_bytes = deobfuscated_incoming_bytes[4:] # skip quick ack
    #     message = TGMessage(ciphertext_bytes = deobfuscated_incoming_bytes, msg_type="server_msg", silent=True, colored=True, instant=True, fetch = True)
    #     incoming_messages.append(message)
    #     decoded_TL_message = deserialize_TL_message(message.message_data_plaintext)
    #
    #     print(decoded_TL_message.to_dict())
    #     if isinstance(decoded_TL_message, MessageContainer):
    #         print("Submessages objects")
    #         for sub_message in decoded_TL_message.messages:
    #             print(sub_message.obj.to_dict())
    #     print()
    #     # if isinstance(decoded_TL_message, MessageContainer):
    #     #     print("Submessages objects")
    #     #     for sub_message in decoded_TL_message.messages:
    #     #         print(sub_message.obj.to_dict())
    #
    #
    #     tcp_len = (len(message.abridged_transport_header) + message.n_bytes_tcp_payload)
    #     # print(f"Deobfuscated bytes from {to_hex_str(deobfuscated_incoming_bytes[:4])} to {to_hex_str(deobfuscated_incoming_bytes[tcp_len -4 : tcp_len])}")
    #     # print(f"Obfuscated bytes from {to_hex_str(bytearray(obfuscated_incoming_traffic[:4]), False)} to {to_hex_str(bytearray(obfuscated_incoming_traffic[tcp_len -4 : tcp_len]), False)}")
    #     this_message_obfuscated_bytes = obfuscated_incoming_bytes[:tcp_len]
    #     this_message_deobfuscated_bytes = deobfuscated_incoming_bytes[:tcp_len]
    #
    #     print(deserialize_TL_message(message.message_data_plaintext).to_dict())
    #     print("ObfuscatedBytes")
    #     print(to_hex_str(this_message_obfuscated_bytes, False))
    #     deobfuscated_incoming_bytes = deobfuscated_incoming_bytes[tcp_len:]
    #     obfuscated_incoming_bytes = obfuscated_incoming_bytes[tcp_len:]
    # print(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(incoming_messages[-1].unix_s)))

if __name__ == "__main__":
    main()
# for i in range(len(outgoing_messages)):
#     if outgoing_messages[i].abridged_transport_header[0] & 128 == 128:
#         print("delta = ",bytes_to_int(outgoing_messages[i].seqNo, little=True))

# merged_messages = merge_outgoing_incoming_messages(outgoing_messages, incoming_messages)
# for message in merged_messages:
#     if "client" in message.msg_type:
#         print(colored_st(str(decode_TL_message(message).to_dict()), "salt", True))
#     else:
#         print(colored_st(str(decode_TL_message(message).to_dict()), "session_id", True))
#     print()
#
# for message in merged_messages:
#     print( message.msg_type)
# with open("last_message", "wb") as file:
#     file.write(last_message.get_encrypted_data())



