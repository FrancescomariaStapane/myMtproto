import math
import tgcrypto
import time
from src.utils import *
import hashlib

from src.MTProto_Session import MTProto_Session


class TGMessage:
    def __init__(self, message_data : bytearray, session: MTProto_Session, msg_type: str, silent: bool, colored: bool):
        self.session = session
        self.message_data = message_data
        unix_s = math.floor(time.time()) << 32  # 32 most significative bits are unix time
        unix_ns = (time.time_ns() - math.floor(time.time()) * 10 ** 9) # 32 less significative bits are nanoseconds since last second
        msg_id =  unix_s + unix_ns
        self.msg_type = msg_type
        modulo = 0 if msg_type == "client_msg" else 1 if msg_type == "server_response_msg" else 3
        additive = (4 - msg_id % 4 + modulo) % 4
        self.message_id = msg_id + additive # message_id mod 4 is 0 for client messages, 3 for server unsolicited messages and 1 for server response messages
        self.seqNo = (self.session.n_content_related << 1) + 1
        session.n_content_related +=1
        self.data_length = (len(self.message_data))
        self.padding = rand_bytes(random.randint(12,1024))
        self.plaintext = (self.session.get_header_Bytes()
                          + to_bytes(self.message_id, 8)
                          + to_bytes(self.seqNo, 4)
                          + to_bytes(self.data_length, 4)
                          + self.message_data
                          + self.padding)

        x = 0 if msg_type == "client_msg" else 8

        auth_key_fragment_msg_key_start = 88 + x
        auth_key_fragment_msg_key_end = 88 + 32 + x
        auth_key_fragment_sha_a_start = x
        auth_key_fragment_sha_a_end = 36 + x
        auth_key_fragment_sha_b_start = 40 + x
        auth_key_fragment_sha_b_end = 40 + 36 + x

        auth_key_fragment_msg_key = self.session.auth_key[auth_key_fragment_msg_key_start : auth_key_fragment_msg_key_end]
        auth_key_fragment_sha_a = self.session.auth_key[auth_key_fragment_sha_a_start : auth_key_fragment_sha_a_end]
        auth_key_fragment_sha_b = self.session.auth_key[auth_key_fragment_sha_b_start : auth_key_fragment_sha_b_end]
        pre_hashed_msg_key_large = auth_key_fragment_msg_key + self.plaintext
        msg_key_large = hashlib.sha256(pre_hashed_msg_key_large).digest()
        msg_key = msg_key_large[8:24]
        sha_256_a = hashlib.sha256(auth_key_fragment_sha_a + msg_key).digest()
        sha_256_b = hashlib.sha256(msg_key + auth_key_fragment_sha_b).digest()
        self.aes_key = sha_256_a[:8] + sha_256_b[8 : 24] + sha_256_a[24:]
        self.aes_iv =  sha_256_b[:8] + sha_256_a[8 : 24] + sha_256_b[24:]
        self.cyphertext = tgcrypto.ige256_encrypt(self.plaintext + bytes(-len(self.plaintext) % 16), self.aes_key, self.aes_iv)


        print()
        if not silent:
            instant = False
            salt_str = colored_str(to_hex_str(self.session.salt), "salt", colored)
            session_id_str = colored_str(to_hex_str(self.session.session_id), "session_id", colored)
            additive_str = colored_str(str(additive), "additive", colored)
            unix_s_str = colored_str(to_hex_str(to_bytes(unix_s >> 32, 4)), "unix_s", colored)
            unix_ns_str = colored_str(to_hex_str(to_bytes(unix_ns, 4)),"unix_ns", colored)
            hex_msg_id = to_hex_str(to_bytes(self.message_id))
            message_id_str = (colored_str(hex_msg_id[:len(hex_msg_id)//2], "unix_s", colored)
                              + colored_str(hex_msg_id[len(hex_msg_id)//2:-2], "unix_ns", colored)
                              + colored_str(hex_msg_id[-2:], "additive", colored))
            msg_seq_no_str = colored_str(to_hex_str(to_bytes(self.seqNo, 4)), "seq_no", colored)
            data_length_str = colored_str(to_hex_str(to_bytes(self.data_length, 4)), "data_length", colored)
            message_data_str = colored_str(to_hex_str(self.message_data), "message_data", colored)
            padding_str = colored_str(to_hex_str(self.padding), "padding", colored)

            plaintext_str = salt_str + session_id_str + message_id_str + msg_seq_no_str + data_length_str + message_data_str + padding_str
            auth_key_str = to_hex_str(self.session.auth_key)
            colored_auth_key_msg = colored_str(to_hex_str(auth_key_fragment_msg_key), "auth_key_msg_key", colored)
            colored_auth_key_sha_a = colored_str(to_hex_str(auth_key_fragment_sha_a), "auth_key_sha_a", colored)
            colored_auth_key_sha_b = colored_str(to_hex_str(auth_key_fragment_sha_b), "auth_key_sha_b", colored)
            colored_auth_key_str = (colored_str(auth_key_str[: 3 * auth_key_fragment_sha_a_start], "unused", colored)
                                    + colored_auth_key_sha_a
                                    + colored_str(auth_key_str[3 * auth_key_fragment_sha_a_end: 3 * auth_key_fragment_sha_b_start], "unused", colored)
                                    + colored_auth_key_sha_b
                                    + colored_str(auth_key_str[3 * auth_key_fragment_sha_b_end: 3 * auth_key_fragment_msg_key_start],"unused", colored)
                                    + colored_auth_key_msg
                                    + colored_str(auth_key_str[3 * auth_key_fragment_msg_key_end :],"unused", colored)
                                    )
            colored_msg_key = colored_str(to_hex_str(msg_key), "msg_key", colored)
            colored_msg_key_large = colored_str(to_hex_str(msg_key_large[:8]), "unused", colored) + colored_msg_key + colored_str(to_hex_str(msg_key_large[24:]),"unused", colored)
            colored_sha_256_a = colored_str(to_hex_str(sha_256_a), "sha_256_a", colored)
            colored_sha_256_b = colored_str(to_hex_str(sha_256_b), "sha_256_b", colored)
            colored_aes_key = colored_str(to_hex_str(self.aes_key[:8]), "sha_256_a", colored) + colored_str(to_hex_str(self.aes_key[8:24]), "sha_256_b", colored) +  colored_str(to_hex_str(self.aes_key[24:]), "sha_256_a", colored)
            colored_aes_iv =  colored_str(to_hex_str(self.aes_iv[:8]), "sha_256_b", colored) + colored_str(to_hex_str(self.aes_iv[8:24]), "sha_256_a", colored) +  colored_str(to_hex_str(self.aes_iv[24:]), "sha_256_b", colored)
            colored_auth_key_id = colored_str(to_hex_str(self.session.auth_key_id), "auth_key_id", colored)
            colored_cyphertext = colored_str(to_hex_str(self.cyphertext), "cyphertext", colored)
            print("\nGenerating plaintext to be encrypted:\n")
            print(f"Generating {colored_str("Internal Header","bold", colored)}, consisting of server salt and session_id\n")

            wait_input(instant)
            print(colored_str("salt:\n", "bold", colored) + colored_str("64 bits, randomly generated by the server, changes every 30 minutes","italic", colored))
            print(salt_str)

            wait_input(instant)
            print(colored_str("\nsession_id:\n", "bold", colored) + "64 bits, generated by client at random, lasts for the entire session")
            print(session_id_str)

            wait_input(instant)
            print(f"\ngenerating {colored_str("Message","bold", colored)}, consisting of message_id, message_seq_no, message_data_length, message_data and padding")

            wait_input(instant)
            print("\ngenerating "+colored_str("message_id: \n", "bold", colored) + f"64 bit, 32 most significative bits are the unix time in seconds. 32 least significative bits are nanoseconds since last second. \nSince message_id % 4 = {msg_id % 4} and message type is {msg_type}, {additive_str} was added so that message_id % 4 = {modulo} ")

            wait_input(instant)
            print(colored_str("unix seconds: ", "bold", colored))
            print(unix_s_str)

            wait_input(instant)
            print(colored_str("nanoseconds: ", "bold", colored))
            print(unix_ns_str)

            wait_input(instant)
            print(colored_str("message_id: ", "bold", colored))
            print(message_id_str)

            wait_input(instant)
            print(colored_str("\nmsg_seq_no: \n", "bold", colored) + "32 bit, message sequence number. Equal to 2n + 1 where n is the number of content related messages sent in the current session prior to this one.")
            print(msg_seq_no_str)

            wait_input(instant)
            print(colored_str("\nmessage_data_length: \n", "bold", colored) + "32 bit, length of actual data")
            print(data_length_str)

            wait_input(instant)
            print(colored_str("\nmessage_data: \n", "bold", colored) + f"variable length ({len(self.message_data)} in this instance), actual message contents")
            print(message_data_str)

            wait_input(instant)
            print(colored_str("\npadding: \n", "bold", colored) + f"12 to 1024 Bytes ({len(self.padding)} in this instance), random length, random contents")
            print(padding_str)

            wait_input(instant)
            print(colored_str("\nassembled plaintext: \n", "bold", colored) + "salt + session_id + message_id + seq_no + message_data_length + message_data + padding")
            print(plaintext_str)

            wait_input(instant)
            print(f"\nGenerating AES IGE {colored_str("aes_key","bold", colored)} and {colored_str("aes_iv","bold", colored)} from auth_key and plaintext:")
            wait_input(instant)
            print(f"{colored_str("\nauth_key: \n", "bold", colored)}2048 bit, exchanged through Diffie-Hellman when logging into a new device, known to client device and server. A single user can have multiple auth_keys, one for each device where they are logged in. Once obtained, it is never changed."
                  f"\nBytes 0..7, 44..47 and 88..95 are unused in communications server to client{" (this case)" if "client" not in self.msg_type else ""}"
                  f"\nBytes 36..39, 76..83 and 120..127 are unused in communications client to server{"(this case)" if "client" in self.msg_type else ""}"
                  f"\nBytes 84..87 and 128..255 are never involved in the computation of aes_key and aes_iv, and may only be used for encryption on local data on device."
                  f"\nAll the remaining bytes are used on both directions of communication")

            print(colored_auth_key_str)

            wait_input(instant)
            print(f"\n{colored_str("x: \n", "bold", colored)}x = 0 on client to server messages, x = 8 on server to client messages. In this instance, x = {x}")

            wait_input(instant)
            print(f"{colored_str("\npre-hashed msg_key_large: \n", "bold", colored)}auth_key_fragment_msg + plaintext, where auth_key_fragment_msg is the 32 bytes of auth_key starting from byte 88 + x ({88 + x})")
            print(colored_auth_key_msg + plaintext_str)

            wait_input(instant)
            print(f"{colored_str("\nmsg_key_large: \n", "bold", colored)}sha-256 of auth_key_fragment_msg + plaintext")
            print(colored_msg_key_large)

            wait_input(instant)
            print(f"{colored_str("\nmsg_key: \n", "bold", colored)}middle 16 bytes of msg_key_large, the rest of msg_key_large is unused")
            print(colored_msg_key)

            wait_input(instant)
            print(f"{colored_str("\npre-hashed sha_256_a: \n", "bold", colored)}auth_key_fragment_a + msg_key, where auth_key_fragment_a is the 36 bytes of auth_key starting from byte x ({x})")
            print(colored_auth_key_sha_a + colored_msg_key)

            wait_input(instant)
            print(f"{colored_str("\nsha_256_a: ", "bold", colored)}\nsha-256 of auth_key_fragment_a + msg_key")
            print(colored_sha_256_a)

            wait_input(instant)
            print(f"{colored_str("\npre-hashed sha_256_b: \n", "bold", colored)}msg_key + auth_key_fragment_b, where auth_key_fragment_b is the 36 bytes of auth_key starting from byte 40 + x ({40 + x})")
            print(colored_msg_key + colored_auth_key_sha_b)

            wait_input(instant)
            print(f"{colored_str("\nsha_256_b: ", "bold", colored)}\nsha-256 of msg_key + auth_key_fragment_b")
            print(colored_sha_256_b)

            wait_input(instant)
            print(f"{colored_str("\naes_key: ", "bold", colored)}\nBytes 0..7 of sha_256_a + bytes 8..23 of sha_256_b + bytes 24..31 of sha_256_a")
            print(colored_aes_key)

            wait_input(instant)
            print(f"{colored_str("\naes_iv: ", "bold", colored)}\nBytes 0..7 of sha_256_b + bytes 8..23 of sha_256_a + bytes 24..31 of sha_256_b")
            print(colored_aes_iv)

            wait_input(instant)
            print("Generating external header")

            wait_input(instant)
            print(f"{colored_str("auth_key_id: ", "bold", colored)}\nSHA-1 of auth_key")
            print(colored_auth_key_id)

            wait_input(instant)
            print(f"{colored_str("external header: ", "bold", colored)}\nauth_key_id + msg_key\nsent in clear text\nauth_key_id is needed to identify the auth_key for decryption, msg_key is needed to compute aes_key and aes_iv")
            print(colored_auth_key_id + colored_msg_key)

            wait_input(instant)
            print(f"{colored_str("\ncyphertext: ", "bold", colored)}\nAES Infinite Garble Mode (IGE) of plaintext (zero padded to be of a multiple of 16 bytes long)")
            print(colored_cyphertext)

            wait_input(instant)
            print(f"{colored_str("pre-obfuscation data: ", "bold", colored)}\nexternal header + cyphertext")
            print(colored_auth_key_id + colored_msg_key + colored_cyphertext)

            wait_input(instant)
            print("Obfuscating data:")

            wait_input(instant)




