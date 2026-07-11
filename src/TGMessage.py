import math
import random

import tgcrypto
import time

from telethon.errors import TypeNotFoundError

from src.utils import *
import hashlib

from src.MtprotoSession import MtprotoSession
from telethon.extensions import BinaryReader



class TGMessage:

    def __init__(self, plaintext_bytes : bytearray = None, session: MtprotoSession = None, msg_type: str  = None, silent: bool = False, colored: bool  = None, instant: bool = False, ciphertext_bytes : bytearray = None):
        
        self.check_msg_key_large = None
        self.check_msg_key = None
        self.msg_type = None
        self.msg_time = None
        self.unix_ns = None
        self.unix_s = None
        self.message_data_plaintext = None
        self.modulo = None
        self.additive = None
        self.message_id = None
        self.seqNo = None
        self.data_length = None
        self.padding = None
        self.plaintext = None
        self.x = None
        self.auth_key_fragment_msg_key_start = None
        self.auth_key_fragment_msg_key_end = None
        self.auth_key_fragment_sha_a_start = None
        self.auth_key_fragment_sha_a_end = None
        self.auth_key_fragment_sha_b_start = None
        self.auth_key_fragment_msg_key = None
        self.auth_key_fragment_sha_b_end = None
        self.auth_key_fragment_sha_a = None
        self.auth_key_fragment_sha_b = None
        self.msg_key_large = None
        self.msg_key = None
        self.sha_256_a = None
        self.sha_256_b = None
        self.aes_key = None
        self.aes_iv = None
        self.ciphertext = None
        self.tcp_payload = None
        self.abridged_transport_header = None
        self.session = session
        self.complete_bytes_ciphertext = None
        self.received_auth_key_id = None
        self.n_bytes_tcp_payload = 0
        if ciphertext_bytes is None:
            self.construct_message_from_plaintext(plaintext_bytes, msg_type, silent, colored, instant)
        else:
            self.construct_message_from_ciphertext(ciphertext_bytes, msg_type, silent, colored, instant)


    def prepare_to_build_msg_key(self, sender: str):
        self.x = 0 if ("client" in sender) else 8
        self.auth_key_fragment_msg_key_start = 88 + self.x
        self.auth_key_fragment_msg_key_end = 88 + 32 + self.x
        self.auth_key_fragment_sha_a_start = self.x
        self.auth_key_fragment_sha_a_end = 36 + self.x
        self.auth_key_fragment_sha_b_start = 40 + self.x
        self.auth_key_fragment_sha_b_end = 40 + 36 + self.x

        self.auth_key_fragment_msg_key = self.session.auth_key[
            self.auth_key_fragment_msg_key_start: self.auth_key_fragment_msg_key_end]
        self.auth_key_fragment_sha_a = self.session.auth_key[
            self.auth_key_fragment_sha_a_start: self.auth_key_fragment_sha_a_end]
        self.auth_key_fragment_sha_b = self.session.auth_key[
            self.auth_key_fragment_sha_b_start: self.auth_key_fragment_sha_b_end]


    def build_aes_key_iv(self):
        self.sha_256_a = hashlib.sha256(self.msg_key + self.auth_key_fragment_sha_a).digest()
        self.sha_256_b = hashlib.sha256(self.auth_key_fragment_sha_b + self.msg_key).digest()
        self.aes_key = self.sha_256_a[:8] + self.sha_256_b[8: 24] + self.sha_256_a[24:]
        self.aes_iv = self.sha_256_b[:8] + self.sha_256_a[8: 24] + self.sha_256_b[24:]

    def construct_message_from_ciphertext(self, received_bytes: bytearray, sender:str, silent: bool, colored: bool, instant: bool = False):
        self.complete_bytes_ciphertext = bytearray(received_bytes)
        if self.complete_bytes_ciphertext[0] > 127:
            print()
        self.complete_bytes_ciphertext[0] &= 127
        if self.complete_bytes_ciphertext[0] != 0x7f:
            self.abridged_transport_header = self.complete_bytes_ciphertext[:1]
            self.n_bytes_tcp_payload = self.abridged_transport_header[0] * 4
            self.tcp_payload = self.complete_bytes_ciphertext[1: 1 + self.n_bytes_tcp_payload]
        else:
            self.abridged_transport_header = self.complete_bytes_ciphertext[:4]
            self.n_bytes_tcp_payload = bytes_to_int(self.abridged_transport_header[1:4], little=True) * 4
            self.tcp_payload = self.complete_bytes_ciphertext[4:  4 + self.n_bytes_tcp_payload]
        # self.session = MtprotoSession(auth_key) # todo questo rigenera l'id della sessione, devo prendere effettivmente i dati dal messaggio
        if self.session is None:
            self.session = MtprotoSession(self.tcp_payload[:8])
        self.received_auth_key_id = self.tcp_payload[:8]
        self.msg_key = self.tcp_payload[8:24]
        self.ciphertext = self.tcp_payload[24:]
        self.prepare_to_build_msg_key(sender)
        self.build_aes_key_iv()
        if len(self.ciphertext) % 16 != 0:
            print("ciphertext length : ", len(self.ciphertext))
        if self.session.auth_key_id == MtprotoSession.NULL_AUTH_KEY_ID:
            self.plaintext = self.ciphertext
        else:
            self.plaintext = tgcrypto.ige256_decrypt(self.ciphertext, self.aes_key, self.aes_iv)
        self.remove_trailing_zeros()
        pre_hashed_msg_key_large = self.auth_key_fragment_msg_key + self.plaintext
        self.check_msg_key_large = hashlib.sha256(pre_hashed_msg_key_large).digest()
        self.check_msg_key = self.check_msg_key_large[8:24]

        self.msg_key_large = self.check_msg_key_large
        self.seqNo = self.plaintext[24:28]
        self.session.salt = self.plaintext[:8]
        self.session.session_id = self.plaintext[8:16]
        self.session.n_content_related = (bytes_to_int(self.seqNo) >> 1) + 1
        self.message_id = self.plaintext[16:24]
        self.unix_s = bytes_to_int(self.message_id[4:], little=True)
        self.unix_ns = bytes_to_int(self.message_id[:4], little=True)
        self.msg_type = "client_msg" if self.unix_ns % 4 == 0 else "server_response_msg" if self.unix_ns % 4 == 1 else "server_unsolicited"
        self.data_length = bytes_to_int(self.plaintext[28:32], little = True)
        self.message_data_plaintext = self.plaintext[32:32 + self.data_length]
        self.padding =  self.plaintext[32 + self.data_length:]
        if not silent and self.message_data_plaintext[:8]!=b"00000000":
            if self.session.auth_key_id == MtprotoSession.NULL_AUTH_KEY_ID:
                instant = True
            self.print_message_decryption(colored, instant)

        if self.check_msg_key != self.msg_key:
            print("auth_key_fragment check on decryption failed")
            print("decrypted msg_key      : ",to_hex_str(self.check_msg_key))
            print("external header msg_key: ",to_hex_str(self.msg_key))
            raise MsgCheckFailedException
        # print("Message raw:")
        # print(str(self.message_data_plaintext)[2:-1])
        print("TL message converted by Telethon BinaryReader")
        try:
            with BinaryReader(self.message_data_plaintext) as reader:
                obj = reader.tgread_object()
                # print(obj)
                print(obj.to_dict())
        except TypeNotFoundError :
            print("Telethon Could not find a matching Constructor ID for the TLObject that was supposed to be read with ID 93d7b347")

    def construct_message_from_plaintext(self, message_data: bytearray, msg_type: str,
                                         silent: bool, colored: bool, instant: bool = False):

        self.message_data_plaintext = message_data
        self.unix_s = math.floor(time.time())   # 32 most significative bits are unix time
        self.unix_ns = (time.time_ns() - math.floor(
            time.time()) * 10 ** 9)  # 32 less significative bits are nanoseconds since last second
        self.msg_time = (self.unix_s << 32) + self.unix_ns
        self.msg_type = msg_type
        self.modulo = 0 if msg_type == "client_msg" else 1 if msg_type == "server_response_msg" else 3 #server_unsolicited
        self.additive = (4 - self.msg_time % 4 + self.modulo) % 4
        self.message_id = to_bytes(self.msg_time + self.additive,8, little = True)  # message_id mod 4 is 0 for client messages, 3 for server unsolicited messages and 1 for server response messages

        # self.message_id = to_bytes((self.msg_time+ self.additive) <<32 >> 32,4, little = True) + to_bytes(self.unix_s, 4, little = True)
        self.seqNo = to_bytes((self.session.n_content_related << 1) + 1, 4, little = True)
        self.session.n_content_related += 1
        self.data_length = len(self.message_data_plaintext)
        self.padding = bytearray(rand_bytes(random.randint(12, 1024)))
        while self.padding[-1] == 0x00:
            self.padding[-1] = rand_bytes(1)[0]
        self.received_auth_key_id = self.session.auth_key_id
        self.plaintext = (self.session.get_header_Bytes()
                          + self.message_id
                          + self.seqNo
                          + to_bytes(self.data_length, length=4, little=True)
                          + self.message_data_plaintext
                          + self.padding)

        self.prepare_to_build_msg_key(msg_type)
        pre_hashed_msg_key_large = self.auth_key_fragment_msg_key + self.plaintext
        self.msg_key_large = hashlib.sha256(pre_hashed_msg_key_large).digest()
        self.msg_key = self.msg_key_large[8:24]
        self.check_msg_key_large = self.msg_key_large
        self.check_msg_key = self.msg_key
        self.build_aes_key_iv()
        if self.session.auth_key_id != MtprotoSession.NULL_AUTH_KEY_ID:
            self.ciphertext = tgcrypto.ige256_encrypt(self.plaintext + bytes(-len(self.plaintext) % 16), self.aes_key,
                                                  self.aes_iv)
        else:
            self.ciphertext = self.plaintext + bytes(-len(self.plaintext) % 16) #if auth_key_idis 000... we do not encrypt

        self.tcp_payload = self.session.auth_key_id + self.msg_key + self.ciphertext
        self.abridged_transport_header = to_bytes(int(len(self.tcp_payload) / 4), 1) if int(
            len(self.tcp_payload) / 4) < 127 else to_bytes(0x7f, 1) + to_bytes(int(len(self.tcp_payload) / 4), 3)
        self.complete_bytes_ciphertext = self.abridged_transport_header + self.tcp_payload
        # print("length:", len(self.ciphertext))
        if self.message_data_plaintext[:8] == b"00000000":
            silent = True
        if self.session.auth_key_id == MtprotoSession.NULL_AUTH_KEY_ID:
            instant = True
        if not silent:
            self.print_message_encryption(colored, instant)
        pass




    def print_message_encryption(self, colored: bool, instant: bool):
        printable_message = PrintableBytesMessage(self, colored)
        salt_str = colored_st("salt", "salt", colored)
        session_id_str = colored_st("session_id", "session_id", colored)
        # internal_header_str = colored_str("internal ", "salt", colored) + colored_str("header", "session_id", colored)
        internal_header_str = colored_st("Internal Header", "bold", colored)
        print("\nGenerating plaintext to be encrypted:\n")
        print(
            f"Generating {internal_header_str}, consisting of server {salt_str} and {session_id_str}\n")

        wait_input(instant)
        print(f"{salt_str}:\n64 bits, randomly generated by the server, changes every 30 minutes")
        print(printable_message.salt_str)



        wait_input(instant)
        print(colored_st(f"\n{session_id_str}:\n", "bold",
                         colored) + "64 bits, generated by client at random, lasts for the entire session")
        print(printable_message.session_id_str)

        print(f"\n{internal_header_str}: {salt_str} + {session_id_str}")
        print(printable_message.salt_str + printable_message.session_id_str)

        unix_s_str = colored_st("unix_s", "unix_s", colored)
        unix_ns_str = colored_st("unix_ns", "unix_ns", colored)
        message_id_str = colored_st("m", "additive", colored) + colored_st("essa", "unix_ns", colored) + colored_st("ge_id", "unix_s", colored)
        message_seq_no_str = colored_st("message_seq_no", "seq_no", colored)
        message_data_len_str = colored_st("message_data_length", "data_length", colored)
        message_data_str = colored_st("message_data", "message_data", colored)
        padding_str = colored_st("padding", "padding", colored)
        plaintext_str = (colored_st("P", "salt", colored) + colored_st("l", "session_id", colored) + colored_st("a", "unix_s", colored)
                         # + colored_str("i","unix_ns",colored) + colored_str("n","data_length",colored)
                         + colored_st("int", "message_data", colored) + colored_st("ext", "padding", colored))
        aes_key_str = colored_st("ae", "sha_256_a", colored) + colored_st("s_k", "sha_256_b", colored) + colored_st(
            "ey", "sha_256_a", colored)
        aes_iv_str = colored_st("ae", "sha_256_b", colored) + colored_st("s_", "sha_256_a", colored) + colored_st(
            "iv", "sha_256_b", colored)
        auth_key_str = colored_st("aut", "auth_key_sha_a", colored) + colored_st("h_k", "auth_key_sha_b",
                                                                                 colored) + colored_st("ey",
                                                                                                          "auth_key_msg_key",
                                                                                                       colored)
        auth_key_fragment_msg_str = colored_st("auth_key_fragment_msg", "auth_key_msg_key", colored)
        x_str = colored_st("x", "x", colored)
        auth_key_fragment_a_str = colored_st("auth_key_fragment_a", "auth_key_sha_a", colored)
        auth_key_fragment_b_str = colored_st("auth_key_fragment_b", "auth_key_sha_b", colored)
        msg_key_large_str = colored_st("msg_key", "msg_key", colored) + colored_st("_large", "unused", colored)
        msg_key_str = colored_st("msg_key", "msg_key", colored)
        sha_256_a_str = colored_st("sha_256_a", "sha_256_a", colored)
        sha_256_b_str = colored_st("sha_256_b", "sha_256_b", colored)
        auth_key_id_str = colored_st("auth_key_id", "auth_key_id", colored)
        ciphertext_str = colored_st("ciphertext", "ciphertext", colored)

        wait_input(instant)
        print(
            f"\ngenerating {plaintext_str}, consisting of {message_id_str}, {message_seq_no_str}, {message_data_len_str}, {message_data_str} and {padding_str}")

        wait_input(instant)
        print(f"\ngenerating {message_id_str}:\n64 bit (little endian), 32 higher order bits are the unix time in seconds ({unix_s_str}). 32 lower order bits are nanoseconds since last second ({unix_ns_str}). \nSince {unix_s_str} + {unix_ns_str} % 4 = {self.msg_time % 4} and message type is {self.msg_type}, {printable_message.additive_str} was added so that {message_id_str} % 4 = {self.modulo} ")

        wait_input(instant)
        print(f"\n{unix_s_str}: ")
        print(printable_message.unix_s_str)

        wait_input(instant)
        print(f"\n{unix_ns_str}: ")
        print(printable_message.unix_ns_str)

        wait_input(instant)
        print(f"\n{message_id_str}: ")
        print(printable_message.message_id_str)

        wait_input(instant)
        print(f"\n{message_seq_no_str}: \n32 bit (little endian), message sequence number. Equal to 2n + 1 where n is the number of content related messages sent in the current session prior to this one.")
        print(printable_message.msg_seq_no_str)

        wait_input(instant)
        print(f"\n{message_data_len_str}: \n32 bit (little endian), length of actual data")
        print(printable_message.data_length_str)

        wait_input(instant)
        print(f"\n{message_data_str}:\nvariable length ({len(self.message_data_plaintext)} in this instance), actual message contents")
        print(printable_message.message_data_str)

        wait_input(instant)
        print(f"\n{padding_str}:\n12 to 1024 Bytes ({len(self.padding)} in this instance), random length, random contents")
        print(printable_message.padding_str)

        wait_input(instant)
        print(f"\nassembled {plaintext_str}: \n{salt_str} + {session_id_str} + {message_id_str} + {message_seq_no_str} + {message_data_len_str} + {message_data_str} + {padding_str}")
        print(printable_message.plaintext_str)

        wait_input(instant)

        print(
            f"\nGenerating AES IGE {aes_key_str} and {aes_iv_str} from {auth_key_str} and {plaintext_str}:")
        wait_input(instant)
        print(
            f"\n{auth_key_str}:\n2048 bit, exchanged through Diffie-Hellman when logging into a new device, known to client device and server. A single user can have multiple auth_keys, one for each device where they are logged in. Once obtained, it is never changed."
            f"\nBytes 0..7, 44..47 and 88..95 are unused in server to client communications {" (this case)" if "client" not in self.msg_type else ""}"
            f"\nBytes 36..39, 76..83 and 120..127 are unused in client to server communications {" (this case)" if "client" in self.msg_type else ""}"
            f"\nBytes 84..87 and 128..255 are never involved in the computation of aes_key and aes_iv, and may only be used for encryption on local data on device."
            f"\nAll the remaining bytes are used on both directions of communication")


        print(printable_message.colored_auth_key_str)

        wait_input(instant)
        print(f"\n{x_str}:\n{x_str} = 0 on client to server messages, {x_str} = 8 on server to client messages. In this instance, {x_str} = {self.x}")

        wait_input(instant)
        print(
            f"\npre-hashed {msg_key_large_str}:\n{auth_key_fragment_msg_str} + {plaintext_str}, where {auth_key_fragment_msg_str} is the 32 bytes of {auth_key_str} starting from byte 88 + {x_str} ({88 + self.x})")
        print(printable_message.colored_auth_key_msg + printable_message.plaintext_str)

        wait_input(instant)
        print(f"\n{msg_key_large_str}:\nsha-256 of {auth_key_fragment_msg_str} + {plaintext_str}")
        print(printable_message.colored_msg_key_large)

        wait_input(instant)
        print(
            f"\n{msg_key_str}: \nmiddle 16 bytes of {msg_key_large_str}, the rest is unused")
        print(printable_message.colored_msg_key)

        wait_input(instant)
        print(
            f"{colored_st("\npre-hashed sha_256_a: \n", "bold", colored)}{msg_key_str} + {auth_key_fragment_a_str}, where {auth_key_fragment_a_str} is the 36 bytes of {auth_key_str} starting from byte {x_str} ({self.x})")
        print(printable_message.colored_auth_key_sha_a + printable_message.colored_msg_key)

        wait_input(instant)
        print(f"\n{sha_256_a_str}:\nsha-256 of {auth_key_fragment_a_str} + {msg_key_str}")
        print(printable_message.colored_sha_256_a)

        wait_input(instant)
        print(
            f"{colored_st("\npre-hashed sha_256_b: \n", "bold", colored)}{auth_key_fragment_b_str} + {msg_key_str}, where {auth_key_fragment_b_str} is the 36 bytes of {auth_key_str} starting from byte 40 + {x_str} ({40 + self.x})")
        print(printable_message.colored_msg_key + printable_message.colored_auth_key_sha_b)

        wait_input(instant)
        print(f"\n{sha_256_b_str}:\nsha-256 of {msg_key_str} + {auth_key_fragment_b_str}")
        print(printable_message.colored_sha_256_b)

        wait_input(instant)
        print(
            f"\n{aes_key_str}:\nBytes 0..7 of {sha_256_a_str} + bytes 8..23 of {sha_256_b_str} + bytes 24..31 of {sha_256_a_str}")
        print(printable_message.colored_aes_key)

        wait_input(instant)
        print(
            f"\n{aes_iv_str}:\nBytes 0..7 of {sha_256_b_str} + bytes 8..23 of {sha_256_a_str} + bytes 24..31 of {sha_256_b_str}")
        print(printable_message.colored_aes_iv)

        wait_input(instant)
        print("Generating external header")

        wait_input(instant)
        print(f"\n 64 lower-order bits of the {auth_key_id_str}:\nSHA-1 of {auth_key_str} (8 bytes)")
        print(printable_message.colored_auth_key_id)

        wait_input(instant)
        print(
            f"\n{colored_st("external header: ", "bold", colored)}\n{auth_key_id_str} + {msg_key_str}\nsent in clear text\n{auth_key_id_str} is needed to identify the {auth_key_str} for decryption, {msg_key_str} is needed to compute {aes_key_str} and {aes_iv_str}")
        print(printable_message.colored_auth_key_id + printable_message.colored_msg_key)

        wait_input(instant)
        print(
            f"\n{ciphertext_str}:\nAES Infinite Garble Mode (IGE) of {plaintext_str} (zero padded to be of a multiple of 16 bytes long), encrypted using {aes_key_str} and {aes_iv_str}")
        print(printable_message.colored_ciphertext)

        wait_input(instant)
        print(f"\n{colored_st("TCP payload: ", "bold", colored)}\nexternal header ({auth_key_id_str} + {msg_key_str}) + {ciphertext_str}")
        print(printable_message.colored_auth_key_id + printable_message.colored_msg_key + printable_message.colored_ciphertext)

        wait_input(instant)
        print("\nAdding abridged transport header:")
        print(
            f"\n{colored_st("Abridged Transport header: ", "bold", colored)}\nTCP payload length divided by 4 if it is less than 127 (0x7f), encoded as 1 byte; otherwise the byte 0x7f followed by TCP payload length divided by 4, encoded as 3 bytes.")
        print(f"In this instance, length of TCP payload divided by 4 is {len(self.tcp_payload)} / 4 = {int(len(self.tcp_payload) / 4)}")
        print(printable_message.transport_header_str)

        wait_input(instant)
        print("Abridged transport header + TCP payload")

        print(f"{printable_message.transport_header_str + printable_message.colored_auth_key_id + printable_message.colored_msg_key + printable_message.colored_ciphertext}")
        print()
        print("Message encrypted")
        print("---------------------------------------------------------------")
        print()
        print()

    def print_message_decryption(self, colored: bool, instant: bool):
        salt_str = colored_st("salt", "salt", colored)
        session_id_str = colored_st("session_id", "session_id", colored)
        # internal_header_str = colored_str("internal ", "salt", colored) + colored_str("header", "session_id", colored)
        internal_header_str = colored_st("Internal Header", "bold", colored)
        unix_s_str = colored_st("unix_s", "unix_s", colored)
        unix_ns_str = colored_st("unix_ns", "unix_ns", colored)
        message_id_str = colored_st("m", "additive", colored) + colored_st("essa", "unix_ns", colored) + colored_st(
            "ge_id", "unix_s", colored)

        message_seq_no_str = colored_st("message_seq_no", "seq_no", colored)
        message_data_len_str = colored_st("message_data_length", "data_length", colored)
        message_data_str = colored_st("message_data", "message_data", colored)
        padding_str = colored_st("padding", "padding", colored)
        plaintext_str = (colored_st("P", "salt", colored) + colored_st("l", "session_id", colored) + colored_st("a",
                                                                                                                "unix_s",
                                                                                                                colored)
                         # + colored_str("i","unix_ns",colored) + colored_str("n","data_length",colored)
                         + colored_st("int", "message_data", colored) + colored_st("ext", "padding", colored))
        aes_key_str = colored_st("ae", "sha_256_a", colored) + colored_st("s_k", "sha_256_b", colored) + colored_st(
            "ey", "sha_256_a", colored)
        aes_iv_str = colored_st("ae", "sha_256_b", colored) + colored_st("s_", "sha_256_a", colored) + colored_st(
            "iv", "sha_256_b", colored)
        auth_key_str = colored_st("aut", "auth_key_sha_a", colored) + colored_st("h_k", "auth_key_sha_b",
                                                                                 colored) + colored_st("ey",
                                                                                                       "auth_key_msg_key",
                                                                                                       colored)
        auth_key_fragment_msg_str = colored_st("auth_key_fragment_msg", "auth_key_msg_key", colored)
        x_str = colored_st("x", "x", colored)
        auth_key_fragment_a_str = colored_st("auth_key_fragment_a", "auth_key_sha_a", colored)
        auth_key_fragment_b_str = colored_st("auth_key_fragment_b", "auth_key_sha_b", colored)
        msg_key_large_str = colored_st("msg_key", "msg_key", colored) + colored_st("_large", "unused", colored)
        msg_key_str = colored_st("msg_key", "msg_key", colored)
        sha_256_a_str = colored_st("sha_256_a", "sha_256_a", colored)
        sha_256_b_str = colored_st("sha_256_b", "sha_256_b", colored)
        auth_key_id_str = colored_st("auth_key_id", "auth_key_id", colored)
        ciphertext_str = colored_st("ciphertext", "ciphertext", colored)
        printable_message = PrintableBytesMessage(self, colored)
        print(f"\nGenerating {plaintext_str} from external headeer ({auth_key_id_str} + {msg_key_str}) + {ciphertext_str}:\n")
        wait_input(instant)
        print("Abridged transport header + TCP payload")
        print(
            f"{printable_message.transport_header_str + printable_message.colored_auth_key_id + printable_message.colored_msg_key + printable_message.colored_ciphertext}")
        wait_input(instant)
        print(f"Abridged transport header:")
        print(printable_message.transport_header_str)
        if self.abridged_transport_header[0] == 0x7f :

            print(f"Since the first byte of Abridged Transport Layer is 0x7f, the length of the TCP payload is 4 times the number encoded in the next 3 bytes of the header. So lenght = 4 * {bytes_to_int(self.abridged_transport_header[1:])} = {len(self.tcp_payload)}")
        print(f"{colored_st("\nTCP payload: ", "bold", colored)}\nexternal header ({auth_key_id_str} + {msg_key_str}) + {ciphertext_str} (after removing Abridged transport header)")
        print(
            printable_message.colored_auth_key_id + printable_message.colored_msg_key + printable_message.colored_ciphertext)

        wait_input(instant)
        print(
            f"{colored_st("\nexternal header: ", "bold", colored)}\n{auth_key_id_str} + {msg_key_str}\nsent in clear text\n{auth_key_id_str} is needed to identify the {auth_key_str} for decryption, {msg_key_str} is needed to compute {aes_key_str} and {aes_iv_str}")
        print(printable_message.colored_auth_key_id + printable_message.colored_msg_key)

        wait_input(instant)
        print(
            f"\n{ciphertext_str}\nAES Infinite Garble Mode (IGE) of plaintext (zero padded to be of a multiple of 16 bytes long)")
        print(printable_message.colored_ciphertext)

        print(
            f"{auth_key_str}2048 bit, exchanged through Diffie-Hellman when logging into a new device, known to client device and server. A single user can have multiple auth_keys, one for each device where they are logged in. Once obtained, it is never changed."
            f"\nBytes 0..7, 44..47 and 88..95 are unused in server to client communications {" (this case)" if "client" not in self.msg_type else ""}"
            f"\nBytes 36..39, 76..83 and 120..127 are unused in client to server communications {" (this case)" if "client" in self.msg_type else ""}"
            f"\nBytes 84..87 and 128..255 are never involved in the computation of aes_key and aes_iv, and may only be used for encryption on local data on device."
            f"\nAll the remaining bytes are used on both directions of communication")

        print(printable_message.colored_auth_key_str)

        print(f"\n{x_str}:\n{x_str} = 0 on client to server messages, {x_str} = 8 on server to client messages. In this instance, {x_str} = {self.x}")

        wait_input(instant)
        print(
            f"{colored_st("\npre-hashed sha_256_a: \n", "bold", colored)} {msg_key_str} + {auth_key_fragment_a_str}, where {auth_key_fragment_a_str} is the 36 bytes of {auth_key_str} starting from byte {x_str} ({self.x})")
        print(printable_message.colored_auth_key_sha_a + printable_message.colored_msg_key)

        wait_input(instant)
        print(f"\n{sha_256_a_str}\nsha-256 of {auth_key_fragment_a_str} + {msg_key_str}")
        print(printable_message.colored_sha_256_a)

        wait_input(instant)
        print(
            f"{colored_st("\npre-hashed sha_256_b: \n", "bold", colored)} {auth_key_fragment_b_str} + {msg_key_str}, where {auth_key_fragment_b_str} is the 36 bytes of {auth_key_str} starting from byte 40 + {x_str} ({40 + self.x})")
        print(printable_message.colored_msg_key + printable_message.colored_auth_key_sha_b)

        wait_input(instant)
        print(f"\n{sha_256_b_str}\nsha-256 of msg_key + auth_key_fragment_b")
        print(printable_message.colored_sha_256_b)

        wait_input(instant)
        print(
            f"\n{aes_key_str}\nBytes 0..7 of {sha_256_a_str} + bytes 8..23 of {sha_256_b_str} + bytes 24..31 of {sha_256_a_str}")
        print(printable_message.colored_aes_key)

        wait_input(instant)
        print(
            f"\n{aes_iv_str}\nBytes 0..7 of sha_256_b + bytes 8..23 of sha_256_a + bytes 24..31 of sha_256_b")
        print(printable_message.colored_aes_iv)

        wait_input(instant)
        print(f"\n{plaintext_str}\n(decrypted from {ciphertext_str} using AES IGE with computed {aes_key_str} and {aes_iv_str}): \n{salt_str} + {session_id_str} + {message_id_str} + {message_seq_no_str} + {message_data_len_str} + {message_data_str} + {padding_str}")
        print(printable_message.plaintext_str)

        wait_input(instant)
        print(f"\nComputing {msg_key_str} again from {plaintext_str} to check it is equal to the one received in the external header")
        wait_input(instant)
        print(f"\n{msg_key_large_str}:\nsha-256 of {auth_key_fragment_msg_str} + {plaintext_str}")
        print(printable_message.colored_check_msg_key_large)

        wait_input(instant)
        print(
            f"\n{msg_key_str}: \nmiddle 16 bytes of {msg_key_large_str}, the rest is unused")
        print(printable_message.colored_check_msg_key)
        wait_input(instant)
        if printable_message.colored_check_msg_key == printable_message.colored_msg_key:
            print(f"{msg_key_str} computed again from {plaintext_str} and {msg_key_str} received in external header match, security check is passed")
        else:
            print(f"{msg_key_str} computed again from {plaintext_str} and {msg_key_str} received in external header do not match, security check is failed. Decryption is aborted")
        print()
        wait_input(instant)
        print(f"Time of the message (epoch time {unix_s_str} taken from 32 higher order bits of {message_id_str}, little endian):")
        time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(self.unix_s ))
        print(colored_st(time_str, "unix_s", colored))
        wait_input(instant)

        print("Message decrypted")
        print("---------------------------------------------------------------")
        print()
        print()

    def remove_trailing_zeros(self):
        while self.plaintext[-1] == 0x00:
            self.plaintext = self.plaintext[:-1]

    def get_decrypted_data(self):
        return self.message_data_plaintext

    def get_encrypted_data(self):
        return self.complete_bytes_ciphertext


class PrintableBytesMessage:
    def __init__(self, message: TGMessage, colored):
        self.message = message
        self.salt_str = colored_st(to_hex_str(self.message.session.salt), "salt", colored)
        self.session_id_str = colored_st(to_hex_str(self.message.session.session_id), "session_id", colored)
        self.additive_str = colored_st(str(self.message.additive), "additive", colored)
        self.unix_s_str = colored_st(to_hex_str(to_bytes(self.message.unix_s, 4, little=True)), "unix_s", colored)
        self.unix_ns_str = colored_st(to_hex_str(to_bytes(self.message.unix_ns, 4, little=True)), "unix_ns", colored)
        hex_msg_id = to_hex_str(self.message.message_id)
        self.message_id_str = (
                                colored_st(str(hex_msg_id[0]), "unix_ns", colored) +
                                colored_st(str(hex_msg_id[1]), "additive", colored) +
                                colored_st(str(hex_msg_id[2:12]), "unix_ns", colored) +
                                self.unix_s_str
                                )
        self.msg_seq_no_str = colored_st(to_hex_str(self.message.seqNo), "seq_no", colored)
        self.data_length_str = colored_st(to_hex_str(to_bytes(self.message.data_length, length=4, little=True)), "data_length", colored)
        self.message_data_str = colored_st(to_hex_str(self.message.message_data_plaintext), "message_data", colored)
        self.padding_str = colored_st(to_hex_str(self.message.padding), "padding", colored)

        self.plaintext_str = self.salt_str + self.session_id_str + self.message_id_str + self.msg_seq_no_str + self.data_length_str + self.message_data_str + self.padding_str
        self.auth_key_str = to_hex_str(self.message.session.auth_key)
        self.colored_auth_key_msg = colored_st(to_hex_str(self.message.auth_key_fragment_msg_key), "auth_key_msg_key",
                                               colored)
        self.colored_auth_key_sha_a = colored_st(to_hex_str(self.message.auth_key_fragment_sha_a), "auth_key_sha_a",
                                                 colored)
        self.colored_auth_key_sha_b = colored_st(to_hex_str(self.message.auth_key_fragment_sha_b), "auth_key_sha_b",
                                                 colored)
        self.colored_auth_key_str = (
                colored_st(self.auth_key_str[: 3 * self.message.auth_key_fragment_sha_a_start], "unused", colored)
                + self.colored_auth_key_sha_a
                + colored_st(
            self.auth_key_str[
                3 * self.message.auth_key_fragment_sha_a_end: 3 * self.message.auth_key_fragment_sha_b_start],
            "unused", colored)
                + self.colored_auth_key_sha_b
                + colored_st(
            self.auth_key_str[
                3 * self.message.auth_key_fragment_sha_b_end: 3 * self.message.auth_key_fragment_msg_key_start],
            "unused",
            colored)
                + self.colored_auth_key_msg
                + colored_st(self.auth_key_str[3 * self.message.auth_key_fragment_msg_key_end:], "unused", colored)
        )
        self.colored_msg_key = colored_st(to_hex_str(self.message.msg_key), "msg_key", colored)
        self.colored_msg_key_large = colored_st(to_hex_str(self.message.msg_key_large[:8]), "unused",
                                                colored) + colored_st(to_hex_str(self.message.msg_key_large[8:24]), "msg_key", colored)+ colored_st(
            to_hex_str(self.message.msg_key_large[24:]),
            "unused", colored)
        self.colored_check_msg_key = colored_st(to_hex_str(self.message.check_msg_key), "msg_key", colored)
        self.colored_check_msg_key_large = colored_st(to_hex_str(self.message.check_msg_key_large[:8]), "unused",
                                                      colored) + colored_st(to_hex_str(self.message.check_msg_key_large[8:24]), "msg_key", colored)+ colored_st(
            to_hex_str(self.message.msg_key_large[24:]),
            "unused", colored)
        self.colored_sha_256_a = colored_st(to_hex_str(self.message.sha_256_a), "sha_256_a", colored)
        self.colored_sha_256_b = colored_st(to_hex_str(self.message.sha_256_b), "sha_256_b", colored)
        self.colored_aes_key = colored_st(to_hex_str(self.message.aes_key[:8]), "sha_256_a", colored) + colored_st(
            to_hex_str(self.message.aes_key[8:24]), "sha_256_b", colored) + colored_st(
            to_hex_str(self.message.aes_key[24:]),
            "sha_256_a", colored)
        self.colored_aes_iv = colored_st(to_hex_str(self.message.aes_iv[:8]), "sha_256_b", colored) + colored_st(
            to_hex_str(self.message.aes_iv[8:24]), "sha_256_a", colored) + colored_st(
            to_hex_str(self.message.aes_iv[24:]),
            "sha_256_b", colored)
        self.colored_auth_key_id = colored_st(to_hex_str(self.message.received_auth_key_id), "auth_key_id", colored)
        self.colored_ciphertext = colored_st(to_hex_str(self.message.ciphertext), "ciphertext", colored)

        if len(self.message.abridged_transport_header) == 1:
            self.transport_header_str = colored_st(to_hex_str(self.message.abridged_transport_header),
                                                   "abridged_transport_header_length", colored)
        else:
            self.transport_header_str = colored_st(to_hex_str(self.message.abridged_transport_header[:1]),
                                                   "abridged_transport_code", colored) + colored_st(
                to_hex_str(self.message.abridged_transport_header[1:]), "abridged_transport_header_length", colored)


class MsgCheckFailedException(Exception):
    pass