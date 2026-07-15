import getpass
import random
import json
import os, re, sys, termios, tty
import tgcrypto
from telethon.tl.functions.messages import SendMessageRequest
from telethon.tl import types, functions
# from telethon.tl.types import InputPeerUser
from telethon import utils

def to_bytes(n: int, length = -1, little = False) -> bytes:
    length = length if length > 0 else (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'little') if little else n.to_bytes(length, 'big')

def bytes_to_int(b: bytes, little=False):
    return int.from_bytes(b, 'little') if little else  int.from_bytes(b, 'big')

def to_hex_str(arr: bytes, spaces = True) -> str:
    s = arr.hex()
    if not spaces:
        return s
    spaced_str = ""
    for i in range(0, len(s), 2):
        spaced_str = spaced_str + s[i:i+2] + " "
    return spaced_str

def rand_bytes(n:int) -> bytes:
    testing = True
    if testing:
        return bytes(random.getrandbits(8) for _ in range(n))
    return os.urandom(n)


def get_ansi(content: str, colored: bool) -> str:
    if not colored: return ""
    if content == "close": return "\x1b[0m"
    if content == "salt": return "\x1b[1;38;5;1;49m"
    if content == "session_id": return "\x1b[1;38;5;12;49m"
    if content == "unix_s": return "\x1b[1;38;5;13;49m"
    if content == "unix_ns": return "\x1b[1;38;5;14;49m"
    if content == "additive": return "\x1b[1;38;5;172;49m"
    if content == "bold" : return "\x1b[1;39;49m"
    if content == "italic" : return "\x1b[3m"
    if content == "seq_no" : return "\x1b[1;38;5;204;49m"
    if content == "data_length" : return "\x1b[1;38;5;223;49m"
    if content == "message_data" : return "\x1b[1;38;5;220;49m"
    if content == "padding" : return "\x1b[0;38;5;117;49m"
    if content == "auth_key_sha_a" : return "\x1b[1;38;5;202;49m"
    if content == "auth_key_sha_b" : return "\x1b[1;38;5;140;49m"
    if content == "auth_key_msg_key" : return "\x1b[1;38;5;34;49m"
    if content == "x" : return "\x1b[1;38;5;210;49m"
    if content == "unused" : return "\x1b[0;38;5;244;49m"
    if content == "msg_key" : return "\x1b[1;38;5;48;49m"
    if content == "sha_256_a" : return "\x1b[1;38;5;200;49m"
    if content == "sha_256_b" : return "\x1b[1;38;5;20;49m"
    if content == "ciphertext" : return "\x1b[1;38;5;228;49m"
    if content == "auth_key_id" : return "\x1b[1;38;5;204;49m"
    if content == "abridged_transport_code" : return "\x1b[1;38;5;87;49m"
    if content == "abridged_transport_header_length" : return "\x1b[1;38;5;202;49m"
    return ""

def colored_st(s:str, content_type: str, colored: bool) -> str:
    return get_ansi(content_type, colored)+ s + get_ansi("close",colored)


def load_user_data_server(auth_key_id: bytearray = None, user_id: str = None):
    if auth_key_id is not None:
        with open('users.json', 'r') as file:
            users = json.load(file)
            if str(auth_key_id.hex()) not in users.keys():
                return None
            user = users[str(auth_key_id.hex())]
            return  user
    elif user_id is not None:
        with open('users_reverse.json', 'r') as file:
            users = json.load(file)
            if str(user_id) not in users:
                return None
            user = users[str(user_id)]
            return user
    raise Exception




def wait_input(instant):
    if not instant: getpass.getpass("")


def extract_protocol_bytes(obf_enc_bytes : bytes):
    # deobfuscator:
    # obf_enc_bytes in input (64 bytes)
    enc_key = obf_enc_bytes[8:40]
    enc_iv = obf_enc_bytes[40:56]
    encrypted_init = tgcrypto.ctr256_encrypt(obf_enc_bytes[:56], enc_key, enc_iv, bytes(1)) + obf_enc_bytes[56:]
    dec_key = obf_enc_bytes[::-1][8:40]
    dec_iv = obf_enc_bytes[::-1][40:56]
    decrypted_init = tgcrypto.ctr256_decrypt( encrypted_init, dec_key, dec_iv, bytes(1))
    protocol_bytes = decrypted_init[56:]
    return protocol_bytes




# def save_cursor_pos():
#     return "\x1b[s"
#
# def return_to_saved_cursor_pos():
#     return "\x1b[u"
#
# def jump_cursor(x, y):# move cursor up <up> lines and <right> positions from start of line
#     return f"\x1b[{y};{x}H"
#
# def rewrite_terminal(x,y, text):
#     print(save_cursor_pos(), end = '')
#     print(jump_cursor(x,y), end = '')
#     print(text, end = '')
#     print(return_to_saved_cursor_pos(),end = '')
#
#
# def getpos():
#
#     buf = ""
#     stdin = sys.stdin.fileno()
#     tattr = termios.tcgetattr(stdin)
#
#     try:
#         tty.setcbreak(stdin, termios.TCSANOW)
#         sys.stdout.write("\x1b[6n")
#         sys.stdout.flush()
#
#         while True:
#             buf += sys.stdin.read(1)
#             if buf[-1] == "R":
#                 break
#
#     finally:
#         termios.tcsetattr(stdin, termios.TCSANOW, tattr)
#
#     # reading the actual values, but what if a keystroke appears while reading
#     # from stdin? As dirty work around, getpos() returns if this fails: None
#     try:
#         matches = re.match(r"^\x1b\[(\d*);(\d*)R", buf)
#         groups = matches.groups()
#     except AttributeError:
#         return None
#
#     return int(groups[0]), int(groups[1])

