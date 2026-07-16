from src.utils import *
salt_bytes = 8
import os

import hashlib

from utils import to_hex_str, colored_st, bytes_to_int, rand_bytes
from tgnet import Tgnet

session_id_bytes = 8

class MtprotoSession:
    NULL_AUTH_KEY_ID = bytearray.fromhex("0000000000000000")
    REQ_DH_PARAMS_CODE = "bee412d7"
    def __init__(self, auth_key, fetch=False):
        self.salt = rand_bytes(8) # mocked, they are given by the server

        if len(auth_key) == len(self.NULL_AUTH_KEY_ID):
            if auth_key == self.NULL_AUTH_KEY_ID:
                self.auth_key = bytearray(bytes(256))
                self.auth_key_id = auth_key
            elif fetch:
                self.auth_key_id = auth_key
                self.auth_key = self.fetch_auth_key(auth_key,'/home/franc/Desktop/tgnets/')
            else:
                self.auth_key_id = bytearray(auth_key)
                self.auth_key = bytearray.fromhex(load_user_data_server(auth_key_id=auth_key)["auth_key"])
        else:
            self.auth_key = auth_key
            self.auth_key_id = bytearray(hashlib.sha1(auth_key).digest())[12:]
        self.session_id = rand_bytes(session_id_bytes)
        # self.auth_key_id = hashlib.sha1(self.auth_key).digest()

        self.n_content_related = 0

    def new_salt(self):
        self.salt = rand_bytes(salt_bytes) # mocked, they are requested and given by the server

    def get_header_Bytes(self):
        return self.salt + self.session_id

    def fetch_auth_key(self,auth_key_id, directory):
        for entry in os.scandir(directory):  # loop through files in the current directory
            if ".dat" in entry.name:
                tg = Tgnet(str(entry.path))
                dc = tg.get_current_datacenter()
                key_temp = dc.get_auth_key_temp()
                # key_perm = dc.get_auth_key_perm()
                # key_media = dc.get_auth_key_media_temp()
                # print(key_temp.hex())
                computed_auth_key_id = bytearray(hashlib.sha1(bytes.fromhex(key_temp.hex())).digest())[12:]
                if to_hex_str(auth_key_id) == to_hex_str(computed_auth_key_id):
                    # print("key extracted from ", entry.name)
                    return key_temp
        print("ERROR: No suitable auth_key found in tgnet files")
        raise Exception
                # print(to_hex_str(auth_key_id))