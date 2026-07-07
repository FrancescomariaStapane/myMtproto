import hashlib
import os

from src.utils import *

salt_bytes = 8
session_id_bytes = 8

class MtprotoSession:
    NULL_AUTH_KEY_ID = bytearray.fromhex("0000000000000000000000000000000000000000")
    REQ_DH_PARAMS_CODE = "bee412d7"
    def __init__(self, auth_key):
        self.salt = rand_bytes(8) # mocked, they are given by the server
        if len(auth_key) == 20:
            if auth_key == self.NULL_AUTH_KEY_ID:
                self.auth_key = bytearray(bytes(256))
                self.auth_key_id = auth_key
            else:
                self.auth_key_id = bytearray(auth_key)
                self.auth_key = bytearray.fromhex(load_user_data_server(auth_key_id=auth_key)["auth_key"])
        else:
            self.auth_key = auth_key
            self.auth_key_id = bytearray(hashlib.sha1(auth_key).digest())
        self.session_id = rand_bytes(session_id_bytes)
        # self.auth_key_id = hashlib.sha1(self.auth_key).digest()

        self.n_content_related = 0

    def new_salt(self):
        self.salt = rand_bytes(salt_bytes) # mocked, they are requested and given by the server

    def get_header_Bytes(self):
        return self.salt + self.session_id