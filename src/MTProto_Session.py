import hashlib
import os

from src.utils import *

salt_bytes = 8
session_id_bytes = 8

class MTProto_Session:

    def __init__(self, salt, auth_key):
        self.salt = salt
        self.auth_key = auth_key
        self.session_id = rand_bytes(session_id_bytes)
        self.auth_key_id = hashlib.sha1(self.auth_key).digest()

        self.n_content_related = 0

    def new_salt(self):
        self.salt = rand_bytes(salt_bytes)

    def get_header_Bytes(self):
        return self.salt + self.session_id