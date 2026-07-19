from src.utils import *
salt_bytes = 8
import os

import hashlib
import asyncio
from opentele.td import TDesktop
from opentele.tl import TelegramClient
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
        elif len(auth_key) == 256:
            self.auth_key = auth_key
            self.auth_key_id = bytearray(hashlib.sha1(auth_key).digest())[12:]
        else:
            self.auth_key = None
            self.auth_key_id = auth_key

        self.session_id = rand_bytes(session_id_bytes)
        # self.auth_key_id = hashlib.sha1(self.auth_key).digest()

        self.n_content_related = 0
        if self.auth_key == None:
            print()

    def new_salt(self):
        self.salt = rand_bytes(salt_bytes) # mocked, they are requested and given by the server

    def get_header_Bytes(self):
        return self.salt + self.session_id

    def fetch_auth_key(self,auth_key_id, directory):
        for entry in os.scandir(directory):
            if ".dat" in entry.name:
                tg = Tgnet(str(entry.path))
                dc = tg.get_current_datacenter()
                key_temp = dc.get_auth_key_temp()
                key_perm = dc.get_auth_key_perm()
                # key_media = dc.get_auth_key_media_temp()
                # print(key_temp.hex())
                # print(key_perm.hex())
                computed_temp_auth_key_id = bytearray(hashlib.sha1(bytes.fromhex(key_temp.hex())).digest())[12:]
                computed_perm_auth_key_id = bytearray(hashlib.sha1(bytes.fromhex(key_perm.hex())).digest())[12:]
                # print()
                # print(entry.name)
                # print("temp auth key id:")
                # print(to_hex_str(computed_temp_auth_key_id))
                # print("perm auth key id:")
                # print(to_hex_str(computed_perm_auth_key_id))

                if to_hex_str(auth_key_id) == to_hex_str(computed_temp_auth_key_id):
                    self.key_name = entry.name
                    # print("key extracted from ", entry.name)
                    return key_temp
            # if "tdata" in entry.name:
            #     tdesk = TDesktop(entry.path)
            #     if not tdesk.isLoaded():
            #         print("Failed to load tdata")
            #         return
            #
            #         # Get the first/main account
            #     account = tdesk.accounts[1]
            #     auth_key = account.localKey.key if account.authKey else None
            #     computed_auth_key_id = bytearray(hashlib.sha1(bytes.fromhex(auth_key.hex())).digest())[12:]
            #
            #     if to_hex_str(auth_key_id) == to_hex_str(computed_auth_key_id):
            #         self.key_name = entry.name
            #         print("key extracted from ", entry.name)
            #         return auth_key
            #     try:
            #         # This may contain temporary keys depending on the library version
            #         if hasattr(account, 'mtp') and account.mtp:
            #             for i, key in enumerate(account.mtp.keys):
            #                 key_type = "Temporary" if getattr(key, 'type', None) == 2 else "Other"
            #                 print(f"Key {i} ({key_type}, DC {getattr(key, 'dcId', '?')}):")
            #                 print(key.key.hex()[:80] + "..." if key.key else "None")
            #     except Exception as e:
            #         print("Could not extract temp keys from mtp:", e)


        # raise KeyNotFoundException("ERROR: No suitable auth_key found in tgnet files")
                # print(to_hex_str(auth_key_id))

class KeyNotFoundException(Exception):
    pass