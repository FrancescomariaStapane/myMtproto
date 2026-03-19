import os

from src.TGMessage import TGMessage


class MTProto_Client():
    def __init__(self, auth_key:bytearray, message: TGMessage):
        self.auth_key = auth_key,
        self.message = message



    def encrypt_message(self, message):
        return message


    def decrypt_message(self, message):
        return message

    def generate_salt(self):
        #todo
        return 0