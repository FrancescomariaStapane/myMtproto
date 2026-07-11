from Crypto.Cipher import AES
from Crypto.Util import Counter

import TGMessage
from MtprotoSession import MtprotoSession
import utils
from TGMessage import TGMessage
from utils import to_hex_str
from tgnet import Tgnet




with open("outgoing", "rb") as file:
    obfuscated_outgoing_traffic = (bytes.fromhex(file.read().decode()))
with open("incoming", "rb") as file:
    obfuscated_incoming_traffic = (bytes.fromhex(file.read().decode()))

init = obfuscated_outgoing_traffic[8:56]
obf_enc_key = init[:32]
obf_enc_iv  = init[32:]
obf_enc_ivInt = int.from_bytes(obf_enc_iv, 'big')

obf_dec_key = init[::-1][:32]
obf_dec_iv  = init[::-1][32:]
obf_dec_ivInt = int.from_bytes(obf_dec_iv, 'big')

counter_tag = Counter.new(128, initial_value=obf_enc_ivInt)
cipher_tag = AES.new(obf_enc_key, AES.MODE_CTR, counter=counter_tag)

tag = cipher_tag.decrypt(obfuscated_outgoing_traffic)[56:64]
print("tag:", tag.hex())


counter_obf_enc = Counter.new(128, initial_value=obf_enc_ivInt + 4)  # skip 4 blocks already consumed
cipher_obf_enc = AES.new(obf_enc_key, AES.MODE_CTR, counter=counter_obf_enc)
deobfuscated_outgoing_traffic = cipher_obf_enc.decrypt(obfuscated_outgoing_traffic[64:])

counter_obf_dec = Counter.new(128, initial_value=obf_dec_ivInt)
cipher_obf_dec = AES.new(obf_dec_key, AES.MODE_CTR, counter=counter_obf_dec)
deobfuscated_incoming_traffic = cipher_obf_dec.decrypt(obfuscated_incoming_traffic)
tg = Tgnet('/home/franc/Desktop/tgnet.dat')
dc = tg.get_current_datacenter()
auth_key = dc.get_auth_key_temp()

deobfuscated_outgoing_bytes = bytearray(bytes.fromhex(utils.to_hex_str(deobfuscated_outgoing_traffic, False)))
deobfuscated_incoming_bytes = bytearray(bytes.fromhex(utils.to_hex_str(deobfuscated_incoming_traffic, False)))
session = MtprotoSession(auth_key)
obfuscated_outgoing_traffic = obfuscated_outgoing_traffic[64:] #skipping already analyzed bytes
print(to_hex_str(deobfuscated_outgoing_bytes))
print("OUTGOING TRAFFIC\n")
while len(deobfuscated_outgoing_bytes) > 0:
    message = TGMessage(ciphertext_bytes = deobfuscated_outgoing_bytes, msg_type="client_msg", silent=False, colored=True, instant=True, session=session)
    tcp_len = (len(message.abridged_transport_header) + message.n_bytes_tcp_payload)
    # print(f"Deobfuscated bytes from {to_hex_str(deobfuscated_outgoing_bytes[:4])} to {to_hex_str(deobfuscated_outgoing_bytes[tcp_len -4 : tcp_len])}")
    # print(f"Obfuscated bytes from {to_hex_str(bytearray(obfuscated_outgoing_traffic[:4]), False)} to {to_hex_str(bytearray(obfuscated_outgoing_traffic[tcp_len -4 : tcp_len]), False)}")

    deobfuscated_outgoing_bytes = deobfuscated_outgoing_bytes[tcp_len:]
    obfuscated_outgoing_traffic = obfuscated_outgoing_traffic[tcp_len:]
last_outgoing_message = message
print("\n\nINCOMING TRAFFIC\n")
while len(deobfuscated_incoming_bytes) > 0:
    if deobfuscated_incoming_bytes[0] & 128 == 128:
        deobfuscated_incoming_bytes = deobfuscated_incoming_bytes[4:] # skip quick ack
    message = TGMessage(ciphertext_bytes = deobfuscated_incoming_bytes, msg_type="server_msg", silent=False, colored=True, instant=True, session=session)
    tcp_len = (len(message.abridged_transport_header) + message.n_bytes_tcp_payload)
    # print(f"Deobfuscated bytes from {to_hex_str(deobfuscated_incoming_bytes[:4])} to {to_hex_str(deobfuscated_incoming_bytes[tcp_len -4 : tcp_len])}")
    # print(f"Obfuscated bytes from {to_hex_str(bytearray(obfuscated_incoming_traffic[:4]), False)} to {to_hex_str(bytearray(obfuscated_incoming_traffic[tcp_len -4 : tcp_len]), False)}")

    deobfuscated_incoming_bytes = deobfuscated_incoming_bytes[tcp_len:]
    obfuscated_incoming_traffic = obfuscated_incoming_traffic[tcp_len:]
last_incoming_message = message

last_message = last_outgoing_message if last_outgoing_message.unix_s << 32 + last_outgoing_message.unix_ns > last_incoming_message.unix_s << 32 + last_incoming_message.unix_ns  else last_incoming_message
with open("last_message", "wb") as file:
    file.write(last_message.get_encrypted_data())

print()
