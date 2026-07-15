from AndroidTelePorter import AndroidSession
from AndroidTelePorter.utils.auth_key import calculate_id
from tgnet import Tgnet
import hashlib
from MtprotoSession import MtprotoSession
from utils import to_hex_str, to_bytes
tgs = [Tgnet('/home/franc/Desktop/tgnets/tgnet.dat'),Tgnet('/home/franc/Desktop/tgnets/tgnet1.dat'),Tgnet('/home/franc/Desktop/tgnets/tgnet2.dat'),Tgnet('/home/franc/Desktop/tgnets/tgnet3.dat') ]

for i in range(len(tgs)):
    dc = tgs[i].get_current_datacenter()
    key_temp = dc.get_auth_key_temp()
    key_perm = dc.get_auth_key_perm()
    key_media = dc.get_auth_key_media_temp()
    print()
    print(f"tgnet{i}: Key temp:")
    print("Auth Key:")
    print(key_temp.hex())
    print("auth_key_id:")
    print(to_hex_str(bytearray(hashlib.sha1(bytes.fromhex(key_temp.hex())).digest())[12:]))
    print(f"tgnet{i}: Key perm:")
    print((key_perm.hex()))
    print("auth_key_id perm:")
    print(to_hex_str(bytearray(hashlib.sha1(bytes.fromhex(key_perm.hex())).digest())[12:]))

# print("Data Center ID:", dc.id)
# print()
# print("Auth Key temp:")
# print(key_temp.hex())
# print("auth_key_id temp:")
# print(to_hex_str(bytearray(hashlib.sha1(bytes.fromhex(key_temp.hex())).digest())[12:]))
#
# print()
# print("Auth Key perm:")
# print(key_temp.hex())
# print("auth_key_id perm:")
# print(to_hex_str(bytearray(hashlib.sha1(bytes.fromhex(key_perm.hex())).digest())[12:]))
#
# print()
# print("Auth Key media:")
# print(key_media.hex())
# print("auth_key_id temp:")
# print(to_hex_str(bytearray(hashlib.sha1(bytes.fromhex(key_media.hex())).digest())[12:]))