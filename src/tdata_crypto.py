"""
Core primitives for reading Telegram Desktop's tdata local storage format.

Ported directly from tdesktop source (telegramdesktop/tdesktop):
  - Telegram/SourceFiles/storage/details/storage_file_utilities.cpp
  - Telegram/SourceFiles/mtproto/mtproto_auth_key.cpp  (AuthKey::prepareAES_oldmtp)
  - Telegram/SourceFiles/storage/storage_domain.cpp
  - Telegram/SourceFiles/storage/storage_account.cpp

Covers:
  - the "TDF$" file container format (magic + version + MD5 trailer)
  - local_key derivation from passcode+salt (SHA512 -> PBKDF2-HMAC-SHA512)
  - the *old* MTProto 1.0 (SHA1-based) AES-IGE key/iv derivation used for
    ALL local storage encryption (tdesktop never migrated this to MTP 2.0)
  - QDataStream primitive decoding (big-endian ints, length-prefixed
    QByteArray/QString)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

from Crypto.Cipher import AES

TDF_MAGIC = b"TDF$"
LOCAL_ENCRYPT_SALT_SIZE = 32  # bytes
STRONG_ITERATIONS = 100_000


# --------------------------------------------------------------------------
# QDataStream primitive readers (Qt_5_1 stream version -> plain big-endian)
# --------------------------------------------------------------------------

class QStream:
    """Minimal reader mimicking the subset of QDataStream used here."""

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def at_end(self) -> bool:
        return self.pos >= len(self.data)

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("QStream: read past end of buffer")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def read_u32(self) -> int:
        return struct.unpack(">I", self._take(4))[0]

    def read_i32(self) -> int:
        return struct.unpack(">i", self._take(4))[0]

    def read_u64(self) -> int:
        return struct.unpack(">Q", self._take(8))[0]

    def read_bytearray(self) -> bytes:
        length = self.read_u32()
        if length == 0xFFFFFFFF:
            return b""  # null QByteArray
        return self._take(length)

    def read_qstring(self) -> str:
        length = self.read_u32()  # length in bytes of the UTF-16BE payload
        if length == 0xFFFFFFFF:
            return ""  # null QString
        raw = self._take(length)
        return raw.decode("utf-16-be")

    def read_raw(self, n: int) -> bytes:
        return self._take(n)


# --------------------------------------------------------------------------
# Old-MTP (SHA1-based) AES-IGE, used for ALL local storage encryption
# --------------------------------------------------------------------------

def _sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def prepare_aes_oldmtp(auth_key: bytes, msg_key: bytes, send: bool):
    """
    Direct port of AuthKey::prepareAES_oldmtp.
    auth_key: 256 raw bytes (the local_key)
    msg_key: 16 bytes
    send: bool -> x = 0 if send else 8
    Returns (aes_key: 32 bytes, aes_iv: 32 bytes)
    """
    x = 0 if send else 8

    sha1_a = _sha1(msg_key + auth_key[x:x + 32])
    sha1_b = _sha1(auth_key[32 + x:32 + x + 16] + msg_key + auth_key[48 + x:48 + x + 16])
    sha1_c = _sha1(auth_key[64 + x:64 + x + 32] + msg_key)
    sha1_d = _sha1(msg_key + auth_key[96 + x:96 + x + 32])

    aes_key = sha1_a[0:8] + sha1_b[8:20] + sha1_c[4:16]
    aes_iv = sha1_a[8:20] + sha1_b[0:8] + sha1_c[16:20] + sha1_d[0:8]

    assert len(aes_key) == 32 and len(aes_iv) == 32
    return aes_key, aes_iv


def aes_ige_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Standard AES-256-IGE decrypt (same primitive MTProto itself uses)."""
    if len(ciphertext) % 16 != 0:
        raise ValueError("IGE ciphertext must be a multiple of 16 bytes")
    aes = AES.new(key, AES.MODE_ECB)
    iv1, iv2 = iv[:16], iv[16:]
    out = bytearray()
    prev_cipher = iv1
    prev_plain = iv2
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        x = bytes(a ^ b for a, b in zip(block, prev_plain))
        dec = aes.decrypt(x)
        plain = bytes(a ^ b for a, b in zip(dec, prev_cipher))
        out += plain
        prev_cipher = block
        prev_plain = plain
    return bytes(out)


def aes_ige_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Included for completeness / round-trip self-testing."""
    if len(plaintext) % 16 != 0:
        raise ValueError("IGE plaintext must be a multiple of 16 bytes")
    aes = AES.new(key, AES.MODE_ECB)
    iv1, iv2 = iv[:16], iv[16:]
    out = bytearray()
    prev_cipher = iv1
    prev_plain = iv2
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        x = bytes(a ^ b for a, b in zip(block, prev_cipher))
        enc = aes.encrypt(x)
        cipher = bytes(a ^ b for a, b in zip(enc, prev_plain))
        out += cipher
        prev_cipher = cipher
        prev_plain = block
    return bytes(out)


# --------------------------------------------------------------------------
# local_key derivation
# --------------------------------------------------------------------------

def create_local_key(passcode: bytes, salt: bytes) -> bytes:
    """
    Direct port of Storage::details::CreateLocalKey.
    Returns 256 raw bytes (the MTP::AuthKey::Data equivalent).
    """
    sha512_hash = hashlib.sha512(salt + passcode + salt).digest()
    iterations = 1 if len(passcode) == 0 else STRONG_ITERATIONS
    return hashlib.pbkdf2_hmac("sha512", sha512_hash, salt, iterations, dklen=256)


# --------------------------------------------------------------------------
# TDF container format + local decryption
# --------------------------------------------------------------------------

@dataclass
class TdfFile:
    version: int
    data: bytes  # payload after magic/version, before the 16-byte MD5 trailer


def read_tdf(path: str) -> TdfFile:
    """
    Reads a tdata "TDF$" container file (tries the modern 's' suffix first,
    falls back to legacy '0'/'1' pair -- mirrors Storage::details::ReadFile).
    Accepts `path` either WITH or WITHOUT the trailing TDF suffix character
    (e.g. both "key_data" and "key_datas" work).
    """
    import os

    # Be forgiving: if the exact path given already exists as a file
    # (caller included the 's'/'0'/'1' suffix themselves), just use it.
    if os.path.isfile(path):
        candidates = [path]
    elif path and path[-1] in "s01" and os.path.isfile(path[:-1] + "s"):
        # Caller passed a suffixed name but that exact suffix doesn't
        # exist -- strip it and redo the normal lookup below.
        path = path[:-1]
        candidates = []
    else:
        candidates = []

    if not candidates and os.path.exists(path + "s"):
        candidates = [path + "s"]
    elif not candidates:
        c0, c1 = path + "0", path + "1"
        if os.path.exists(c0) and os.path.exists(c1):
            # pick most recently modified first, matching tdesktop's logic
            if os.path.getmtime(c0) < os.path.getmtime(c1):
                candidates = [c1, c0]
            else:
                candidates = [c0, c1]
        elif os.path.exists(c0):
            candidates = [c0]
        elif os.path.exists(c1):
            candidates = [c1]

    if not candidates:
        raise FileNotFoundError(f"No tdata file found at {path}[s|0|1]")

    last_err = None
    for fname in candidates:
        try:
            with open(fname, "rb") as f:
                raw = f.read()
            if raw[:4] != TDF_MAGIC:
                raise ValueError(f"Bad magic in {fname}")
            version = struct.unpack("<i", raw[4:8])[0]  # native (little-endian) qint32
            body_and_sig = raw[8:]
            if len(body_and_sig) < 16:
                raise ValueError(f"Too short: {fname}")
            data, sig = body_and_sig[:-16], body_and_sig[-16:]

            md5 = hashlib.md5()
            md5.update(data)
            md5.update(struct.pack("<i", len(data)))
            md5.update(struct.pack("<i", version))
            md5.update(TDF_MAGIC)
            if md5.digest() != sig:
                raise ValueError(f"MD5 signature mismatch in {fname}")

            return TdfFile(version=version, data=data)
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue
    raise last_err


def decrypt_local(encrypted: bytes, local_key: bytes) -> bytes:
    """
    Direct port of Storage::details::DecryptLocal.
    `encrypted` = 16-byte msg_key + AES-IGE ciphertext.
    Returns the inner payload bytes (QDataStream-decodable), with the
    4-byte length prefix already stripped.
    """
    if len(encrypted) <= 16 or (len(encrypted) & 0x0F):
        raise ValueError(f"Bad encrypted part size: {len(encrypted)}")

    msg_key, ciphertext = encrypted[:16], encrypted[16:]
    aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key, send=False)
    decrypted = aes_ige_decrypt(ciphertext, aes_key, aes_iv)

    check = hashlib.sha1(decrypted).digest()[:16]
    if check != msg_key:
        raise ValueError(
            "SHA1 check failed decrypting local data -- wrong local_key "
            "(wrong passcode?) or corrupted file"
        )

    data_len = struct.unpack("<I", decrypted[:4])[0]  # native (LE) uint32
    if data_len > len(decrypted) or data_len < 4:
        raise ValueError(f"Bad decrypted length: {data_len}")

    return decrypted[4:data_len]


def read_encrypted_tdf(path: str, local_key: bytes) -> bytes:
    """
    Reads a tdata TDF file whose body is itself a single length-prefixed
    QByteArray holding the AES-IGE-encrypted payload (the common case for
    all "keyed" storage files, e.g. search suggestions / recent bots).
    Returns the decrypted, QDataStream-ready payload.
    """
    tdf = read_tdf(path)
    stream = QStream(tdf.data)
    encrypted = stream.read_bytearray()
    return decrypt_local(encrypted, local_key)


if __name__ == "__main__":
    # Self-test: round-trip the crypto primitives with synthetic data,
    # since we don't have real tdata files in this sandbox to test against.
    import os

    local_key = os.urandom(256)
    plaintext_payload = b"hello tdata parser, this is a test payload!"

    # Mimic EncryptedDescriptor + PrepareEncrypted framing.
    size = 4 + len(plaintext_payload)
    body = struct.pack("<I", size) + plaintext_payload
    pad = (-len(body)) % 16
    body += os.urandom(pad)

    msg_key = hashlib.sha1(body).digest()[:16]
    aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key, send=False)
    ciphertext = aes_ige_encrypt(body, aes_key, aes_iv)
    encrypted_blob = msg_key + ciphertext

    recovered = decrypt_local(encrypted_blob, local_key)
    assert recovered == plaintext_payload, f"MISMATCH: {recovered!r} != {plaintext_payload!r}"
    print("Self-test passed: IGE + old-mtp key derivation + framing round-trip OK")

    # Also test create_local_key runs without error and is deterministic.
    k1 = create_local_key(b"", os.urandom(32))
    assert len(k1) == 256
    salt = os.urandom(32)
    k2a = create_local_key(b"mypasscode", salt)
    k2b = create_local_key(b"mypasscode", salt)
    assert k2a == k2b and len(k2a) == 256
    print("Self-test passed: create_local_key deterministic, correct length")