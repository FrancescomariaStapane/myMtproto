"""
Parses Telegram Desktop's tdata local storage to recover access_hash values
for peers cached locally (self, recent search suggestions, recent inline
bots -- NOT full dialogs/contacts, see caveats below).

Ported directly from tdesktop source:
  - storage/storage_domain.cpp   (top-level key_<name> file -> local_key)
  - storage/storage_account.cpp  (per-account "map" file -> lsk* entries)
  - storage/serialize_peer.cpp   (writePeer/readPeer byte layout)
  - data/data_peer_id.cpp        (PeerId type-bit encoding)

Usage:
    from tdata_crypto import create_local_key
    from tdata_parser import decrypt_domain_key_file, get_access_hash

    # Option A: you already have local_key bytes extracted some other way.
    local_key = bytes.fromhex("...")  # 256 bytes

    # Option B: derive it from the domain "key_" file + your passcode
    # (empty bytes if you never set a passcode in Telegram Desktop).
    local_key = decrypt_domain_key_file("/path/to/tdata/key_s", passcode=b"")

    result = get_access_hash(
        account_base_path="/path/to/tdata/<ACCOUNT_HASH_FOLDER>/",
        local_key=local_key,
        user_id=123456789,
    )
    print(result)

IMPORTANT CAVEATS (read before relying on this):
  1. This only finds peers cached in a handful of specific local caches:
     yourself, ~48 recently opened/searched chats, and recently used
     inline bots. It does NOT contain your full dialog list or contact
     list -- tdesktop re-fetches those from the server each launch rather
     than persisting them wholesale. If your target user_id isn't in one
     of these categories, it genuinely isn't on disk anywhere.
  2. `account_base_path` is the per-account subfolder inside tdata (the one
     containing files named "map*" among others) -- point this at that
     folder directly rather than the top-level tdata/ folder.
  3. The crypto layer (AES-IGE + old-MTP key derivation + TDF framing) has
     been self-tested for internal round-trip consistency in tdata_crypto.py,
     but has NOT been validated against a real tdesktop-produced file in
     this environment (no real tdata was available to test against). Treat
     it as a strong first draft to debug against your own files, not as
     guaranteed-correct without a decrypt succeeding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from tdata_crypto import (
    QStream,
    create_local_key,
    decrypt_local,
    read_encrypted_tdf,
    read_tdf,
)
from utils import twos_comp

# lsk* Local Storage Key enum, from storage_account.cpp
LSK_DRAFT = 0x01
LSK_DRAFT_POSITION = 0x02
LSK_LEGACY_IMAGES = 0x03
LSK_LOCATIONS = 0x04
LSK_LEGACY_STICKER_IMAGES = 0x05
LSK_LEGACY_AUDIOS = 0x06
LSK_RECENT_STICKERS_OLD = 0x07
LSK_BACKGROUND_OLD_OLD = 0x08
LSK_USER_SETTINGS = 0x09
LSK_RECENT_HASHTAGS_AND_BOTS = 0x0A
LSK_STICKERS_OLD = 0x0B
LSK_SAVED_PEERS_OLD = 0x0C
LSK_REPORT_SPAM_STATUSES_OLD = 0x0D
LSK_SAVED_GIFS_OLD = 0x0E
LSK_SAVED_GIFS = 0x0F
LSK_STICKERS_KEYS = 0x10
LSK_TRUSTED_PEERS = 0x11
LSK_FAVED_STICKERS = 0x12
LSK_EXPORT_SETTINGS = 0x13
LSK_BACKGROUND_OLD = 0x14
LSK_SELF_SERIALIZED = 0x15
LSK_MASKS_KEYS = 0x16
LSK_CUSTOM_EMOJI_KEYS = 0x17
LSK_SEARCH_SUGGESTIONS = 0x18
LSK_WEBVIEW_TOKENS = 0x19
LSK_ROUND_PLACEHOLDER = 0x1A
LSK_INLINE_BOTS_DOWNLOADS = 0x1B
LSK_MEDIA_LAST_PLAYBACK_POSITIONS = 0x1C
LSK_BOT_STORAGES = 0x1D
LSK_PREFS = 0x1E

VERSION_TAG = 0x77FF_FFFF_FFFF_FFFF
MODERN_IMAGE_LOCATION_TAG = -2147483648  # qint32 min

PEER_TYPE_USER = 0
PEER_TYPE_CHAT = 1
PEER_TYPE_CHANNEL = 2


def file_key_to_hex(key: int) -> str:
    """Mirrors Storage::details::ToFilePart -- nibble-by-nibble, LSB first."""
    chars = []
    v = key
    for _ in range(16):
        nib = v & 0x0F
        chars.append(chr(ord('0') + nib) if nib < 10 else chr(ord('A') + nib - 10))
        v >>= 4
    return "".join(chars)


# --------------------------------------------------------------------------
# Domain-level key_<name> file -> local_key
# --------------------------------------------------------------------------

def decrypt_domain_key_file(path_without_suffix: str, passcode: bytes = b"") -> bytes:
    """
    Reads the top-level tdata/key_<name> file and recovers the real
    local_key (256 raw bytes) used to encrypt everything else.
    `passcode` is your Telegram Desktop local passcode, empty if unset.
    """
    tdf = read_tdf(path_without_suffix)
    stream = QStream(tdf.data)
    salt = stream.read_bytearray()
    key_encrypted = stream.read_bytearray()
    _info_encrypted = stream.read_bytearray()  # account indices, not needed here

    if len(salt) != 32:
        raise ValueError(f"Unexpected salt size: {len(salt)}")

    passcode_key = create_local_key(passcode, salt)
    inner = decrypt_local(key_encrypted, passcode_key)
    if len(inner) != 256:
        raise ValueError(
            f"Expected 256-byte local_key, got {len(inner)} -- "
            "wrong passcode, or file format mismatch"
        )
    return inner


# --------------------------------------------------------------------------
# Peer (writePeer/readPeer) parsing
# --------------------------------------------------------------------------

@dataclass
class Peer:
    peer_type: int  # PEER_TYPE_*
    bare_id: int
    access_hash: Optional[int] = None
    first_name: str = ""
    last_name: str = ""
    phone: str = ""
    username: str = ""
    name: str = ""  # chat/channel name


def _decode_peer_id(serialized: int):
    reserved_flag = 0x80 << 48
    legacy = not (serialized & reserved_flag)
    if legacy:
        # Legacy format not implemented -- extremely old tdata only.
        raise NotImplementedError("Legacy PeerId serialization not supported")
    value = serialized & ~reserved_flag
    peer_type = (value >> 48) & 0xFF
    bare_id = value & 0xFFFFFFFFFFFF  # 48 bits
    return peer_type, bare_id


def _skip_image_location(stream: QStream) -> None:
    tag = stream.read_i32()
    if tag == MODERN_IMAGE_LOCATION_TAG:
        stream.read_bytearray()  # serialized ImageLocation, unused here
    else:
        raise NotImplementedError(
            "Legacy (non-modern) image location format encountered -- "
            "not implemented, file may be from a very old tdesktop version"
        )


def read_peer(stream: QStream, debug: bool = False) -> Optional[Peer]:
    peer_id_serialized = stream.read_u64()
    version_tag = stream.read_u64()

    if version_tag == VERSION_TAG:
        version = stream.read_i32()
        _photo_id = stream.read_u64()
    else:
        version = 0
        _photo_id = version_tag  # legacy: this field WAS the photo id

    peer_type, bare_id = _decode_peer_id(peer_id_serialized)
    if debug:
        print(f"    [debug] peer_id_serialized={peer_id_serialized:#x} "
              f"version_tag_matched={version_tag == VERSION_TAG} "
              f"version={version} photo_id={_photo_id:#x} "
              f"-> decoded type={peer_type} bare_id={bare_id}")

    _skip_image_location(stream)
    if version > 0:
        _photo_has_video = stream.read_i32()

    peer = Peer(peer_type=peer_type, bare_id=bare_id)

    if peer_type == PEER_TYPE_USER:
        peer.first_name = stream.read_qstring()
        peer.last_name = stream.read_qstring()
        peer.phone = stream.read_qstring()
        peer.username = stream.read_qstring()
        peer.access_hash = stream.read_u64()
        _flags = stream.read_i32()
        _inline_placeholder = stream.read_qstring()
        _lastseen = stream.read_u32()
        _contact = stream.read_i32()
        _bot_info_version = stream.read_i32()
        if version > 2:
            _supports_guest_chat = stream.read_i32()

    elif peer_type == PEER_TYPE_CHAT:
        peer.name = stream.read_qstring()
        _count = stream.read_i32()
        _date = stream.read_i32()
        _chat_version = stream.read_i32()
        _field1 = stream.read_i32()
        _field2 = stream.read_i32()
        _flags = stream.read_u32()
        _invite_link = stream.read_qstring()
        # Chats don't carry an access_hash in Telegram's model.

    elif peer_type == PEER_TYPE_CHANNEL:
        peer.name = stream.read_qstring()
        peer.access_hash = stream.read_u64()
        _date = stream.read_i32()
        _legacy_version = stream.read_i32()
        _legacy_forbidden = stream.read_i32()
        _flags = stream.read_u32()
        _invite_link = stream.read_qstring()

    else:
        raise NotImplementedError(f"Unknown peer type bits: {peer_type}")

    return peer


def read_self_serialized(blob: bytes) -> Peer:
    """lskSelfSerialized entries are a single writePeer block, no count prefix."""
    return read_peer(QStream(blob))


def read_top_peers_blob(blob: bytes, debug: bool = False) -> list[Peer]:
    """
    TopPeers::serialize() format: quint32 app_version, quint32 disabled,
    quint32 count, then `count` x (writePeer block + quint64 rating).
    Distinct from read_peer_list: extra 'disabled' header field and a
    trailing rating value after each peer.
    """
    stream = QStream(blob)
    if stream.at_end():
        return []
    app_version = stream.read_u32()
    _disabled = stream.read_u32()
    count = stream.read_u32()
    if debug:
        print(f"[debug] top_peers blob length={len(blob)} "
              f"app_version={app_version} disabled={_disabled} count={count}")
    peers = []
    for i in range(count):
        peers.append(read_peer(stream, debug=debug))
        stream.read_u64()  # rating, not needed for access_hash lookup
    return peers


def read_peer_list(blob: bytes, debug: bool = False) -> list[Peer]:
    """
    Format shared by search-suggestions / recent-hashtags-and-bots-style
    caches: quint32 app version tag, quint32 count, then `count` writePeer
    blocks back to back.

    debug=True: on failure, print diagnostics (which index failed, stream
    position, surrounding hex, and the raw fields read so far for that
    entry) instead of just propagating the exception blind.
    """
    stream = QStream(blob)
    if stream.at_end():
        return []
    app_version = stream.read_u32()
    count = stream.read_u32()
    if debug:
        print(f"[debug] blob length={len(blob)} app_version={app_version} count={count}")
    peers = []
    for i in range(count):
        start_pos = stream.pos
        try:
            peers.append(read_peer(stream, debug=debug))
        except Exception as e:  # noqa: BLE001
            if debug:
                lo = max(0, start_pos - 16)
                hi = min(len(blob), stream.pos + 32)
                print(f"[debug] FAILED at peer index {i}/{count}, "
                      f"entry started at byte {start_pos}, "
                      f"failed at byte {stream.pos}")
                print(f"[debug] hex around failure ({lo}:{hi}):")
                print(" ", blob[lo:hi].hex())
                marker = "  " + " " * ((stream.pos - lo) * 3) + "^^"
                print(marker)
            raise
    return peers


# --------------------------------------------------------------------------
# Account "map" file
# --------------------------------------------------------------------------

@dataclass
class AccountMap:
    self_serialized: Optional[bytes] = None
    search_suggestions_key: Optional[int] = None
    recent_hashtags_and_bots_key: Optional[int] = None
    # Other lsk* keys exist (stickers, drafts, etc.) -- add as needed.


def read_account_map(map_path_without_suffix: str, local_key: bytes) -> AccountMap:
    tdf = read_tdf(map_path_without_suffix)
    outer = QStream(tdf.data)
    _legacy_salt = outer.read_bytearray()
    _legacy_key_encrypted = outer.read_bytearray()
    map_encrypted = outer.read_bytearray()

    decrypted = decrypt_local(map_encrypted, local_key)
    stream = QStream(decrypted)

    result = AccountMap()
    while not stream.at_end():
        key_type = stream.read_u32()

        if key_type in (LSK_DRAFT, LSK_DRAFT_POSITION, LSK_BOT_STORAGES):
            count = stream.read_u32()
            for _ in range(count):
                stream.read_u64()  # FileKey
                stream.read_u64()  # PeerId serialized
        elif key_type in (LSK_LEGACY_IMAGES, LSK_LEGACY_STICKER_IMAGES, LSK_LEGACY_AUDIOS):
            count = stream.read_u32()
            for _ in range(count):
                stream.read_u64()  # FileKey
                stream.read_u64()  # first
                stream.read_u64()  # second
                stream.read_i32()  # size
        elif key_type == LSK_SELF_SERIALIZED:
            result.self_serialized = stream.read_bytearray()
        elif key_type == LSK_BACKGROUND_OLD:
            stream.read_u64()
            stream.read_u64()
        elif key_type == LSK_STICKERS_KEYS:
            stream.read_u64()
            stream.read_u64()
            stream.read_u64()
            stream.read_u64()
        elif key_type == LSK_MASKS_KEYS:
            stream.read_u64()
            stream.read_u64()
            stream.read_u64()
        elif key_type == LSK_CUSTOM_EMOJI_KEYS:
            stream.read_u64()
            stream.read_u64()
            stream.read_u64()
        elif key_type == LSK_WEBVIEW_TOKENS:
            stream.read_bytearray()
            stream.read_bytearray()
        elif key_type == LSK_SAVED_GIFS_OLD:
            stream.read_u64()
        elif key_type == LSK_SAVED_PEERS_OLD:
            stream.read_u64()
        elif key_type == LSK_RECENT_HASHTAGS_AND_BOTS:
            result.recent_hashtags_and_bots_key = stream.read_u64()
        elif key_type == LSK_SEARCH_SUGGESTIONS:
            result.search_suggestions_key = stream.read_u64()
        elif key_type in (
            LSK_LOCATIONS, LSK_REPORT_SPAM_STATUSES_OLD, LSK_TRUSTED_PEERS,
            LSK_RECENT_STICKERS_OLD, LSK_BACKGROUND_OLD_OLD, LSK_USER_SETTINGS,
            LSK_STICKERS_OLD, LSK_FAVED_STICKERS, LSK_SAVED_GIFS,
            LSK_EXPORT_SETTINGS, LSK_ROUND_PLACEHOLDER,
            LSK_INLINE_BOTS_DOWNLOADS, LSK_MEDIA_LAST_PLAYBACK_POSITIONS,
            LSK_PREFS,
        ):
            stream.read_u64()  # all single-FileKey entries
        else:
            raise NotImplementedError(f"Unhandled lsk entry type: {hex(key_type)}")

    return result


# --------------------------------------------------------------------------
# High-level orchestration
# --------------------------------------------------------------------------

def get_access_hash(
    account_base_path: str,
    local_key: bytes,
    user_id: int,
    debug: bool = False,
) -> Optional[int]:
    """
    account_base_path: the per-account tdata subfolder (contains "map*"
        among other files), WITH a trailing slash.
    local_key: 256 raw bytes (from decrypt_domain_key_file, or extracted
        some other way).
    user_id: the bare numeric Telegram user id you're looking for.

    Searches self + search-suggestions + recent-hashtags-and-bots caches.
    Returns the access_hash, or None if that user isn't cached locally.
    """
    account_map = read_account_map(account_base_path + "map", local_key)

    candidates: list[Peer] = []

    if account_map.self_serialized:
        if debug:
            print(f"[debug] self_serialized length={len(account_map.self_serialized)}")
        candidates.append(read_self_serialized(account_map.self_serialized))

    if account_map.search_suggestions_key is not None:
        fname = account_base_path + file_key_to_hex(account_map.search_suggestions_key)
        if debug:
            print(f"[debug] reading search suggestions file: {fname}")
        wrapper = read_encrypted_tdf(fname, local_key)
        wrapper_stream = QStream(wrapper)
        # Account::readSearchSuggestions: top, recent are always present;
        # settingsSearches, guestChatBots only if the stream isn't exhausted
        # (older files may not have written them).
        top_blob = wrapper_stream.read_bytearray()
        recent_blob = wrapper_stream.read_bytearray()
        settings_searches_blob = b""
        guest_bots_blob = b""
        if not wrapper_stream.at_end():
            settings_searches_blob = wrapper_stream.read_bytearray()
        if not wrapper_stream.at_end():
            guest_bots_blob = wrapper_stream.read_bytearray()

        if debug:
            print(f"[debug] top={len(top_blob)}B recent={len(recent_blob)}B "
                  f"settingsSearches={len(settings_searches_blob)}B "
                  f"guestChatBots={len(guest_bots_blob)}B")

        candidates.extend(read_top_peers_blob(top_blob, debug=debug))
        candidates.extend(read_peer_list(recent_blob, debug=debug))
        # settingsSearches is text search history (no peers); guestChatBots
        # follows the same list format as `top` if you need it later:
        # candidates.extend(read_top_peers_blob(guest_bots_blob, debug=debug))

    if account_map.recent_hashtags_and_bots_key is not None:
        fname = account_base_path + file_key_to_hex(account_map.recent_hashtags_and_bots_key)
        blob = read_encrypted_tdf(fname, local_key)
        # This file has hashtags first, then a bots peer list -- see
        # Account::writeRecentHashtagsAndBots in storage_account.cpp if you
        # need to parse the hashtag strings too. Bots-only extraction:
        stream = QStream(blob)
        write_count = stream.read_u32()
        search_count = stream.read_u32()
        for _ in range(write_count):
            stream.read_qstring()
            stream.read_raw(2)  # quint16
        for _ in range(search_count):
            stream.read_qstring()
            stream.read_raw(2)  # quint16
        bots_count = stream.read_u32()
        for _ in range(bots_count):
            candidates.append(read_peer(stream))

    for peer in candidates:
        if peer.peer_type == PEER_TYPE_USER and peer.bare_id == user_id:
            return twos_comp(peer.access_hash, 64)

    return None