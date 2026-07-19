#!/usr/bin/env python3
"""
Extract access_hash values from a Telegram Android cache4.db.

Telegram Android's `users` and `chats` tables store each entity as a raw
serialized TL object in a BLOB `data` column - access_hash isn't a plain
SQL column, it's a field inside that TL-encoded blob. This script parses
just enough of the TL layout to pull it out reliably:

  - It doesn't hardcode the User/Channel constructor magic numbers
    (those change almost every schema layer), so instead it locates the
    known `uid` (already given to us by SQLite) as a little-endian int64
    inside the blob. In the TL schema, `access_hash` has - for the
    entire history of the protocol - always been the field immediately
    following `id`, so once `id` is located, the next 8 bytes are the
    candidate access_hash.
  - Every extraction is validated: the script decodes the TL string that
    should immediately follow (first_name for users, title for chats)
    and checks it against the `name` column SQLite already has. If it
    doesn't match, the row is reported as unverified rather than
    guessed.
  - Plain "basic group" chats (as opposed to channels/supergroups) don't
    have an access_hash field at all in the TL schema - those are
    correctly reported as N/A, not as an extraction failure.

Requires cache4.db (+ its -wal/-shm siblings, if present, in the same
directory) from a Telegram Android-family client (stock Telegram,
Telegram FOSS, Plus Messenger, etc. all share this schema).

Usage:
    python3 extract_access_hashes.py /path/to/cache4.db
    python3 extract_access_hashes.py /path/to/cache4.db --csv out.csv
"""

import argparse
import csv
import sqlite3
import sys


def read_tl_string(data: bytes, offset: int):
    """Decode a TL `string`/`bytes` field at `offset`. Returns (text, new_offset) or None."""
    if offset >= len(data):
        return None
    first = data[offset]
    if first < 254:
        length = first
        start = offset + 1
    else:
        if offset + 4 > len(data):
            return None
        length = int.from_bytes(data[offset + 1:offset + 4], "little")
        start = offset + 4
    end = start + length
    if end > len(data):
        return None
    raw = data[start:end]
    total = (start - offset) + length
    pad = (-total) % 4
    new_offset = end + pad
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text, new_offset


def locate_id(data: bytes, entity_id: int):
    """Find the little-endian int64 encoding of entity_id in the blob."""
    id_bytes = entity_id.to_bytes(8, "little", signed=True)
    idx = data.find(id_bytes)
    return idx


def extract_user_access_hash(uid: int, name: str, data: bytes):
    idx = locate_id(data, uid)
    if idx == -1 or idx < 8:
        return None, "id not found in blob"

    flags = int.from_bytes(data[4:8], "little")
    if not (flags & 0x1):
        return None, "flags bit0 clear (no access_hash field for this user)"

    ah_offset = idx + 8
    if ah_offset + 8 > len(data):
        return None, "blob too short for access_hash"
    access_hash = int.from_bytes(data[ah_offset:ah_offset + 8], "little", signed=True)

    # validate against first_name, if flags bit1 (first_name present) is set
    verified = None
    if flags & 0x2:
        result = read_tl_string(data, ah_offset + 8)
        if result:
            decoded_first_name = result[0]
            verified = name.lower().startswith(decoded_first_name.lower()) or \
                decoded_first_name.lower() in name.lower()
    return access_hash, ("verified" if verified else "unverified")


def extract_chat_access_hash(uid: int, name: str, data: bytes):
    idx = locate_id(data, uid)
    if idx == -1:
        return None, "id not found in blob"

    # Two layouts are possible depending on constructor:
    #  - chatForbidden / channelForbidden: constructor(4) + id(8) directly, no flags
    #  - chat / channel: constructor(4) + flags(4) + id(8)
    # We already located id positionally, so just check what's right after it.
    ah_offset = idx + 8
    if ah_offset + 8 > len(data):
        return None, "blob too short"

    # try interpreting the next 8 bytes as access_hash, then validate by
    # decoding the title that should follow and comparing to `name`
    candidate_ah = int.from_bytes(data[ah_offset:ah_offset + 8], "little", signed=True)
    title_after_ah = read_tl_string(data, ah_offset + 8)

    # try interpreting the next bytes as title directly (no access_hash present)
    title_no_ah = read_tl_string(data, ah_offset)

    name_lower = name.lower().strip()

    def matches(candidate_title):
        if not candidate_title:
            return False
        return candidate_title.lower().strip() == name_lower

    if title_after_ah and matches(title_after_ah[0]):
        return candidate_ah, "verified"
    if title_no_ah and matches(title_no_ah[0]):
        return None, "no access_hash field (basic group)"

    # neither hypothesis validated cleanly
    return None, "could not verify layout"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("db_path", help="Path to cache4.db")
    parser.add_argument("--csv", help="Optional path to write results as CSV")
    args = parser.parse_args()

    uri = f"file:{args.db_path}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.OperationalError as e:
        print(f"Could not open {args.db_path}: {e}")
        sys.exit(1)

    results = []  # (kind, uid, name, access_hash, status)

    for uid, name, data in conn.execute("SELECT uid, name, data FROM users"):
        if not data:
            continue
        ah, status = extract_user_access_hash(uid, name or "", data)
        results.append(("user", uid, name, ah, status))

    for uid, name, data in conn.execute("SELECT uid, name, data FROM chats"):
        if not data:
            continue
        ah, status = extract_chat_access_hash(uid, name or "", data)
        results.append(("chat", uid, name, ah, status))

    conn.close()

    found = [r for r in results if r[3] is not None]
    skipped_no_hash = [r for r in results if r[3] is None and "no access_hash" in r[4]]

    print(f"Extracted {len(found)} access_hash values "
          f"({sum(1 for r in found if r[0]=='user')} users, "
          f"{sum(1 for r in found if r[0]=='chat')} chats/channels)\n")

    for kind, uid, name, ah, status in found:
        marker = "" if status == "verified" else "  [UNVERIFIED]"
        print(f"[{kind}] id={uid}\tname={name!r}\taccess_hash={ah}{marker}")

    if skipped_no_hash:
        print(f"\n{len(skipped_no_hash)} chats have no access_hash field "
              f"(plain basic groups - these don't use access_hash in MTProto).")

    real_failures = [r for r in results if r[3] is None and r[4] not in
                      ("no access_hash field (basic group)",) and
                      "flags bit0 clear" not in r[4]]
    if real_failures:
        print(f"\n{len(real_failures)} entries could not be parsed/verified:")
        for kind, uid, name, ah, status in real_failures:
            print(f"  [{kind}] id={uid} name={name!r}: {status}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["type", "id", "name", "access_hash", "status"])
            for kind, uid, name, ah, status in results:
                if ah is not None:
                    writer.writerow([kind, uid, name, ah, status])
        print(f"\nWrote {len(found)} rows to {args.csv}")


if __name__ == "__main__":
    main()