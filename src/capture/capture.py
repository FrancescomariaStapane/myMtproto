#!/usr/bin/env python3
"""
Capture traffic to/from a subnet on a given interface, split it into TCP
streams, and write raw hex (no separators) of outgoing/incoming payloads
to two files per stream in the current directory: out0/in0, out1/in1, ...

Usage:
    sudo python3 tcp_stream_hex_capture.py -i eth0 -t 192.168.1.0/20

Stop with Ctrl+C.

"outgoing" = payload in packets whose destination is inside the subnet.
"incoming" = payload in packets whose source is inside the subnet.
"""

import argparse
import ipaddress
import signal
import sys

from scapy.all import *
from scapy.layers.inet import TCP, IP


class StreamWriter:
    """
    Assigns each new TCP stream (identified by its 4-tuple, direction
    independent) the next free index, and writes payload bytes as
    continuous hex into outN / inN files in the current directory.
    """

    def __init__(self, subnet):
        self.subnet = subnet
        self.stream_ids = {}     # canonical 4-tuple key -> index
        self.handles = {}        # index -> {"out": fh, "in": fh}
        self.next_id = 0

    def _key(self, pkt):
        ip = pkt[IP]
        tcp = pkt[TCP]
        a = (ip.src, tcp.sport)
        b = (ip.dst, tcp.dport)
        lo, hi = sorted([a, b])
        return (lo, hi)

    def _get_index(self, key):
        if key not in self.stream_ids:
            idx = self.next_id
            self.stream_ids[key] = idx
            self.handles[idx] = {
                "out": open(f"stream_{idx}_out", "a"),
                "in": open(f"stream_{idx}_in", "a"),
            }
            self.next_id += 1
            print(f"New stream {idx}: {key[0]} <-> {key[1]}  -> stream_{idx}_out / stream_{idx}_in")
        return self.stream_ids[key]

    def write(self, pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        ip = pkt[IP]
        payload = bytes(pkt[Raw].load)
        if not payload:
            return

        dst_in_subnet = ipaddress.ip_address(ip.dst) in self.subnet
        src_in_subnet = ipaddress.ip_address(ip.src) in self.subnet

        if dst_in_subnet:
            direction = "out"
        elif src_in_subnet:
            direction = "in"
        else:
            return

        idx = self._get_index(self._key(pkt))
        fh = self.handles[idx][direction]
        fh.write(payload.hex())
        fh.flush()

        print(f"[stream_{idx}_{direction}] +{len(payload)} bytes")

    def close_all(self):
        for pair in self.handles.values():
            for fh in pair.values():
                fh.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--iface", required=True)
    parser.add_argument("-t", "--target", required=True)
    args = parser.parse_args()

    subnet = ipaddress.ip_network(args.target, strict=False)
    writer = StreamWriter(subnet)

    bpf_filter = f"net {subnet.with_prefixlen} and tcp"

    def handle_sigint(sig, frame):
        print("\nStopping capture")
        writer.close_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    print(f"Capturing on {args.iface}, filter='{bpf_filter}'")
    try:
        sniff(
            iface=args.iface,
            filter=bpf_filter,
            prn=writer.write,
            store=False,
            count=0,
        )
    finally:
        writer.close_all()


if __name__ == "__main__":
    main()

