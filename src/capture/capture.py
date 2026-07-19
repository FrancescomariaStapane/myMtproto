#!/usr/bin/env python3
"""
Capture traffic to/from a subnet on a given interface, split it into TCP
streams, reassemble each direction in correct TCP sequence order (dropping
retransmitted duplicates and buffering out-of-order segments), and write
raw hex (no separators) of outgoing/incoming payloads to two files per
stream in the current directory: stream_0_out/stream_0_in, stream_1_out/stream_1_in, ...

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

from scapy.all import sniff, TCP, IP, Raw


class DirectionReassembler:
    """
    Reassembles one direction of a TCP stream into correct sequence order.

    - Segments that arrive out of order are buffered until the gap ahead
      of them is filled.
    - Segments (or the overlapping portion of a segment) that duplicate
      data already written (retransmissions) are dropped.
    - Only the reassembled, gap-free, de-duplicated byte stream is ever
      written out.
    """

    def __init__(self, file_handle):
        self.fh = file_handle
        self.next_seq = None          # expected next sequence number
        self.pending = {}             # seq -> payload, for out-of-order segments
        self.total_written = 0

    def _write(self, payload):
        if not payload:
            return
        self.fh.write(payload.hex())
        self.fh.flush()
        self.total_written += len(payload)

    def feed(self, seq, payload):
        if not payload:
            return

        if self.next_seq is None:
            # first segment seen for this direction: treat its seq as the
            # reassembly origin
            self.next_seq = seq

        # segment ends before our current position: fully a retransmission
        if seq + len(payload) <= self.next_seq:
            return

        # segment starts before our position but extends past it:
        # keep only the new tail portion
        if seq < self.next_seq:
            overlap = self.next_seq - seq
            payload = payload[overlap:]
            seq = self.next_seq

        if seq == self.next_seq:
            self._write(payload)
            self.next_seq += len(payload)
            # drain any buffered segments that are now contiguous
            while self.next_seq in self.pending:
                buffered = self.pending.pop(self.next_seq)
                self._write(buffered)
                self.next_seq += len(buffered)
        else:
            # out of order / gap ahead of us: buffer it, but trim if it
            # overlaps something already buffered at a lower seq
            if seq not in self.pending:
                self.pending[seq] = payload


class StreamWriter:
    """
    Assigns each new TCP stream (identified by its 4-tuple, direction
    independent) the next free index, and reassembles + writes payload
    bytes as continuous hex into outN / inN files in the current directory.
    """

    def __init__(self, subnet):
        self.subnet = subnet
        self.stream_ids = {}     # canonical 4-tuple key -> index
        self.reassemblers = {}   # index -> {"out": DirectionReassembler, "in": DirectionReassembler}
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
            out_fh = open(f"stream_{idx}_out", "a")
            in_fh = open(f"stream_{idx}_in", "a")
            self.reassemblers[idx] = {
                "out": DirectionReassembler(out_fh),
                "in": DirectionReassembler(in_fh),
            }
            self.next_id += 1
            print(f"New stream {idx}: {key[0]} <-> {key[1]}  -> stream_{idx}_out / stream_{idx}_in")
        return self.stream_ids[key]

    def write(self, pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
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
            return  # shouldn't happen given the BPF filter

        idx = self._get_index(self._key(pkt))
        reassembler = self.reassemblers[idx][direction]

        before = reassembler.total_written
        reassembler.feed(tcp.seq, payload)
        written = reassembler.total_written - before

        label = f"stream_{idx}_{direction}"
        if written:
            print(f"[{label}] +{written} bytes (seq={tcp.seq})")
        else:
            print(f"[{label}] buffered/dropped {len(payload)} bytes (seq={tcp.seq}, "
                  f"expected {reassembler.next_seq})")

    def close_all(self):
        for pair in self.reassemblers.values():
            for reassembler in pair.values():
                if reassembler.pending:
                    print(f"warning: {len(reassembler.pending)} out-of-order segment(s) "
                          f"never became contiguous and were left unwritten "
                          f"(gap at seq {reassembler.next_seq})")
                reassembler.fh.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--iface", required=True, help="Interface to capture on")
    parser.add_argument("-t", "--target", required=True,
                         help="Target subnet in CIDR form, e.g. 192.168.1.0/20")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Stop after N packets (default: 0 = run until Ctrl+C)")
    args = parser.parse_args()

    subnet = ipaddress.ip_network(args.target, strict=False)
    writer = StreamWriter(subnet)

    bpf_filter = f"net {subnet.with_prefixlen} and tcp"

    def handle_sigint(sig, frame):
        print("\nStopping capture, closing files...")
        writer.close_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    print(f"Capturing on {args.iface}, filter='{bpf_filter}'")
    print("Files are created in the current directory as stream_N_out / stream_N_in per stream.")
    print("Press Ctrl+C to stop.")

    try:
        sniff(
            iface=args.iface,
            filter=bpf_filter,
            prn=writer.write,
            store=False,
            count=args.count if args.count > 0 else 0,
        )
    finally:
        writer.close_all()


if __name__ == "__main__":
    main()