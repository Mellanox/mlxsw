"""
Copyright 2016, 2018 Mellanox Technologies. All rights reserved.
Licensed under the GNU General Public License, version 2 as
published by the Free Software Foundation; see COPYING for details.
"""

import struct
import sys

def pcap_header_out(f, link_type = 162):
    pcap_header = struct.pack("IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 0xffff,
                              link_type)
    f.write(pcap_header)
    f.flush()

def pcap_packet_header(secs, usecs, pktlen):
    return struct.pack("IIII", secs, usecs, pktlen, pktlen)

def nulstr_to_str(s):
    assert s.endswith(b'\0')
    return s[:-1]

def normalize_ba(ba):
    if (isinstance(ba, str)):
        ba = bytearray(ba + "\0", 'utf-8')
    return ba

class Tag:
    def __init__(self, tag, decoder, encoder):
        self._tag = tag
        self._decoder = decoder
        self._encoder = encoder

    def tag(self):
        return self._tag

    def decode(self, s):
        return self._decoder(s)

    def encode(self, v):
        return self._encoder(v)

tlv_bus_name =    Tag(0, nulstr_to_str, normalize_ba)
tlv_dev_name =    Tag(1, nulstr_to_str, normalize_ba)
tlv_driver_name = Tag(2, nulstr_to_str, normalize_ba)
tlv_incoming =    Tag(3, lambda s: struct.unpack("?", s)[0],
                         lambda v: struct.pack("?", v))
tlv_type =        Tag(4, lambda s: struct.unpack("H", s)[0],
                         lambda v: struct.pack("H", v))
tlv_buf =         Tag(5, lambda s: s, lambda v: v)

tag_dict = {t.tag(): t for t in [tlv_bus_name, tlv_dev_name, tlv_driver_name,
                                 tlv_incoming, tlv_type, tlv_buf]}
