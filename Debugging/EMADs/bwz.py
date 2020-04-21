#! /usr/bin/python
"""
Copyright 2018 Mellanox Technologies. All rights reserved.
Licensed under the GNU General Public License, version 2 as
published by the Free Software Foundation; see COPYING for details.
"""

__author__ = """
petrm@mellanox.com (Petr Machata)
"""

import os
import sys
import struct
import pcapy
import errno
import getopt
from common import pcap_header_out, pcap_packet_header, tag_dict, \
    tlv_bus_name, tlv_dev_name, tlv_driver_name, tlv_incoming, tlv_type, tlv_buf

def usage():
    sys.stdout.write(
        "{argv[0]} [OPTIONS...] [FILE]\n"
        "\n"
        "Bearbeitungswerkzeug is a tool for processing pcap files captured by\n"
        "devlink-hwmsg.py. It's a shell filter that reads packets from one stream\n"
        "and produces a stream of packets filtered and transformed from the input.\n"
        "There's a simple DSL for selecting which packets to filter out and which\n"
        "to keep, and a way to describe what information and in which format should\n"
        "be included in the output stream.\n"
        "\n"
        "Options:\n"
        "  -f EXPR   Packet filter expression (which packets to include)\n"
        "  -s EXPR   Packet slicer expression (what to include in a packet)\n"
        '  -r FILE   Read input from FILE ("-" means stdin, the default)\n'
        '  -w FILE   Write output to FILE ("-" means stdout, the default)\n'
        '  -t TYPE   LINKTYPE to use in pcap header (the default is 162)\n'
        "  --help    Show this help and exit\n"
        "  --show    Show filter and slicer expressions and exit\n"
        "\n"
        "Filter expressions:\n"
        "  Keywords:\n"
        "    bus      Name of the bus where the message was captured\n"
        "    dev      Name of the device where the message was captured\n"
        "    driver   Name of the driver managing the device\n"
        "    incoming Whether the message was send from the device to the kernel\n"
        "    outgoing The opposite of incoming\n"
        "    type     Type of the message\n"
        "    buf      The message itself\n"
        "\n"
        "  Literals:\n"
        '    "X"        Literal string <X>\n'
        "    123        Literal numbers\n"
        "    True,False Booleans\n"
        "\n"
        "  Compound expressions:\n"
        "    X == Y   Expressions X and Y evaluate to the same value\n"
        "    X != Y   The opposite\n"
        "    X & Y    Boolean conjunction\n"
        "    X | Y    Boolean disjunction\n"
        "    ~X       Boolean negation ('outgoing' is the same as '~incoming')\n"
        "    X[Y]     Sequence (string) access\n"
        "    X[Y:Z]   Sequence (string) slicing\n"
        "\n"
        "  Examples:\n"
        '    driver == "mlxsw_spectrum"  # Just messages to this driver\n'
        '    driver[:5] == "mlxsw"       # Messages to any mlxsw driver\n'
        '    incoming & (driver == "X")  # Only incoming messages to this driver\n'
        "\n"
        "Slicer expressions:\n"
        "  Keywords:\n"
        "    The same suite of keywords is supported for slicing as well.\n"
        "\n"
        "  Combiners:\n"
        "    X, Y, Z       Dump values of these keywords one after another\n"
        "    tlv(X, Y, Z)  Dump the values in the same TLV format\n"
        "\n"
        "  Examples:\n"
        "    buf                # Just the message payload without TLV marking\n"
        "    tlv(incoming, buf) # These two pieces of data in TLV format\n"
        .format(argv=sys.argv)
        )

try:
    optlist, args = getopt.gnu_getopt(sys.argv[1:], 'f:r:s:t:vw:',
                                      ["help", "show"])
except(getopt.GetoptError, e):
    print(e)
    sys.exit(1)

query_string = "True"
slicer_string = "tlv(*all)"
show_exprs_and_exit = False
read_file = "-"
write_file = "-"
link_type = 162

opts = dict(optlist)
if "--help" in opts:
    usage()
    sys.exit(0)
if "--show" in opts:
    show_exprs_and_exit = True
if "-f" in opts:
    query_string = opts["-f"]
if "-s" in opts:
    slicer_string = opts["-s"]
if "-r" in opts:
    read_file = opts["-r"]
if "-w" in opts:
    write_file = opts["-w"]
if "-v" in opts:
    verbose = True
if "-t" in opts:
    link_type = int(opts["-t"])

class Q(object):
    def __eq__(self, other):
        return Binary(self, other, "(%s == %s)", lambda a, b: a == b)

    def __ne__(self, other):
        return Binary(self, other, "(%s != %s)", lambda a, b: a != b)

    def __getitem__(self, key):
        return Binary(self, key, "(%s[%s])", lambda a, b: a[b])

    def __and__(self, other):
        return Binary(self, other, "(%s & %s)", lambda a, b: a and b)

    def __or__(self, other):
        return Binary(self, other, "(%s | %s)", lambda a, b: a or b)

    def __invert__(self):
        return Unary(self, "(~%s)", lambda a: not a)

class Immediate(Q):
    def __init__(self, value, tag=None):
        self._tag = tag
        self._value = value

    def value(self):
        return self._value

    def tag(self):
        return self._tag

    def evaluate(self, tlv):
        return self

    def __str__(self):
        return repr(self._value)

class Unary(Q):
    def __init__(self, a, fmt, f):
        self._a = a
        self._fmt = fmt
        self._f = f

    def evaluate(self, tlv):
        a = evaluate(self._a, tlv)
        return Immediate(self._f(a.value()), None)

    def __str__(self):
        return self._fmt % self._a

class Binary(Q):
    def __init__(self, a, b, fmt, f):
        self._a = a
        self._b = b
        self._fmt = fmt
        self._f = f

    def evaluate(self, tlv):
        a = evaluate(self._a, tlv)
        b = evaluate(self._b, tlv)
        return Immediate(self._f(a.value(), b.value()), None)

    def __str__(self):
        b = self._b if isinstance(self._b, Q) else Immediate(self._b)
        return self._fmt % (self._a, b)

class Select(Q):
    def __init__(self, tag, name):
        self._tag = tag
        self._name = name

    def evaluate(self, tlv):
        return Immediate(tlv[self._tag], self._tag)

    def __str__(self):
        return self._name

class Slicer(object):
    def __init__(self, gen):
        self._items = list(gen)

    def slice_data(self, tlv):
        ret = bytearray()
        for item in self._items:
            a = evaluate(item, tlv)
            tag = a.tag()
            if tag is None:
                raise RuntimeError("%s has indeterminate tag" % str(item))

            v = tag_dict[tag].encode(a.value())
            ret += self.pack(tag, v)
        return ret

class IterableSlicer(Slicer):
    def pack(self, tag, data):
        return data

    def __str__(self):
        return ", ".join(str(item) for item in self._items)

class TLVSlicer(Slicer):
    def pack(self, tag, data):
        return struct.pack("HH", tag, len(data)) + data

    def __str__(self):
        return "tlv(%s)" % ", ".join(str(item) for item in self._items)

def evaluate(obj, tlv):
    if isinstance(obj, Q):
        return obj.evaluate(tlv)
    else:
        return Immediate(obj)

def slice_data(obj, tlv):
    if isinstance(obj, Slicer):
        return obj.slice_data(tlv)

    if isinstance(obj, (tuple, list)):
        gen = iter(obj)
    else:
        gen = iter((obj, ))
    return IterableSlicer(gen).slice_data(tlv)

class Query:
    bus = Select(tlv_bus_name.tag(), "bus")
    dev = Select(tlv_dev_name.tag(), "dev")
    driver = Select(tlv_driver_name.tag(), "driver")
    incoming = Select(tlv_incoming.tag(), "incoming")
    outgoing = ~incoming
    type = Select(tlv_type.tag(), "type")
    buf = Select(tlv_buf.tag(), "buf")
    v = Immediate

query = eval(query_string, dict(Query.__dict__))
slicer = eval(slicer_string, dict(Query.__dict__),
              {"tlv": lambda *args: TLVSlicer(iter(args)),
               "all": (Query.bus, Query.dev, Query.driver, Query.incoming,
                       Query.type, Query.buf)})

if show_exprs_and_exit:
    sys.stderr.write("filter=%s\n" % str(query))
    sys.stderr.write("slice=%s\n" % str(slicer))
    sys.exit(0)

def read_tlv(data):
    ret = {}
    while len(data) != 0:
        tag, length = struct.unpack("HH", data[:4])
        data = data[4:]
        value = tag_dict[tag].decode(data[:length])
        data = data[length:]
        ret[tag] = value
    return ret

def main():
    out = os.fdopen(1, "wb") if write_file == "-" else open(write_file, "wb")
    pcap_header_out(out, link_type)

    r = pcapy.open_offline(read_file)
    while True:
        try:
            hdr, payload = r.next()
        except pcapy.PcapError:
            break

        if hdr == None:
            break
        secs, usecs = hdr.getts()
        tlv = read_tlv(payload)
        if evaluate(query, tlv).value():
            data = slice_data(slicer, tlv)

            try:
                out.write(pcap_packet_header(secs, usecs, len(data)))
                out.write(data)
                out.flush()
            except(IOError, e):
                if e.errno == errno.EPIPE:
                    return
                raise

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("Interrupted.\n")
