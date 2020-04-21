#! /usr/bin/python

"""
Copyright 2016, 2018 Mellanox Technologies. All rights reserved.
Licensed under the GNU General Public License, version 2 as
published by the Free Software Foundation; see COPYING for details.
"""

__author__ = """
jiri@mellanox.com (Jiri Pirko)
"""

import perf
import sys
import struct
from common import pcap_header_out, pcap_packet_header, \
    tlv_bus_name, tlv_dev_name, tlv_driver_name, tlv_incoming, tlv_type, tlv_buf

from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE,SIG_DFL)

class tracepoint(perf.evsel):
    def __init__(self, sys, name):
        config = perf.tracepoint(sys, name)
        perf.evsel.__init__(self, type = perf.TYPE_TRACEPOINT, config = config,
                            freq = 0, sample_period = 1, wakeup_events = 1,
                            sample_type = perf.SAMPLE_PERIOD | perf.SAMPLE_TID |
                            perf.SAMPLE_CPU | perf.SAMPLE_RAW |
                            perf.SAMPLE_TIME)

def tlv_data(data_type, data):
    enc = data_type.encode(data)
    tlv_header = struct.pack("HH", data_type.tag(), len(enc))
    return tlv_header + enc

def event_out(event):
    data = bytearray()
    data += tlv_data(tlv_bus_name, event.bus_name)
    data += tlv_data(tlv_dev_name, event.dev_name)
    data += tlv_data(tlv_driver_name, event.driver_name)
    data += tlv_data(tlv_incoming, event.incoming)
    data += tlv_data(tlv_type, event.type)
    data += tlv_data(tlv_buf, event.buf)

    secs = event.sample_time // 1000000000
    usecs = (event.sample_time % 1000000000) // 1000
    sys.stdout.write(pcap_packet_header(secs, usecs, len(data)))
    sys.stdout.write(data)
    sys.stdout.flush()

def main():
    sys.stdout = open('/dev/stdout', 'wb')

    tp = tracepoint("devlink", "devlink_hwmsg")
    cpus = perf.cpu_map()
    threads = perf.thread_map(-1)

    evlist = perf.evlist(cpus, threads)
    evlist.add(tp)
    evlist.open()
    evlist.mmap()

    pcap_header_out(sys.stdout)

    while True:
        try:
            evlist.poll(timeout = -1)
        except KeyboardInterrupt:
            break
        for cpu in cpus:
            while True:
                event = evlist.read_on_cpu(cpu)
                if not event:
                    break
                if not isinstance(event, perf.sample_event):
                    continue
                event_out(event)

if __name__ == '__main__':
    main()
