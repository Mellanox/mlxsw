Hardware messages monitoring
--------------

It is possible to monitor all messages driver is sending down to hardware and
messages coming from hardware back to the driver. This is implemented
as a kernel tracepoint. The tracepoint name is `devlink:devlink_hwmsg`.

There is a simple python script called `devlink-hwmsg.py` that hooks up
on this tracepoint and converts events into PCAP output.
You can get it like this:

```
sw:~$ git clone https://github.com/jpirko/hwmsg_tracing.git
```

Then just use it from your desktop connecting it to Wireshark for easier
view like this:

```
desktop:~$ ssh sw sudo ~/hwmsg_tracing/devlink-hwmsg.py | sudo wireshark -k -i -
```

In case the `devlink-hwmsg.py` complains about missing `tracepoint` object,
you need to update `python-perf` package. For example like this:

```
sw:~$ sudo dnf install https://kojipkgs.fedoraproject.org//packages/kernel/4.8.0/0.rc7.git4.1.fc25/x86_64/python-perf-4.8.0-0.rc7.git4.1.fc25.x86_64.rpm -y
```

Also make sure that `devlink` module is loaded before you run the script.

Processing hardware messages
--------------

Hardware message packets contain data in a custom TLV-based format. The tool
`bwz.py` can be used to filter this data based on values inside individual TLV
fields, and to slice the data (i.e. omit some TLV records or remove the TLV
headers altogether).

`bwz` includes a simple language for expressing filtering (`-f`) and slicing
(`-s`). See `--help` for details of operation. E.g. to include just the payload
of messages that the kernel sends out, you could pipe `devlink-hwmsg.py` output
as follows:

```
sw:~$ devlink-hwmsg.py | bwz.py -f outgoing -s buf | ...
```

To select complete messages from a particular driver, you could do this:

```
sw:~$ devlink-hwmsg.py | bwz.py -f 'driver == "mlxsw_spectrum"' | ...
```

It's possible to query substrings of individual values using Python array
subscript syntax. E.g. if you know the message buffer is in Mellanox EMAD
format, you can do the following to select all messages related to the RAUHT
register (whose ID is 0x8014):

```
sw:~$ ... | bwz.py -f 'buf[0x14:0x16] == "\x80\x14"' | ...
```

One can combine the conditions using `&` and `|` for "and" and "or". Make sure
you parenthesize the combined expressions, `&` and `|` don't have the right
precedence in Python. When in doubt, use the command line argument `--show` to
have `bwz` dump how it understands the task.

```
sw:~$ bwz.py --show -f '(driver == "mlxsw_spectrum") & outgoing & \
                        (buf[0x14:0x16] == "\x80\x14")'
filter=(((driver == 'mlxsw_spectrum') & (~incoming)) & ((buf[slice(20, 22, None)]) == '\x80\x14'))
slice=tlv(bus, dev, driver, incoming, type, buf)
```

`bwz` depends on `pcapy`, a Python package for processing pcap files.
