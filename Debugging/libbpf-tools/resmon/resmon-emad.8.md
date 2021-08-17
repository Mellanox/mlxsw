% resmon-emad(8) | Linux

NAME
====

`resmon emad` - inject an EMAD into the `resmon` daemon in mock mode

SYNOPSIS
========

`resmon emad string <HEX_PAYLOAD>`

DESCRIPTION
===========

When `resmon` is run in the mock mode (and only then), it understands the RPC
method `emad`. This is the only way to inject EMADs into `resmon` in the mock
mode.

See `resmon-start(8)` for details on the mock mode.

PARAMETERS
==========

`string <HEX_PAYLOAD>`

: Payload of the EMAD to inject into the daemon. Payload only, i.e. without
    the Ethernet header.

    The payload is given in a hex-coded EMAD payload. Hex-coding means that
    each byte is represented by two hexadecimal digits describing the byte
    value. Thus e.g. the string "Hello!" (ASCII 0x48, 0x65, 0x6c, 0x6c,
    0x6f, 0x21) would be hex-coded as 48656c6c6f21.

    A way to obtain the EMADs in question in the first place is through the tool
    `emadump` in `src` directory of the repository, e.g. by feeding the resulting
    pcap file to wireshark.

EXAMPLE
=======

```
$ resmon --sockdir . start mode mock
$ resmon --sockdir . -v emad string \
		 08040000801382012d68bbc20004cbd3102100000000000000000000000000`
		`00000000000000000000000000000000000000000000000000000000000000`
		`00000000000000000000000000000000000000000000000000000000000000`
		`00000000000000000000000000000000000000000000000000000000000000`
		`000000000000000000000000000000000000000000000000180f0000000100`
		`000000000000000020000000000000000000000000c6010203802000020000`
		`0000000000000000000000000000000000000000000000010000
resmond took the EMAD
$ resmon --sockdir . stats
Resource                      Usage
IPv4 LPM                      1 / 10000 (0%) <-- newly-allocated resource
[...]
Total                         1 / 10000 (0%)
```

RPC REQUEST
===========

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "method": "emad",
  "params": {
    "payload": "<HEX_PAYLOAD>"
  }
}
```

RPC RESPONSE
============

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "result": null
}
```

This response indicates that the daemon accepted the EMAD. A failure of any
kind would be communicated through an error response.

SEE ALSO
========

resmon(8), resmon-start(8)

[JSON RPC specification][JSON RPC].

REPORTING ISSUES
================

To report issues please send an email to: mlxsw@nvidia.com.

[JSON RPC]: https://www.jsonrpc.org/specification
