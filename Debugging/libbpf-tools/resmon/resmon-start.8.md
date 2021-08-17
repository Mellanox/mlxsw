% resmon-start(8) | Linux

NAME
====

`resmon start` - start `resmon`, the resource monitor for NVIDIA Spectrum
switches

SYNOPSIS
========

`resmon start [mode {hw | mock}]`

DESCRIPTION
===========

After the daemon is up and running, it starts collecting allocation and
deallocation requests. Any allocations done prior to the daemon start will
not have been recorded and will thus be invisible to the daemon. Therefore
to have a fully accurate view of the state of resources, it is necessary to
issue a devlink reload, e.g.:

```shell
$ devlink reload pci/0000:06:00
```

This way even resources allocated during driver init are recorded.

## Communication With the Daemon

The daemon opens a Unix socket through which it communicates with the
client. The communication is according to the [JSON RPC][] protocol. Please
refer to the specification to understand the details of the message format.

Besides the JSON RPC interface, the suite also provides command-line
wrappers for individual JSON-RPC methods. Please refer to man pages for the
individual commands for further details.

OPTIONS
=======

Please refer to `resmon(8)` for details about command-line options.

When the daemon is started in a verbose mode (`-v`), the messages can be
seen in `journalctl -t resmon`.

PARAMETERS
==========

`mode {mock | hw}`

: By default, `resmon` starts in hardware mode, which means that it
    installs probes necessary to capture the EMAD messages exchanged
    between the `mlxsw` driver and the FW running on a device.

    For testing purposes, it is possible to start `resmon` in mock mode. In
    that situation `resmon` may run unprivileged, and the EMAD messages are
    injected from user space.

    To start `resmon` in mock mode, pass `mode mock` to the start command
    line:

    ```shell
    $ resmon start mode mock
    ```

    It is also possible to `systemctl edit resmon.service` to create an
    override with adjusted start-up parameters.


SEE ALSO
========

resmon(8), resmon-stop(8), resmon-ping(8)

[JSON RPC specification][JSON RPC].

REPORTING ISSUES
================

To report issues please send an email to: mlxsw@nvidia.com.

[JSON RPC]: https://www.jsonrpc.org/specification
