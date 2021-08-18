% resmon-start(8) | Linux

NAME
====

`resmon start` - start `resmon`, the resource monitor for NVIDIA Spectrum
switches

SYNOPSIS
========

`resmon start [mode {hw | mock}] [[include | exclude] resources RES1 RES2 ...`

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

`[include | exclude] resources <RES> <RES> <...>`

: It is possible to configure a subset of resources that `resmon` is
    supposed to monitor. This will save the memory and some processing time
    that would be necessary for bookkeeping of uninterested resources. The
    list of resources to monitor needs to be selected when the daemon is
    started:

    ```shell
    $ resmon start resources lpm_ipv4 lpm_ipv6
    ```

    It is also possible to request monitoring of a group of resources. E.g.
    `lpm_ipv4` and `lpm_ipv6` are grouped together in a group named `lpm`:

    ```shell
    $ resmon start resources lpm
    ```

    It is also possible to monitor all resources except of an excluded few.
    E.g. to exclude LPM resources:

    ```shell
    $ resmon start exclude resources lpm
    ```

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
