% resmon(8) | Linux

NAME
====

`resmon` - resource monitor for NVIDIA Spectrum switches

SYNOPSIS
========

`resmon -V`

`resmon [-v | -q] [--json] [--sockdir <PATH>]
{start | stop | ping | emad | stats | dump}`

DESCRIPTION
===========

`resmon` is a daemon for monitoring ASIC resource consumption in NVIDIA
Spectrum Ethernet switches with Linux `mlxsw` driver.

The daemon opens a Unix socket through which it communicates with the
client using the [JSON RPC][] protocol.

## Supported Platforms

`resmon` supports NVIDIA Spectrum-2 and later switches.

Partial support is available on NVIDIA Spectrum-1 switches: KVDL-based
resources will not be tracked properly, because KVDL in Spectrum-1 switches
is managed by software, not firmware, and therefore the release events will
not be seen by `resmon`. When running on Spectrum-1, it is therefore
reasonable to exclude KVDL resources from being monitored. See
`resmon-start(8)` for details on how to do that.

## Method of Operation

The driver communicates with the device using Ethernet packets called
Ethernet Management Datagrams (EMADs). The tool works by hooking up to a
function in the `mlxsw` driver that processes EMAD responses, filtering
out register EMADs that might indicate resource allocation or
deallocation. These it sends through a ring buffer to the user-space
daemon that dissects the registers and keeps track of state of
individual resources.

OPTIONS
=======

`-v, --verbose, -q, --quiet`

: Be more or less verbose, respectively. It makes sense to repeat the `-v`
    option up to three times, which increases verbosity every time (mostly
    for the benefit of messages from the BPF tooling).

`--sockdir <PATH>`

: Location of the Unix socket to use for communication with the daemon.

    By default, `resmon` opens the socket in a directory specified by the
    build-time variable `RUNSTATEDIR`. The default value of the variable is
    `/usr/local/var/run`. It is common to override the build-time variable
    `LOCALSTATEDIR` to `/var`, in which case `RUNSTATEDIR` is `/var/run`,
    and that's where the socket will be placed.

    The command-line argument `--sockdir` allows overriding of this default
    location.

`--json`

: When displaying the response sent by the daemon back to the client,
    instead of interpreting it and formatting in a human-readable way, dump
    the JSON result object instead, if any. Errors, including interpreted
    valid JSON RPC error response, are still dumped to standard error as
    usual.

    Please see manual pages for the individual client commands to
    understand the result object format. The man pages document full
    response object, the result is returned under the `result` key.

COMMANDS
========

`start`

: Starts the daemon.

`stop`

: Stops the daemon.

`stats`

: Scrapes collected resource allocation statistics.

`ping`

: Probes the liveness of the daemon.

`emad`

: Injects a hardware configuration message to the daemon. Only available in
  mock mode.

`dump`

: Show the contents of the tables that the daemon uses to keep track of
  resource allocation.

SEE ALSO
========

resmon-start(8), resmon-stop(8), resmon-stats(8), resmon-ping(8),
resmon-emad(8), resmon-dump(8)

[JSON RPC specification][JSON RPC].

REPORTING ISSUES
================

To report issues please send an email to: mlxsw@nvidia.com.

[JSON RPC]: https://www.jsonrpc.org/specification
