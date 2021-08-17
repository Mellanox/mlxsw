% resmon-ping(8) | Linux

NAME
====

`resmon ping` - probe the liveness of the `resmon` daemon

SYNOPSIS
========

`resmon ping`

DESCRIPTION
===========

The `ping` RPC method and the associated command-line wrapper can be used
to check whether the daemon is alive and capable of servicing RPC requests.

Note that the `resmon` daemon is a single-threaded program. If an
outstanding `stats` request is blocked in `devlink` (such as would be the
case during the driver reset), the daemon will not service `ping` requests
either, until the block clears.

RPC REQUEST
===========

The `ping` method takes any object for `params`. The daemon will simply
return the passed-in object through the `result` in response.

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "method": "ping",
  "params": $OBJECT
}
```

RPC RESPONSE
============

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "result": $OBJECT
}
```

SEE ALSO
========

resmon(8), resmon-start(8), resmon-stop(8)

[JSON RPC specification][JSON RPC].

REPORTING ISSUES
================

To report issues please send an email to: mlxsw@nvidia.com.

[JSON RPC]: https://www.jsonrpc.org/specification
