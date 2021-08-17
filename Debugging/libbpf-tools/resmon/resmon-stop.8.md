% resmon-stop(8) | Linux

NAME
====

`resmon stop` - stop the `resmon` daemon

SYNOPSIS
========

`resmon stop`

DESCRIPTION
===========

The `stop` RPC method and the associated command-line wrapper can be used
to stop the `resmon` daemon.

RPC REQUEST
===========

The `stop` method takes no parameters.

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "method": "stop"
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

This response indicates that the daemon intends to stop soon. A refusal to
stop would be expressed through an error response.


SEE ALSO
========

resmon(8), resmon-start(8), resmon-ping(8)

[JSON RPC specification][JSON RPC].

REPORTING ISSUES
================

To report issues please send an email to: mlxsw@nvidia.com.

[JSON RPC]: https://www.jsonrpc.org/specification
