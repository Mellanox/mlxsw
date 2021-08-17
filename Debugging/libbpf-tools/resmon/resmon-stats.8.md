% resmon-stats(8) | Linux

NAME
====

`resmon stats` - dump statistics about objects allocated in the device

SYNOPSIS
========

`resmon stats`

DESCRIPTION
===========

The daemon collects allocation and deallocation requests for a number of
resource types. It can report number of entries allocated for individual
resource types through the `stats` command:

```shell
$ resmon stats
Resource                      Usage
IPv4 LPM                      29 / 524288 (0%)
IPv6 LPM                      35 / 524288 (0%)
ATCAM                         12 / 524288 (0%)
ACL Action Set                1008 / 524288 (0%)
IPv4 Host Table               6 / 524288 (0%)
IPv6 Host Table               0 / 524288 (0%)
Adjacency Table               0 / 524288 (0%)
FDB Entry                     74 / 524288 (0%)
Total                         1164 / 524288 (0%)
```

The value behind slash is the capacity of on-chip memory. This is reported
separately at each resource for convenience, but actually all resources consume
the same memory. This can be seen in the "Total" line, where individual resource
usages are summed, but the capacity is still the same.

RPC REQUEST
===========

The RPC method takes no parameters:

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "method": "stats",
}
```

RPC RESPONSE
============

The `stats` method returns list of resources with their consumptions and
capacities:

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "result": {
    "gauges": [
      {
        "name": "unique_name",
        "descr": "Human-readable desciption",
        "value": $V,
        "capacity": $C
      },
      ...
  }
}
```

The result object has one element, "gauges", whose value is an array of objects.
Each object has a unique symbolic name of the resource for which this gauge is;
a human-readable description of what the resource is; current occupation below
"value"; and current capacity.

SEE ALSO
========

resmon(8)

[JSON RPC specification][JSON RPC].

REPORTING ISSUES
================

To report issues please send an email to: mlxsw@nvidia.com.

[JSON RPC]: https://www.jsonrpc.org/specification
