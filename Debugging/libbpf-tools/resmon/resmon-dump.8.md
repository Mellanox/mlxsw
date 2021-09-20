% resmon-dump(8) | Linux

NAME
====

`resmon dump` - Show the contents of the tables that the daemon uses to
keep track of resource allocation.

SYNOPSIS
========

`resmon dump list tables`

`resmon dump table <TABLE>`

DESCRIPTION
===========

The `dump` family of commands serves for introspecting state of the daemon.
It allows querying which internal tables the daemon has, and dumping the
contents of individual tables.

Note that the `dump` tool introspects tables, not resources. Some tables
hold more than one resource, and some resources are backed by more than one
table. A resource reference in some form is to be expected in individual
dumps, but is not required to be -- a helper table that is wholly
resource-agnostic is theoretically possible.

The command `resmon dump list tables` returns the list of names of tables
that the daemon knows about. These names can be plugged into the `resmon
dump table` command to request a dump of that table.

In verbose mode, `resmon dump list tables` lists for each table also the
number of rows, and a sequence number, a 32-bit integer value that gets
incremented every time a row is added to or removed from the table.

PARAMETERS
==========

`table <TABLE>`

: Name of the table to dump. The list of valid table names can be obtained
    through the `dump list tables` command.

EXAMPLE
=======

```
$ resmon emad string 08040000801382012d68bbc20004cbd3102100000000000000000`
                    `00000000000000000000000000000000000000000000000000000`
                    `00000000000000000000000000000000000000000000000000000`
                    `00000000000000000000000000000000000000000000000000000`
                    `00000000000000000000000000000000000000000000000000000`
                    `0000000000000000000000000000000180f000000010000000000`
                    `0000000020000000000000000000000000c601020380200002000`
                    `00000000000000000000000000000000000000000000000010000
$ resmon dump table ralue
|| dip          | vr || resource | slots ||
|| 198.1.2.3/32 | 0  || LPM_IPV4 | 1     ||
```

RPC REQUEST: get_tables
=======================

For the `dump list tables` command:

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "method": "get_tables"
}
```

RPC RESPONSE: get_tables
========================

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "result": {
    "tables": [
      {
        "name": $NAME,
        "seqnn": $SEQNN,
        "nrows": $NROWS
      },
      ...
    ]
  }
}
```

`$NAME` is a string representing the name of the table, `$SEQNN` is a
sequence number, a 32-bit quantity that gets incremented every time a row
is added to or deleted from the table, and `$NROWS` is number of rows in
the table.

Caveats
-------

This is a provisional API. It can change or go away in the future.

RPC REQUEST: next_row
=======================

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "method": "next_row",
  "params": {
    "table": $NAME
  }
}
```

See below for the usage details.

Caveats
-------

This is a provisional API. It can change or go away in the future.

RPC RESPONSE: next_row
======================

Either the request returns one row from the table:

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "result": {
    "row": {
      "key": {
        $FIELD1: $VALUE1,
        $FIELD2: $VALUE2,
        ...
      },
      "value": {
        $FIELD3: $VALUE3,
        $FIELD4: $VALUE4,
        ...
      }
    }
  }
}
```

In this case, the result contains a JSON object with fields "key" and
"value". The "key" object contains fields that form the unique key of this
table record. The "value" object contains other information, typically what
resource is being allocated by this row.

Or it returns a null, indicating the iteration is over:

```
{
  "jsonrpc": "2.0",
  "id": $ID,
  "result": {
    "row": null
  }
}
```

The `next_row` RPC is meant to be called repeatedly, while it keeps
yielding rows. The iteration stops after a null row is returned.

Caveats
-------

The RPC is not designed to handle concurrent iteration (each table can be
iterated only by one client at a time), and does not attempt to achieve
atomicity.

The iteration will be stopped prematurely if there were changes to the
table that make maintenance of consistent cursor too difficult. Such
changes will be reflected in seqnn bump.

The RPC is best-effort in that it is unreasonably difficult to make sure
that the dump is consistent. A way to maximize the likelihood of detecting
an inconsistent dump is by:

- observing table seqnn before and after the iteration: if it does not
  change, that is an indication that no rows were added or removed
  (however, though there is also a remote possibility that exactly 0x100M
  changes took place instead).

- checking number of rows actually dumped. If it is fewer than the number
  of rows reported at the table before the dump, then the dump certainly is
  incomplete. However even if the number of rows matches, what could have
  happened is that concurrent access to the cursor causes this client to
  inadvertently restart the iteration. Then further concurrent accesses
  cause it to get exactly the right number of rows, but some are missing
  and some are duplicated.

- looking for duplicates among the reported keys.

The first two measures are implemented in the resmon command-line client.
Users that rely on the interface in production (which they should not) and
want to ensure consistent dumps, should implement a mutual exclusion scheme
on the layer above the RPC. Provided a locking scheme, checking seqnn is
realistically the only thing that is necessary to be quite sure about dump
consistency.

This is a provisional API. It can change or go away in the future.

SEE ALSO
========

resmon(8)

[JSON RPC specification][JSON RPC].

REPORTING ISSUES
================

To report issues please send an email to: mlxsw@nvidia.com.

[JSON RPC]: https://www.jsonrpc.org/specification
