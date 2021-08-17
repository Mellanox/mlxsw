% resmon-exporter(8) | Linux

NAME
====

`resmon-exporter` - Prometheus node exporter for `resmon`

SYNOPSIS
========

`resmon-exporter [--resmon-sockdir <PATH>] -f <TEXTFILE_NAME> [-i <INTERVAL> | -1]`

`resmon-exporter [--resmon-sockdir <PATH>] -l <ADDR:PORT>`

DESCRIPTION
===========

`resmon-exporter` is a Prometheus node exporter, a component that exports
the statistics collected by `resmon` in a format that the Prometheus
time-series database understands. The exporter can run in one of two modes:
a file mode, in which it fetches the statistics and dumps them in a file,
either once or in regular intervals; or a listening mode, in which the
exporter accepts TCP connections on a designated port, and serves the
result to its clients.

OPTIONS
=======

`-f <TEXTFILE_NAME>`

: Run the exporter in file mode. `<TEXTFILE_NAME>` is the name of the file
    where the statistics are stored.

`-i <INTERVAL>`

: When in file mode, how often should the statistics be scraped and the
    file updated.

`-1`

: When in file mode, scrape the statistics once, store them in the file,
    and exit.

`-l <ADDR:PORT>`

: Open a TCP socket on a given address and port. Every time a connection is
    made to this port, scrape the statistics and send them as a response.

`--resmon-sockdir <PATH>`

: The directory in which `resmon` opens the RPC socket. This should only be
    necessary to customize if the `resmon` daemon itself is running with
    non-default `--sockdir`.

EXAMPLE
=======

```shell
$ resmon-exporter -l 0.0.0.0:9417
$ curl http://localhost:9417
# HELP node_net_resmon_stats Resmon stats
# TYPE node_net_resmon_stats gauge
node_net_resmon_stats{descr="IPv4 LPM",name="LPM_IPV4"} 0.0
node_net_resmon_stats{descr="IPv6 LPM",name="LPM_IPV6"} 0.0
... etc ...
node_net_resmon_stats{descr="Total",name="TOTAL"} 0.0
# HELP node_net_resmon_stats_capacity Resmon stats capacity
# TYPE node_net_resmon_stats_capacity gauge
node_net_resmon_stats_capacity{descr="IPv4 LPM",name="LPM_IPV4"} 10000.0
node_net_resmon_stats_capacity{descr="IPv6 LPM",name="LPM_IPV6"} 10000.0
... etc ...
node_net_resmon_stats_capacity{descr="Total",name="TOTAL"} 10000.0
```

SEE ALSO
========

resmon(8)

REPORTING ISSUES
================

To report issues please send an email to: mlxsw@nvidia.com.
