# mlxsw `resmon`

`resmon` is a daemon for monitoring ASIC resource consumption in NVIDIA Spectrum
Ethernet switches with Linux `mlxsw` driver.

## Building & Installation

To build `resmon`, first make sure that development packages for the following
libraries are installed on the system:

- [json-c](https://github.com/json-c/json-c)
- [systemd](https://systemd.io/)
- [libnl-genl](http://www.infradead.org/~tgr/libnl/)

Additionally, to build `resmon` manual pages, make sure the following is
installed:

- [pandoc](https://pandoc.org/)

On top of that, some requirements arise from the fact that `resmon` uses a BPF
component. These requirements are covered in the [top-level
README.md](../README.md).

Please refer to the [top-level README.md](../README.md) for detailed building and installation instructions as well.

## Daemon Control

To start and stop the daemon, use the commands `start` and `stop`:

```shell
$ resmon start
$ resmon stop
```

Under usual circumstances, it is expected that `systemctl` will be used to
manage the daemon. To start, inspect status of, and stop the `resmon` daemon:

```shell
$ systemctl start resmon
$ systemctl status resmon
$ systemctl stop resmon
```

For further details, please consult man pages [`resmon(8)`](resmon.8.md),
[`resmon-start(8)`](resmon-start.8.md) and
[`resmon-stop(8)`](resmon-stop.8.md).

## Prometheus Exporter

Shipped together with `resmon` is a Prometheus node exporter, a component that
exports the statistics collected by `resmon` in a format that the Prometheus
time-series database understands. This can be started using `systemctl`:

```shell
$ systemctl start resmon-exporter
$ systemctl status resmon-exporter
$ systemctl stop resmon-exporter
```

By default, the resmon-exporter service opens a TCP socket at 0.0.0.0:9417.
Requests at that port are responded to with a resmon stats scrape in
Prometheus node exporter format:

```shell
$ curl http://localhost:9417
# HELP node_net_resmon_stats Resmon stats
# TYPE node_net_resmon_stats gauge
node_net_resmon_stats{descr="IPv4 LPM",name="LPM_IPV4"} 0.0
node_net_resmon_stats{descr="IPv6 LPM",name="LPM_IPV6"} 0.0
... etc ...
```

For further details, please consult the
[`resmon-exporter(8)`](resmon-exporter.8.md) man page.
