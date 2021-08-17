# mlxsw libbpf-tools

This directory includes various BPF-based tools aimed at improving the
observability and debuggability of mlxsw. The tools are written using
[libbpf][1], so that they could be compiled once and run everywhere
[(CO-RE)][2].

## List of tools

* src/emadlatency: Summarize EMAD latency as a histogram. [Examples](src/emadlatency_example.txt)
* src/emadump: Dump EMADs to a PCAP file. [Examples](src/emadump_example.txt)
* src/trapagg: Dump aggregated per-{trap, flow} statistics. [Examples](src/trapagg_example.txt)
* resmon/resmon: Monitor resource consumption in Spectrum switches.

## Building

Before building any of libbpf-tools, the system needs to have the following
tools installed:

- clang
- llvm-strip

Besides this, BPF-based tools need the kernel that they are running on to
be configured with BTF (BPF Type Format) annotations:

- `CONFIG_DEBUG_INFO_BTF=y`

Then to prepare the source tree for building, first check out the libbpf
submodule:

```shell
$ git submodule update --init --recursive       # check out libbpf
```

Then either just build everything:

```shell
$ make
```

Or cherry-pick what should be built:

```shell
$ make -C src
$ make -C src emadump
$ make -C resmon
$ make -C resmon resmon
```

Some tools support installation. For those that do, the build system can be
configured by passing variables describing the directory layout of the system
where tools will be installed.

```shell
$ make PREFIX=/usr LOCALSTATEDIR=/var
```

## Installation

Some tools support installation. To install all that do, run:

```shell
$ make install
```

It is also possible to cherry-pick installation of a certain tool:

```shell
$ make -C resmon install
```

Remember to pass the directory-layout variables to install as well:

```shell
$ make PREFIX=/usr LOCALSTATEDIR=/var install
```

The build system also supports staged installations, e.g.:

```shell
$ make PREFIX=/usr LOCALSTATEDIR=/var DESTDIR=${HOME}/tmp/ install
```

## Further resources

1. [BPF portability and CO-RE][3]
2. [BCC to libbpf conversion guide][4]
3. [Building BPF applications with libbpf-boostrap][5]
4. [BPF ring buffer][6]
5. [Why We Switched from BCC to libbpf for Linux BPF Performance Analysis][7]
6. [Tips and Tricks for Writing Linux BPF Applications with libbpf][8]

[1]: https://github.com/libbpf/libbpf
[2]: https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere
[3]: https://nakryiko.com/posts/bpf-portability-and-co-re/
[4]: https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/
[5]: https://nakryiko.com/posts/libbpf-bootstrap/
[6]: https://nakryiko.com/posts/bpf-ringbuf/
[7]: https://en.pingcap.com/blog/why-we-switched-from-bcc-to-libbpf-for-linux-bpf-performance-analysis
[8]: https://en.pingcap.com/blog/tips-and-tricks-for-writing-linux-bpf-applications-with-libbpf
