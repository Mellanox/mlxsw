# mlxsw libbpf-tools

This directory includes various BPF-based tools aimed at improving the
observability and debuggability of mlxsw. The tools are written using
[libbpf][1], so that they could be compiled once and run everywhere
[(CO-RE)][2].

## List of tools

* emadlatency: Summarize EMAD latency as a histogram. [Examples](src/emadlatency_example.txt)
* emadump: Dump EMADs to a PCAP file. [Examples](src/emadump_example.txt)
* trapagg: Dump aggregated per-{trap, flow} statistics. [Examples](src/trapagg_example.txt)

## Building

```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd src
$ make
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
