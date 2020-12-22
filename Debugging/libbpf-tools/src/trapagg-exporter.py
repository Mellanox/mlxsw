#!/usr/bin/env python
"""Collect trap metrics and publish them via http or save them to a file."""
import argparse
import logging
import os
import prometheus_client
import re
import subprocess
import sys
import time

from prometheus_client.core import CounterMetricFamily


class TrapaggCollector(object):
    """Collect aggregated per-{trap, flow} metrics and publish them via http
       or save them to a file."""

    def __init__(self, args=None):
        """Construct the object and parse the arguments."""
        self.args = None
        if not args:
            args = sys.argv[1:]
        self._parse_args(args)

    def _parse_args(self, args):
        """Parse CLI args and set them to self.args."""
        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            '-f',
            '--textfile-name',
            dest='textfile_name',
            help=('Full file path where to store data for node '
                  'collector to pick up')
        )
        group.add_argument(
            '-l',
            '--listen',
            dest='listen',
            help='Listen host:port, i.e. 0.0.0.0:9417'
        )
        parser.add_argument(
            '-i',
            '--interval',
            dest='interval',
            type=int,
            help=('Number of seconds between updates of the textfile. '
                  'Default is 5 seconds')
        )
        parser.add_argument(
            '-1',
            '--oneshot',
            dest='oneshot',
            action='store_true',
            default=False,
            help='Run only once and exit. Useful for running in a cronjob'
        )
        arguments = parser.parse_args(args)
        if arguments.oneshot and not arguments.textfile_name:
            logging.error('Oneshot has to be used with textfile mode')
            parser.print_help()
            sys.exit(1)
        if arguments.interval and not arguments.textfile_name:
            logging.error('Interval has to be used with textfile mode')
            parser.print_help()
            sys.exit(1)
        if not arguments.interval:
            arguments.interval = 5
        self.args = vars(arguments)

    def trapagg_output_get(self, command):
        """Execute command and return output."""
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE)
        except OSError as e:
            logging.critical(e.strerror)
            sys.exit(1)
        return proc.stdout.readlines()

    def update_trapagg_stats(self, counter):
        """Update counter with statistics from trapagg."""
        command = ['./trapagg', '-s']
        output = self.trapagg_output_get(command)
        for line in output[2:]:
            columns = line.decode('utf-8').split()
            counter.add_metric(columns[:-1], columns[-1])

    def collect(self):
        """
        Collect the metrics.

        Collect the metrics and yield them. Prometheus client library
        uses this method to respond to http queries or save them to disk.
        """
        output = self.trapagg_output_get(['./trapagg', '-s'])

        labels = [l.lower() for l in output[1].decode('utf-8').split()]
        counter = CounterMetricFamily('node_net_trapagg',
                                      'Aggregated trap data', labels=labels)

        for line in output[2:]:
            columns = line.decode('utf-8').split()
            counter.add_metric(columns[:-1], columns[-1])

        yield counter

if __name__ == '__main__':
    collector = TrapaggCollector()
    registry = prometheus_client.CollectorRegistry()
    registry.register(collector)
    args = collector.args
    if args['listen']:
        (ip, port) = args['listen'].split(':')
        prometheus_client.start_http_server(port=int(port),
                                            addr=ip, registry=registry)
        while True:
            time.sleep(3600)
    if args['textfile_name']:
        while True:
            collector.collect()
            prometheus_client.write_to_textfile(args['textfile_name'],
                                                registry)
            if collector.args['oneshot']:
                sys.exit(0)
            time.sleep(args['interval'])
