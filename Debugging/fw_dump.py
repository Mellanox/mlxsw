#!/usr/bin/python3

from datetime import datetime
import subprocess
import argparse
import sys

def make_parser():
    parser = argparse.ArgumentParser(description='A script that triggers mstflint when fw_fatal events occur')
    parser.add_argument('--output-path',
                        default="/tmp",
                        help='Path to output tar file, default is /tmp')
    return parser

def read_line(p):
    line = p.stdout.readline()
    if not isinstance(line, (str)):
        line = line.decode('utf-8').rstrip()
    return line

def verify_dependencies():
    # Verify that there is a single Mellanox PCI device
    cmd = 'lspci | grep Mellanox | wc -l'
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    mellanox_pci_count = read_line(p)
    if int(mellanox_pci_count) != 1:
        print("There is no single Mellanox PCI device")
        return 1

    # Verify that devlink is installed
    cmd = "which devlink"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    rc = p.wait()
    if rc:
        print("devlink is not installed")
        return rc

    # Verify that mstflint is installed
    cmd = "which mstflint"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    rc = p.wait()
    if rc:
        print("mstflint is not installed")
        return rc

    return 0

def dump_fw(p, pci_addr, tar_path):
    if p.poll() is not None:
        return

    line = read_line(p)
    if "state error" not in line:
        return

    date_time_str = datetime.now().strftime("%d.%m.%Y,%H:%M:%S")
    tar_name = date_time_str + "-mstregdump.tar.xz"

    cmd = "for i in {1..3}; do mstregdump %s > /tmp/mstregdump$i; done" % pci_addr
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out, err = p.communicate()

    cmd = "cd /tmp && tar cvJf %s/%s mstregdump[123]" % (tar_path, tar_name)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out, err = p.communicate()

    cmd = "rm -rf /tmp/mstregdump*"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

def main(cmdline=None):
    parser = make_parser()
    args = parser.parse_args()

    rc = verify_dependencies()
    if rc:
        return rc

    cmd = 'lspci | grep Mellanox | cut -d " " -f1'
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    pci_addr = read_line(p)

    cmd = "devlink monitor health"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

    while p.poll() is None:
        line = read_line(p)
        if "fw_fatal" in line:
            dump_fw(p, pci_addr, args.output_path)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
