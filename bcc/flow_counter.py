from bcc import BPF
import pyroute2
import time
import sys
import ctypes as ct
import struct
from socket import inet_ntop, AF_INET

flags = 0

def usage():
    print("Usage: {0} <ifdev>".format(sys.argv[0]))
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 2:
    usage()

if_name = sys.argv[1]

def int2ip(addr):
    return inet_ntop(AF_INET, struct.pack("I", addr))

ip = pyroute2.IPRoute()
if_idx = ip.link_lookup(ifname=if_name)[0]

# load BPF program
b = BPF(src_file="flow_counter.c", cflags=["-w"])
xdp_function = b.load_func("xdp_counter", BPF.XDP)
b.attach_xdp(sys.argv[1], xdp_function)

while 1:
    try:
        time.sleep(2)
        for k,v in sorted(b["rx_flows"].items()):
            print ("%s %u" % (int2ip(k.value), v.value))
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

b.remove_xdp(if_idx, flags)
