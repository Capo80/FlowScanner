from fcntl import ioctl
import struct
import time
import signal
import sys
#import yara
import ctypes
import threading
#import networkx as nx
#import matplotlib.pyplot as plt

RD_VALUE = 0x9010f001

filename = "/dev/insp_device"

def hexdump(data: bytes):
    def to_printable_ascii(byte):
        return chr(byte) if 32 <= byte <= 126 else "."

    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + 16]
        hex_values = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_values = "".join(to_printable_ascii(byte) for byte in chunk)
        print(f"{offset:08x}  {hex_values:<48}  |{ascii_values}|")
        offset += 16

def yara_check():
#    rules = yara.compile('test/yabin_test/yabin.yar')

    buff = bytearray(4096 + 8 + 4)

    fd = open(filename, "wb")

    if fd == -1:
        print("Error opening file")
        sys.exit(1)
    
    print("Waiting from kernel...")
    while True:
        
        ioctl(fd, RD_VALUE, buff)
        pid = struct.unpack("<i", buff[-4:])[0]
        address = struct.unpack("<Q", buff[-12:-4])[0]
        if (pid == 0):
            time.sleep(1)
        else:
            if pid == -1:
                # print("All pages have been read")
                time.sleep(1)
                continue

            # print("Contents: ")
            # hexdump(buff[:4096])
            # print("PID: {}, Address: {:x}".format(pid, address))
            try:
                # pass
                #if ("inject" in open("/proc/" + str(pid) + "/cmdline").read()):
#                matches = rules.match(data=bytes(buff[:4096]))
                if False:
                    print("------------------")
                    print("matches: ", matches)
                    print("address", hex(address))
                    print("pid", pid)
            except Exception:
                pass

yara_check()
