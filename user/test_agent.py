from fcntl import ioctl
import struct
import time
import signal
import sys
import os
import yara

def signal_handler(sig, frame):
    print("Gracefull exit")
    fd.close()
    sys.exit(0)

RD_VALUE = 0x9010f001

filename = "/dev/insp_device"
rules = yara.compile('rules.yar')
buff = bytearray(4096 + 8 + 4)

fd = open(filename, "wb")
print("Waiting from kernel...")
while True:

    ioctl(fd, RD_VALUE, buff)
    pid = struct.unpack("<i", buff[-4:])[0]
    address = struct.unpack("<Q", buff[-12:-4])[0]
    #flags = struct.unpack("<I", buff[-8:-4])[0]
    if (pid == 0):
        time.sleep(1)
    else:
        try:
            #write maps to file
            if (not os.path.exists("test_data/"+str(pid)+"_maps.txt")):
                with open("/proc/"+str(pid)+"/maps", "rb") as fr:
                    with open("test_data/"+str(pid)+"_maps.txt", "wb") as fw:
                        fw.write(fr.read())
            
            #write cmdline to file
            if (not os.path.exists("test_data/"+str(pid)+"_cdmline.txt")):
                with open("/proc/"+str(pid)+"/cmdline", "rb") as fr:
                    with open("test_data/"+str(pid)+"_cdmline.txt", "wb") as fw:
                        fw.write(fr.read())

            #save info on page
            if (not os.path.exists("test_data/"+str(pid)+"_pages.txt")):
                fw = open("test_data/"+str(pid)+"_pages.txt", "w")
            else:
                fw = open("test_data/"+str(pid)+"_pages.txt", "a")

            print("------------------")
            print("memory: ", buff[:8])
            print("pid", pid)
            print("address", hex(address))


            fw.write(str(pid) + ", " + str(hex(address)) + "\n")
            fw.close()
        except Exception as e: 
            print(e)



