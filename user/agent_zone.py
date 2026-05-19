from fcntl import ioctl
import time
import signal
import sys
# import yara
import ctypes
#import networkx as nx
#import matplotlib.pyplot as plt
#import numpy as np
from binascii import hexlify


RD_VALUE = 0xa038f001
GET_CFG_BY_PID = 0xa038f002

filename = "/dev/insp_device"

zone_sizes = []

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


def signal_handler(sig, frame):
    print("Gracefull exit")

    if (len(zone_sizes) == 0):
        sys.exit(0)

    np_zone_sizes = np.array(zone_sizes)
    print("Mean size of zones: ", np.mean(np_zone_sizes))

    sys.exit(0)

class Timespec64(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_longlong),
        ("tv_nsec", ctypes.c_long)
    ]

class Stats(ctypes.Structure):
    _fields_ = [
        ("num_of_control_instructions", ctypes.c_ulong),
        ("num_of_arithmetic_instructions", ctypes.c_ulong),
        ("num_of_logical_instructions", ctypes.c_ulong),
        ("num_of_data_transfer_instructions", ctypes.c_ulong),
        ("num_of_system_instructions", ctypes.c_ulong),
        ("num_of_miscellaneous_instructions", ctypes.c_ulong),
        ("num_of_vex_or_evex_instructions", ctypes.c_ulong)
    ]

class UserZone(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_char * 4096 * 2),  # PAGE_SIZE * MAX_PAGES, assuming PAGE_SIZE is 4096 and MAX_PAGES is 2
        ("pid", ctypes.c_int),
        ("ptid", ctypes.c_int),
        ("tid", ctypes.c_int),
        ("start_addr", ctypes.c_ulong),
        ("end_addr", ctypes.c_ulong),
        ("stats", Stats),
        ("ts", Timespec64),
        
    ]

def struct_to_dict(struct):
    return {field[0]: getattr(struct, field[0]) for field in struct._fields_}

NSEC_PER_SEC = 1e9  # Number of nanoseconds in a second

def timespec64_to_ns(ts):
    return int(ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec)
    
def create_id(tid, ts):
    # Convert tid and ts to string and concatenate them with an underscore
    id = str(tid) + "_" + str(ts)
    return id

# Perform a yara check on the pages
def zone_yara_check ():

#    rules = yara.compile('test/yabin_test/yabin.yar')

    buff = bytearray(ctypes.sizeof(UserZone))

    fd = open(filename, "wb")

    if fd == -1:
        print("Error opening file")
        sys.exit(1)
    
    print("Waiting from kernel...")

    while True:
        # print(hex(RD_VALUE))
        ioctl(fd, RD_VALUE, buff)

        uz = UserZone.from_buffer(buff)

        pid = uz.pid

        if (pid == 0):
            time.sleep(1)
        else:
            if pid == -1: #uncomment this if you want to exit when all zones have been read
                #print("All zones have been read")
                time.sleep(1)
                continue
                # break

            tid = uz.tid
            start_addr = uz.start_addr
            end_addr = uz.end_addr
            page_addr = start_addr & 0xfffffffffffff000

            stats_dict = struct_to_dict(uz.stats)
            timestamp = timespec64_to_ns(uz.ts)

            # hexdump(buff[:end_addr-start_addr])
            # print("PID: {}, TID: {}, Start Address: {:x}, End Address: {:x}, size : {}".format(pid, tid, start_addr, end_addr, end_addr - start_addr))
            # print("PID: {}, TID: {}, Start Address: {:x}, End Address: {:x}, Timestamp: {}, Stats: {}".format(pid, tid, start_addr, end_addr, timestamp, stats_dict))
#            time.sleep(0.1)
            zone_sizes.append(end_addr - start_addr)
 
            try:
                pass
                #if ("inject" in open("/proc/" + str(pid) + "/cmdline").read()):
                #print("DATA: ", bytes(buff[:end_addr - start_addr + 1]))
                #matches = rules.match(data=bytes(buff[:end_addr - start_addr]))
                # if matches or True:
                #     print("------------------")
                #     print("matches: ", matches)
                #     print("address", hex(page_addr))
                #     print("buff: ", hexlify(buff[:end_addr - start_addr]))
                #     print("pid", pid)
            except Exception:
                pass


            #np_zone_sizes = np.array(zone_sizes)
            #print("Mean size of zones: ", np.mean(np_zone_sizes))
    


def get_cfg ():

    # Create an empty dictionary to hold the graph
    cfg = []

    fd = open(filename, "wb")

    if fd == -1:
        print("Error opening file")
        sys.exit(1)

    print ("Waiting from kernel...")

    while True:
        # Read the cfg_node struct from the kernel

        buff = bytearray(ctypes.sizeof(UserZone))

        ioctl(fd, RD_VALUE, buff)
        
        uz = UserZone.from_buffer(buff)

        pid = uz.pid

        if pid == 0:
            time.sleep(1)
        else:
            if pid == -1:
                print("All zones have been read")
                break

            tid = uz.tid
            ptid = uz.ptid
            start_addr = uz.start_addr
            end_addr = uz.end_addr
            data=bytes(buff[:end_addr - start_addr])
            stats_dict = struct_to_dict(uz.stats)
            timestamp = timespec64_to_ns(uz.ts)

            #print("PID: {}, TID: {}, Start Address: {:x}, End Address: {:x}, Timestamp: {}, Stats: {}".format(pid, tid, start_addr, end_addr, timestamp, stats_dict))

            # Add the node
            if (pid != 0):
                cfg.append(uz)

    return cfg
            

def get_cfg_by_pid (pid):

        graph_by_pid = []
        
         # Create a UserZone instance with the given PID 
         # Convert the UserZone instance to a bytearray
        buff = bytearray(UserZone(pid=pid))
    
        fd = open(filename, "wb")
    
        if fd == -1:
            print("Error opening file")
            sys.exit(1)

        print ("Waiting from kernel...")

        while True:
            # Read the cfg_node struct from the kernel
            try:
                
                buff = bytearray(UserZone(pid=pid))

                ioctl(fd, GET_CFG_BY_PID, buff)
    
            except Exception:
                print("Error reading from kernel")
                break
    
        
            uz = UserZone.from_buffer(buff)

            if uz.pid == 0:
                time.sleep(1)
            else :
                if uz.pid == -1:
                    break

                if pid != uz.pid:
                    print("Error: pid mismatch")
                    break
                
                # fields of the uz struct
                tid = uz.tid
                start_addr = uz.start_addr
                end_addr = uz.end_addr
                page_addr = start_addr & 0xfffffffffffff000
                data=bytes(buff[:end_addr - start_addr])

                stats_dict = struct_to_dict(uz.stats)
                timestamp = timespec64_to_ns(uz.ts)

                print("PID: {}, TID: {}, Start Address: {:x}, End Address: {:x}, Timestamp: {}, Stats: {}".format(pid, tid, start_addr, end_addr, timestamp, stats_dict))

                if (pid != 0):
                    graph_by_pid.append(uz)

        return graph_by_pid

def create_and_display_cfg(cfg_nodes, prog_name):
            
    cfg_nodes.sort(key=lambda x: timespec64_to_ns(x.ts))

    print("Creating graph..., nodes are {}".format(len(cfg_nodes)))

    start_node = None
    end_node = None

     # Create a dictionary to store the last node of each thread
    last_node = {}

    # Create a new graph
    G = nx.DiGraph()
    
    for node in cfg_nodes:

        tid = node.tid
        pid = node.pid
        ptid = node.ptid
        timestamp = timespec64_to_ns(node.ts)

        #print("PID: {}, TID: {}, Timestamp: {}".format(pid, tid, timestamp))

        # Create a unique node id based on tid and timestamp
        node_id = str(tid) + "_" + str(node.start_addr)

        if start_node is None:
            start_node = node_id
        
        end_node = node_id

        # Add the node to the graph
        G.add_node(node_id, tid=tid, pid = pid, timestamp = timestamp)

        # If there is a last node for this thread, add an edge from the last node to this node
        if tid in last_node:
            G.add_edge(last_node[tid], node_id)


        if tid not in last_node and ptid in last_node:
            # This is the first node for this thread, so it should be a child node
            # Add an edge from the last node of the parent thread to this node
            G.add_edge(last_node[ptid], node_id)
            
        last_node[tid] = node_id


    # Display the graph
    plt.figure(figsize=(16, 9))
    # Initialize node_sizes to a list of 10s (or whatever size you want for regular nodes)
    node_sizes = [50 for _ in G.nodes()]

    # Get the indices of the start and end nodes
    start_node_index = list(G.nodes()).index(start_node)
    end_node_index = list(G.nodes()).index(end_node)

    # Set the sizes of the start and end nodes to a larger value
    node_sizes[start_node_index] = 150
    node_sizes[end_node_index] = 150    


    node_colors = ["green" if node == start_node else "red" if node != end_node else "blue" for node in G.nodes()]
    pos = nx.spring_layout(G)
    nx.draw(G, pos = pos, with_labels=False, node_size=node_sizes, node_color=node_colors, edge_color="blue")
    # Create a dictionary of labels for the start and end nodes
    labels = {start_node: "Start", end_node: "End"}
    # Adjust the y position of the labels
    label_pos = {node: (x, y+0.03) for node, (x, y) in pos.items() if node in labels}

    # Draw the labels for the start and end nodes
    nx.draw_networkx_labels(G, label_pos, labels=labels, font_color='black')
    # Set the title
    plt.title("Control Flow Graph")
    # Save the graph to a PDF file
    plt.savefig("test/efg_test/{}_graph.pdf".format(prog_name), format="pdf")
    # plt.show()

signal.signal(signal.SIGTERM, signal_handler)

# Perform a yara check on the pages
zone_yara_check()

# To build the EFG, we need to get the nodes from the kernel
# nodes = get_cfg()
# create_and_display_cfg(nodes, "clear")
#get_cfg_by_pid(11356)




