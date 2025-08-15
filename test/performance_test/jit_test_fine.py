from re import S
import subprocess
import sys
from time import sleep
import numpy as np
import os, shutil
import pandas as pd
import time

QEMU_ACTIVE = False
DYNAMORIO_ACTIVE = False
PIN_ACTIVE = False
if len(sys.argv) > 2 and sys.argv[2] == "qemu":
    QEMU_ACTIVE = True
    print("activating qemu")

if len(sys.argv) > 2 and sys.argv[2] == "dynamo":
    DYNAMORIO_ACTIVE = True
    print("activating dynamo")

if len(sys.argv) > 2 and sys.argv[2] == "pin":
    PIN_ACTIVE = True
    print("activating pin")

def run_command(cmd):
    # print(cmd)
    cmd_out = subprocess.run(cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
        shell=True,
        executable="/bin/bash")

    return cmd_out

def run_time_command(cmd, executions):
    if QEMU_ACTIVE:
        cmd = "qemu-x86_64 " + cmd
    elif DYNAMORIO_ACTIVE:
        cmd = "/home/user/DynamoRIO-Linux-11.90.20260/bin64/drrun -c /home/user/DynamoRIO-Linux-11.90.20260/samples/bin64/libempty.so -- " + cmd
        # cmd = "../dynamorio/DynamoRIO-Linux-10.93.20007/bin64/drrun -t drmemtrace -- " + cmd
    elif PIN_ACTIVE:
        cmd = "/home/user/pin/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin -- " + cmd

    print(cmd)
    full_command = f'time -p for i in $(seq 0 {executions}); do {cmd}; done;'
    timed_perf = run_command(full_command)
   

    # print("output, ", timed_perf)
    lines = timed_perf.stderr.split("\n")
    
    real_time = lines[-4].split(" ")[1]
    user_time = lines[-3].split(" ")[1]
    sys_time = lines[-2].split(" ")[1]
    
    real_time = float(real_time.replace(",", "."))
    user_time = float(user_time.replace(",", "."))
    sys_time = float(sys_time.replace(",", "."))

    return (real_time, user_time, sys_time)

class Language:
    def __init__(self, name, extension, run_cmd, jit, needs_build=False,build_cmd=None, out_build=None):
        self.name = name
        self.extension = extension
        self.run_cmd = run_cmd
        self.jit = jit
        self.needs_build = needs_build
        self.build_cmd = build_cmd
        self.out_build = out_build
    
    def __repr__(self):
        return f"Language({self.name}, JIT={self.jit})"

    def build(self, file):
        if self.needs_build:
            return run_command(self.build_cmd.format(file))
    
    def run(self, file, N):
        if self.needs_build:
            self.build(file)
            out = run_command(self.run_cmd.format(self.out_build, N))
            run_command(f"rm {self.out_build}")
            return out
        else:    
            return run_command(self.run_cmd.format(file, N))

    def time_run(self, file, N, executions):
        if self.needs_build:
            self.build(file)
            out = run_time_command(self.run_cmd.format(self.out_build, N), executions)
            run_command(f"rm {self.out_build}")
            return out
        else:    
            return run_time_command(self.run_cmd.format(file, N), executions)

TESTED_LANGUAGES = [
    # Language("C", ".c", "./{} {}", False, True, "gcc {} -o a.out -lm", "a.out"),
    #https://stitcher.io/blog/php-8-jit-setup
    # Language("PHP", ".php", "/usr/bin/php -dopcache.enable_cli=1 -dopcache.enable=1 -dopcache.jit_buffer_size=100M -dopcache.jit=1255 {} {}", True, False),
    Language("PYTHON", ".py", "/tmp/python3 {} {}", True, False),
    # Language("LuaJit", ".lua", "/usr/bin/luajit {} {}", True, False),
    # Language("Ruby", ".rb", "ruby --jit {} {}", True, False) # No WX pages????
]

#SRC_FOLDER = "/home/user/KAT/user/jit-benchmarks"
SRC_FOLDER = "/mnt/shared/KAT/user/jit-benchmarks"
len = len(SRC_FOLDER + "/")

TEST_NUMBER = 10

FILES = [
        "fasta",
        "matmul",
        "brainfuck",
        "fannkuchredux",
        "spectralnorm",
        "nbody",
        "binarytrees"
        ]
    
EXECUTIONS = {
    "C": {
        "fasta":1000000,
        "matmul":400,
        "fannkuchredux":10,
        "spectralnorm":1000,
        "binarytrees":15
    },
    "PHP": {
        "fasta":200000,
        "matmul":100,
        "fannkuchredux":9,
        "spectralnorm":250,
        "binarytrees":13
    },

    "PYTHON": {
        "fasta":100000,
        "matmul":150,
        "fannkuchredux":9,
        "spectralnorm":200,
        "binarytrees":10,
    },

    "LuaJit": {
        "fasta":1000000,
        "matmul":600,
        "fannkuchredux":10,
        "spectralnorm":2000,
        "binarytrees":13,
    },
    "Ruby": {
        "fasta":50000,
        "matmul":100,
        "fannkuchredux":9,
        "spectralnorm":200,
        "binarytrees":13
    },
}

time_info = {
        "Language": [],
        "Test Name": [],
        "Real Time": [],
        "User Time": [],
        "Sys Time": [],
        "N": [],
    }
print(f"Getting files from: {SRC_FOLDER}")
for root, subdirs, files in os.walk(SRC_FOLDER):
    for filename in files:
        file_path = os.path.join(root, filename)

        _, file_extension = os.path.splitext(file_path)
        
        for l in TESTED_LANGUAGES:
            #if "spectralnorm" in file_path:
            #    continue

            if not any([i in file_path for i in EXECUTIONS[l.name].keys()]):
                continue

            if l.extension == file_extension:
                
                print(f"Running test {l.name}-{root[len:]}\tExecutions: {EXECUTIONS[l.name][root[len:]]}\tTest size: {TEST_NUMBER}")
                
                for i in range(0, TEST_NUMBER):
                    real, user, sys_ = l.time_run(file_path, EXECUTIONS[l.name][root[len:]], 1)

                    time_info["Language"].append(l.name)
                    time_info["Test Name"].append(root[len:])
                    time_info["Real Time"].append(real)
                    time_info["User Time"].append(user)
                    time_info["Sys Time"].append(sys_)
                    time_info["N"].append(EXECUTIONS[l.name][root[len:]])

                    time.sleep(0.1)
                

                results = pd.DataFrame(time_info)

                print(results)                
                results.to_csv(sys.argv[1])
