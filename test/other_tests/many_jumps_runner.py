import subprocess
import csv
import os

# --- Configuration ---
BINARY_PATH = "./a.out"
DYNAMO_PATH = "/home/user/DynamoRIO-Linux-11.90.20260/bin64/drrun"
DYNAMO_SO   = "/home/user/DynamoRIO-Linux-11.90.20260/samples/bin64/libempty.so"
PIN_PATH    = "/home/user/pin/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin"

# Parameters
K_JUMPS    = [1, 10, 100, 1000]
NOPS       = [0, 5, 10, 15, 30]
ITER_VALS  = [1, 2, 5, 10]

METHODS = {
    "Native":  lambda k, n, x: [BINARY_PATH, str(k), str(n), str(x)],
    "QEMU":    lambda k, n, x: ["qemu-x86_64", BINARY_PATH, str(k), str(n), str(x)],
    "Dynamo":  lambda k, n, x: [DYNAMO_PATH, "-c", DYNAMO_SO, "--", BINARY_PATH, str(k), str(n), str(x)],
    "Pin":     lambda k, n, x: [PIN_PATH, "--", BINARY_PATH, str(k), str(n), str(x)]
}

def run_test(method_name, k, nops, x):
    cmd = METHODS[method_name](k, nops, x)
    try:
        # 5-minute timeout for heavy instrumentation overhead
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in result.stdout.split('\n'):
            if "Total Cycles:" in line:
                return int(line.split(":")[1].strip())
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception:
        return "ERROR"
    return "FAIL"

def main():
    if not os.path.exists(BINARY_PATH):
        print(f"Error: {BINARY_PATH} not found. Compile jump_program.c first.")
        return

    results = []
    print(f"{'Method':<10} | {'K':<5} | {'Nop':<4} | {'X':<3} | {'Avg CPJ'}")
    print("-" * 45)

    for k in K_JUMPS:
        for n in NOPS:
            for x in ITER_VALS:
                for name in METHODS.keys():
                    cycles = run_test(name, k, n, x)
                    
                    if isinstance(cycles, int):
                        total_exec_jumps = k * 1000 * x
                        cpj = cycles / total_exec_jumps
                        cpj_str = f"{cpj:.2f}"
                    else:
                        cpj_str = str(cycles)

                    print(f"{name:<10} | {k:<5} | {n:<4} | {x:<3} | {cpj_str}")
                    results.append([name, k, n, x, cycles, cpj_str])

    # Save to CSV
    csv_file = "multi_method_results.csv"
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Method", "K_Jumps", "Nops", "Iterations", "Total_Cycles", "Avg_CPJ"])
        writer.writerows(results)

    print(f"\nDone. Results saved to {csv_file}")

if __name__ == "__main__":
    main()
