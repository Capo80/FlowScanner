import subprocess
import csv
import os
import sys

# --- Configuration ---
BINARY_PATH = "./a.out"

# Parameters to test
K_JUMPS    = [1, 10, 100, 1000]
NOPS       = [0, 5, 10, 15, 30]
ITER_VALS  = [1, 2, 5, 10]

def run_native_test(k, nops, iters):
    """Executes: ./jump_program <K> <Nops> <Iters>"""
    cmd = [BINARY_PATH, str(k), str(nops), str(iters)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        for line in result.stdout.split('\n'):
            if "Total Cycles:" in line:
                return int(line.split(":")[1].strip())
    except Exception as e:
        return f"ERROR"
    return "FAIL"

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <label_for_csv>")
        return

    csv_label = sys.argv[1]

    if not os.path.exists(BINARY_PATH):
        print(f"Error: Compile the C code first: gcc -O0 jump_program.c -o jump_program")
        return

    results = []
    
    # Updated Header
    print(f"{'Label':<12} | {'K':<4} | {'Nop':<3} | {'Iters':<5} | {'Total Cycles':<14} | {'Avg CPJ'}")
    print("-" * 72)

    for k in K_JUMPS:
        for n in NOPS:
            for x in ITER_VALS:
                cycles = run_native_test(k, n, x)
                
                if isinstance(cycles, int):
                    # Total Jumps = (K * 1000) * X
                    total_exec_jumps = k * 1000 * x
                    cpj = cycles / total_exec_jumps
                    cpj_str = f"{cpj:.4f}"
                else:
                    cpj_str = "N/A"

                print(f"{csv_label:<12} | {k:<4} | {n:<3} | {x:<5} | {str(cycles):<14} | {cpj_str}")
                results.append([csv_label, k, n, x, cycles, cpj_str])

    # Save/Append to CSV
    csv_file = "multi_iter_benchmark.csv"
    file_exists = os.path.isfile(csv_file)
    
    with open(csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Label", "K_Jumps", "Nops", "Iterations", "Total_Cycles", "Avg_CPJ"])
        writer.writerows(results)
    
    print(f"\nResults appended to {csv_file}")

if __name__ == "__main__":
    main()
