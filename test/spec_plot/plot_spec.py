
import matplotlib.pyplot as plt
import numpy as np

benchmarks = [
    "perlbench", "gcc", "mcf", "omnetpp",
    "xalancbmk", "x264", "deepsjeng",
    "leela_s", "exchange2", "xz"
]

base_time = np.array([422, 672, 906, 614, 566, 317, 499, 567, 322, 3466], dtype=float)
qemu_time = np.array([3205, 3597, 2496, 2159, 1685, 3236, 2367, 2019, 1680, 7946], dtype=float)
dynamo_time = np.array([708, 1014, 1042, 720, 836, 386, 613, 624, 348, 3895], dtype=float)
pin_time = np.array([916, 1196, 1085, 800, 748, 433, 709, 712, 390, 4073], dtype=float)
flowscanner_time = np.array([423, 672, 906, 614, 566, 317, 499, 571, 324, 3466], dtype=float)

# Replace 0 (missing) with np.nan
qemu_time[qemu_time == 0] = np.nan
dynamo_time[dynamo_time == 0] = np.nan
pin_time[pin_time == 0] = np.nan

# Normalize by baseline
qemu_norm = qemu_time / base_time
dynamo_norm = dynamo_time / base_time
pin_norm = pin_time / base_time
flowscanner_norm = flowscanner_time / base_time
base_norm = base_time / base_time  # all ones

# Bar setup
bar_width = 0.15
index = np.arange(len(benchmarks))

# Blue color palette
colors = {
    'Base': '#1f4e79',
    'Qemu': '#74a9cf',
    'DynamoRIO': '#2b6cb0',
    'Pin': '#08306b',
    'FlowScanner': '#a6bddb'
}

# Increase font sizes here
plt.rcParams.update({
    'axes.titlesize': 22,
    'axes.labelsize': 22,
    'xtick.labelsize': 20,
    'ytick.labelsize': 20,
    'legend.fontsize': 20,
    'figure.titlesize': 24
})

plt.figure(figsize=(14, 7))

plt.bar(index, base_norm, bar_width, color=colors['Base'], label='Baseline')
plt.bar(index + bar_width, qemu_norm, bar_width, color=colors['Qemu'], label='Qemu')
plt.bar(index + 2 * bar_width, dynamo_norm, bar_width, color=colors['DynamoRIO'], label='DynamoRIO')
plt.bar(index + 3 * bar_width, pin_norm, bar_width, color=colors['Pin'], label='Pin')
plt.bar(index + 4 * bar_width, flowscanner_norm, bar_width, color=colors['FlowScanner'], label='FlowScanner')

plt.axhline(1, color='black', linestyle='--', linewidth=0.8, alpha=0.7)
# print(index)
# print(index + 2 * bar_width)
# print(benchmarks)
plt.xlabel('Benchmark')
plt.ylabel('Normalized Execution Time')
plt.title('Normalized Execution Time Comparison (Baseline = 1.0)')
plt.xticks(index + 2* bar_width, benchmarks, rotation=45, ha="right", rotation_mode='anchor')

# Cap Y-axis at 2.0 for better comparison visibility
plt.ylim(0, 2.5)

plt.legend()
plt.grid(axis='y', linestyle='--', alpha=0.5)

plt.tight_layout(pad=1)

# Save figure with tight bounding box to cut white space
plt.savefig('spec_execution_time.pdf', bbox_inches='tight', dpi=300)

plt.show()

