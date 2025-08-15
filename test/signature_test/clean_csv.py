import pandas as pd
import sys

bin_intel = sys.argv[1]
if bin_intel not in ["bin", "intel"]:
    print("bad arg")
    exit()


if bin_intel == "intel":
    INPUT_FOLDER = "/home/user/projects/malware_res/flow_scanner/"
    OUTPUT_FOLDER = "/home/user/projects/malware_res/flow_scanner_cleaned/"
else:
    INPUT_FOLDER = "/home/user/projects/JITScanner_zone/test/signature_gen/traces/orig_bin/"
    OUTPUT_FOLDER = "/home/user/projects/JITScanner_zone/test/signature_gen/traces/"

if bin_intel == "intel":
    names = [
        'flow_full_trace_pack_page_intel64.csv',
        'flow_full_trace_pack_zone_intel64.csv',
        'flow_full_trace_plain_page_intel64.csv', 
        'flow_full_trace_plain_zone_intel64.csv'
    ]
else:
    names = [
        'flow_trace_page_bin.csv',
        'flow_trace_zone_bin.csv',
    ]

# List of CSV file paths
csv_files = [INPUT_FOLDER + name for name in names]

print("Reading everything...")
# Read the CSVs into DataFrames
dfs = [pd.read_csv(file, header=None) for file in csv_files]

print("Finding common filenames...")
# Get the sets of filenames from the second column (index 1)
filename_sets = [set(df[1]) for df in dfs]

# Find the intersection of filenames
common_filenames = set.intersection(*filename_sets)

print("Filtering...")

# Filter each DataFrame to keep only rows with common filenames
filtered_dfs = [df[df[1].isin(common_filenames)] for df in dfs]

print("Saving...")
# Save the filtered DataFrames back to CSV or process further
for i, filtered_df in enumerate(filtered_dfs):
    print(OUTPUT_FOLDER + names[i])
    filtered_df.to_csv(OUTPUT_FOLDER + names[i], index=False, header=False)

print("Filtering complete. Filtered files are saved.")
