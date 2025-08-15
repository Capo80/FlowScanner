
import pandas as pd
import json
import ast
import sys
import importlib
import os

TRACE_FOLDER = "/home/user/projects/malware_res/flow_scanner/"
# JITScanner signatures

if len(sys.argv) < 2:
    print("misssing args")
    exit(-1)

name = sys.argv[1]
if  name == "page" or name == "zone":
    TRACE_FILE = os.path.join(TRACE_FOLDER, f"flow_full_trace_pack_{name}_intel64.csv")
else:
    print("bad args")
    exit(1)

PROBE_NAME = "JITScanner"

FAMILY_CSV = "traces/families.csv"

OFFSET_MASK = 0b111111111111
PAGE_SIZE = 0x1000*2
PAGE_MASK = (~((PAGE_SIZE//2)-1))
SIGNATURE_SIZE = 32

############################ Prepare family imformation #######################

print("Preparing family information...")

fam_df = pd.read_csv(FAMILY_CSV)
fam_dict = dict(zip(fam_df['File'], fam_df['Folder']))

################################# Prepare traces #############################

print("Reading traces...")

df = pd.read_csv(TRACE_FILE)

all_filenames = df.iloc[:, 1].values

########################### Test signatures ###################################

total_packed = 0
total = 0
family_packed = dict.fromkeys(fam_df['Folder'], 0)
family_total = dict.fromkeys(fam_df['Folder'], 0)
missing_family = 0
page_seen = {
    "filename" : [],
    "page_seen" : [],
}

print("Checking traces...")
i = 0
for index, row in df.iterrows():
    
    # get the json into python dict
    if "ERROR" in row[4]:
        continue
    full_result_json = ast.literal_eval(row[4])

    # Extract required fields
    probe_results = full_result_json['probe_results']
    antivirus_results = probe_results['antivirus'][PROBE_NAME]
    
    detection_result = antivirus_results['status']
    filename = row[1]

    if detection_result != -1:
        
        trace = antivirus_results["results"]["full_data"]
        
        # if "dadd" in filename:
        #     print(trace)
        already_matched = {}
        total_pages = {}
        c = 0

        if fam_dict.get(filename) is None:
            # print("Mssing file", filename)
            missing_family += 1
            continue

        pack_first_page = trace.get("0x4000e8")
        if pack_first_page is not None:
            total_packed += 1

            family_packed[fam_dict.get(filename)] += 1


        family_total[fam_dict.get(filename)] += 1


        total += 1
    i += 1

    # if i >= 200:
    #     exit()
    #

# page_df = pd.DataFrame(page_seen)
# page_df.to_csv(f"test_outputs/page_seen_{name}_{sys.argv[3]}_{sys.argv[2]}.csv")

print("Completed analysis, getting results...")

for family in family_total.keys():

    print(f"{family}: {family_packed.get(family)}/{family_total.get(family)}")

print(f"\nTotal: {total_packed}/{total}")

print("Missing family:", missing_family)



