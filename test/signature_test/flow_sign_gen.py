import pandas as pd
import json
import ast
import sys
from collections import Counter
import math

if len(sys.argv) < 3:
    print("Missing args")
    exit(-1)

split_train_test = sys.argv[1]
if  split_train_test == "25":
    MALWARE_TRAIN_TEST_SPLIT = 0.25
    GOODWARE_TRAIN_TEST_SPLIT = 0.25
elif split_train_test == "50":
    MALWARE_TRAIN_TEST_SPLIT = 0.50
    GOODWARE_TRAIN_TEST_SPLIT = 0.50
elif split_train_test == "75":
    MALWARE_TRAIN_TEST_SPLIT = 0.75
    GOODWARE_TRAIN_TEST_SPLIT = 0.75
elif split_train_test == "90":
    MALWARE_TRAIN_TEST_SPLIT = 0.90
    GOODWARE_TRAIN_TEST_SPLIT = 0.90
elif split_train_test == "100":
    MALWARE_TRAIN_TEST_SPLIT = 1
    GOODWARE_TRAIN_TEST_SPLIT = 1
else:
    print("bad args")
    exit(-1)

zone_page = sys.argv[2]
if  zone_page == "page":
    MALWARE_TRACE_FILE = "/home/user/projects/malware_res/flow_scanner_cleaned/flow_full_trace_plain_page_intel64.csv"
    GOODWARE_TRACE_FILE = "traces/flow_trace_page_bin.csv"
elif zone_page == "zone":
    # MALWARE_TRACE_FILE = "traces/flow_trace_zone_intel64.csv"
    MALWARE_TRACE_FILE = "/home/user/projects/malware_res/flow_scanner_cleaned/flow_full_trace_plain_zone_intel64.csv"
    GOODWARE_TRACE_FILE = "traces/flow_trace_zone_bin.csv"
else:
    print("bad args")
    exit(-1)

PROBE_NAME = "JITScanner"

OUT_FILE = f"signatures/flow_sign_{zone_page}_m{int(MALWARE_TRAIN_TEST_SPLIT*100)}_g{int(GOODWARE_TRAIN_TEST_SPLIT*100)}.py"

OUT_TRAIN_FILE = f"signatures/train_set_{zone_page}_m{int(MALWARE_TRAIN_TEST_SPLIT*100)}_g{int(GOODWARE_TRAIN_TEST_SPLIT*100)}.csv"

FAMILY_CSV = "traces/families.csv"
SIGNATURE_SIZE = 32 # signatures are hex encoded so size 32 is 16 bytes
OFFSET_MASK = 0b111111111111
SIGNATURE_BLACKLIST = ['00000000000000000000000000000000']
PAGE_SIZE = 0x1000*2 # page is saved as hex
SIGNATURE_HEADER = '''
#   ** SIGNATURE FILE AUTO-GENERATE BY JITS_SIGN_GEN **

'''

fd = open(OUT_FILE,"w")
fd.write(SIGNATURE_HEADER)
############################ Read Traces #######################################

print("Reading trace files...")

malware_df = pd.read_csv(MALWARE_TRACE_FILE)
goodware_df = pd.read_csv(GOODWARE_TRACE_FILE)

all_filenames = malware_df.iloc[:, 1].values

########################### Prepare family infomation #########################

print("Preparing family information...")

fam_df = pd.read_csv(FAMILY_CSV)
fam_df = fam_df[fam_df['File'].isin(all_filenames)]

fam_dict = dict(zip(fam_df['File'], fam_df['Folder']))

fam_train_len = Counter(fam_dict.values())

for key, value in fam_train_len.items():
    fam_train_len[key] = math.ceil(fam_train_len[key] * MALWARE_TRAIN_TEST_SPLIT) 


########################### Prepare training sets #############################

print("Preparing train sets...")


all_filenames = malware_df.iloc[:, 1].values
malware_train_filenames = {}
for file in all_filenames:
    if fam_train_len[fam_dict[file]] == 0:
        malware_train_filenames[file] = False
    else:
        malware_train_filenames[file] = True 
        fam_train_len[fam_dict[file]] -= 1

all_filenames = goodware_df.iloc[:, 1].values
goodware_train_filenames = {}
for file in all_filenames[:int(len(all_filenames)*GOODWARE_TRAIN_TEST_SPLIT)]:
    goodware_train_filenames[file] = False


train_df = pd.DataFrame.from_dict(malware_train_filenames, orient="index")
train_df.to_csv(OUT_TRAIN_FILE)

################################# Get malware signatures ######################

print("Getting malware signatures...")

signatures = {}
total_signatures = 0
non_error_files = 0
total_filenames = 0
train_filenames = 0
for index, row in malware_df.iterrows():
   
    if "ERROR" in row[4]:
        continue

    # get the json into python dict
    full_result_json = ast.literal_eval(row[4])
    
    # Extract required fields
    probe_results = full_result_json['probe_results']
    antivirus_results = probe_results['antivirus'][PROBE_NAME]
    
    detection_result = antivirus_results['status']
    filename = row[1]

    total_filenames += 1
    # use only training set
    if malware_train_filenames.get(filename) is None or not malware_train_filenames.get(filename):
        continue
    
    train_filenames += 1
    if detection_result != -1:
        
        signatures[filename] = []
        # trace = antivirus_results["results"]["matches_raw"]
        trace = antivirus_results["results"]["full_data"]
        
        for address, page in trace.items():

            start_offset = int(address, 16) & OFFSET_MASK
            if (start_offset + SIGNATURE_SIZE) > PAGE_SIZE:
                end_offset = PAGE_SIZE
            else:
                end_offset = start_offset + SIGNATURE_SIZE

            #print(address, "\t", hex(start_offset),  hex(end_offset), page[start_offset:end_offset])
            if page[start_offset:end_offset] not in SIGNATURE_BLACKLIST:
                signatures[filename].append(page[start_offset:end_offset])
                total_signatures += 1
        non_error_files += 1


print(f"Recovered {total_signatures} signatures from {non_error_files} files")
print(f"Test filenames: {train_filenames}/{total_filenames}")
############################## PREPARE STRUCTS ################################

print("Preparing signatures structs...")

signature_nbr = {}
signature_match = {}
for filename, value in signatures.items():
    if len(value) != 0:
        signature_nbr[filename] = len(value)
        for sign in value:
            signature_match[sign] = filename

############################## REMOVE GOODWARE SIGNATURES ####################

# df = pd.read_csv(GOODWARE_TRACE_FILE)

# # Iterate through each row
# deteleted_signatures = 0
# for index, row in df.iterrows():
    
#     # get the json into python dict
#     full_result_json = ast.literal_eval(row[4])
    
#     # Extract required fields
#     probe_results = full_result_json['probe_results']
#     antivirus_results = probe_results['antivirus'][PROBE_NAME]
    
#     detection_result = antivirus_results['status']
#     filename = row[1]
    
#     if detection_result != -1:
        
#         signatures[filename] = []
#         trace = antivirus_results["results"]["matches_raw"]
        
#         for address, page in trace.items():

#             start_offset = int(address, 16) & OFFSET_MASK
#             if (start_offset + SIGNATURE_SIZE) > PAGE_SIZE:
#                 end_offset = PAGE_SIZE
#             else:
#                 end_offset = start_offset + SIGNATURE_SIZE

#             #print(address, "\t", hex(start_offset),  hex(end_offset), page[start_offset:end_offset])
#             sign = page[start_offset:end_offset]
#             if signature_match.get(sign) is not None:
#                 filename = signature_match[sign]
#                 signature_nbr[filename] -= 1

#                 #print(sign, signature_match[sign])
              
#                 if signature_nbr[filename] == 0:
#                     del signature_nbr[filename]

#                 del signature_match[sign]

#                 deteleted_signatures += 1

########################## GOODWARE SIGNATURES REMOVAL ###########################

print("Removing goodware sigatures...")

deteleted_signatures = 0
for index, row in goodware_df.iterrows():
    
    # get the json into python dict
    full_result_json = ast.literal_eval(row[4])
    
    # Extract required fields
    probe_results = full_result_json['probe_results']
    antivirus_results = probe_results['antivirus'][PROBE_NAME]
    
    detection_result = antivirus_results['status']
    filename = row[1]

    # use only training set
    if goodware_train_filenames.get(filename) is None:
        continue

    # print("Index: ", index)

    if detection_result != -1:
        
        trace = antivirus_results["results"]["matches_raw"]
        
        for address, page in trace.items():

            for i in range(0, PAGE_SIZE-SIGNATURE_SIZE, 2):

                # if we find a signature in a goodware it is not a good signature
                if signature_match.get(page[i:i+SIGNATURE_SIZE]) is not None:
                    
                    del signature_match[page[i:i+SIGNATURE_SIZE]]
                    deteleted_signatures += 1
        

print(f"Deleted {deteleted_signatures} signatures...")

fd.write(f"sign_info = {signature_nbr}\n\n")
fd.write(f"sign_match = {signature_match}\n\n")
fd.write(f"MALWARE_TRAIN_TEST_SPLIT = {MALWARE_TRAIN_TEST_SPLIT}\n\n")
fd.write(f"GOODWARE_TRAIN_TEST_SPLIT = {GOODWARE_TRAIN_TEST_SPLIT}\n\n")

fd.close()
