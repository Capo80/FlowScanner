import pandas as pd
import json
import ast
import sys
import importlib
import csv
from collections import Counter
# JITScanner signatures

# arg1 = tp or fp, true or false positives
# arg2 = 25, 50, 75, 90, split train/test
# arg3 = zone, page, traces to test
# arg4 = zone, page, signature to use
# arg5  = plain/pack, plain or packed samples

if len(sys.argv) < 6:
    print("misssing args")
    exit(-1)


zone = sys.argv[3]
if zone != "zone" and zone != "page":
    print("bad arg 3")
    exit()

pack = sys.argv[5]
if pack != "plain" and pack != "pack":
    print("bad args 5")
    exit()

if sys.argv[1] == "tp":
    name = "intel64"
    TRACE_FILE = f"/home/user/projects/malware_res/flow_scanner_cleaned/flow_full_trace_{pack}_{zone}_intel64.csv"
elif sys.argv[1] == "fp":
    name = "bin"
    TRACE_FILE = f"traces/flow_trace_{zone}_bin.csv"
else:
    print("bad args")
    exit(1)


split_train_test = sys.argv[2]
if split_train_test not in ["25", "50", "75", "90"]:
    print("bad split")
    exit(-1)

sign_file = sys.argv[4]
if sign_file == "own":
    sign_file = sys.argv[3]

js = importlib.import_module(f"signatures.flow_sign_{sign_file}_m{split_train_test}_g{split_train_test}")

OUTPUT = "test_outputs/" + zone + "_" + "sign" + sign_file + "_" + split_train_test + "_" + pack + f"_{name}.json"

TRAIN_FILE = f"signatures/train_set_{sign_file}_m{split_train_test}_g{split_train_test}.csv"
split_train_test = int(split_train_test)/100

PROBE_NAME = "JITScanner"

FAMILY_CSV = "traces/families.csv"


# match percentage
EASY_MATCH_PERC = 0.25 
MEDIUM_MATCH_PERC = 0.50
HARD_MATCH_PERC = 0.75 

OFFSET_MASK = 0b111111111111
PAGE_SIZE = 0x1000*2
PAGE_MASK = (~((PAGE_SIZE//2)-1))
SIGNATURE_SIZE = 32

############################ Prepare family imformation #######################

print("Preparing family information...")

fam_df = pd.read_csv(FAMILY_CSV)
fam_dict = dict(zip(fam_df['File'], fam_df['Folder']))

########################### Prepare training sets #############################

print("Preparing train sets...")
df = pd.read_csv(TRACE_FILE)
all_filenames = df.iloc[:, 1].values

if name == "intel64":
    train_dict={}
    with open(TRAIN_FILE,'r') as f:
        reader = csv.reader(f)
        next(reader) # toss headers
        for file, train in reader:
            train_dict[file] = eval(train)

    print(Counter(train_dict.values()))

    test_filenames = {}
    for file in all_filenames:
        # print(file, train_dict[file])
        if file not in train_dict:
            test_filenames[file] = True 
        else:
            test_filenames[file] = not train_dict[file]
else:
    test_filenames = {}
    for i, file in enumerate(all_filenames):
        if i < int(len(all_filenames)*split_train_test):
            test_filenames[file] = False
        else:
            test_filenames[file] = True

########################### Test signatures ###################################

detections = {}
offset_info = {
    "filename" : [],
    "land_page" : [],
    "land_address" : [],
    "matched_offset" : [],
    "matched_file" : [],
    "matched_family" : [],
    "matched_signature" : [],
    "zone_lenght" : [],
    "distance" : [],
}

page_seen = {
    "filename" : [],
    "page_seen" : [],
}
total_test_samples = 0
for index, row in df.iterrows():
    
    if "ERROR" in row[4]:
        continue

    # get the json into python dict
    full_result_json = ast.literal_eval(row[4])
    
    # Extract required fields
    probe_results = full_result_json['probe_results']
    antivirus_results = probe_results['antivirus'][PROBE_NAME]
    
    detection_result = antivirus_results['status']
    filename = row[1]

    # skip train set filenames and filenames we don't have signatures for
    if test_filenames.get(filename) is not None and not test_filenames[filename]:
        continue
    
    total_test_samples += 1
    detections[filename] = {}
    if detection_result != -1:
        
        # print(TRACE_FILE)
        if name == "intel64":
            trace = antivirus_results["results"]["full_data"]
        else:
            trace = antivirus_results["results"]["matches_raw"]

        # if "dadd" in filename:
        #     print(trace)
        already_matched = {}
        total_pages = {}
        for address, page in trace.items():
            # ignore packer
            if address[:3] != "0x4":
                continue
            total_pages[address[:-3]] = True
            found = False

            for i in range(0, len(page)-SIGNATURE_SIZE, 2):

                if js.sign_match.get(page[i:i+SIGNATURE_SIZE]) is not None:
                    
                    sign = page[i:i+SIGNATURE_SIZE]

                    if already_matched.get(sign) is not None: # Match signature only once
                        continue
                    
                    matched_file = js.sign_match[sign] 

                    # match only if its the same family
                    if name == "intel64" and fam_dict.get(matched_file) is None:
                        print("MIssing file", matched_file)
                        continue
                    
                    if name == "intel64" and fam_dict.get(filename) is None:
                        print("MIssing file", filename)
                        continue

                    # print(fam_dict[filename],fam_dict[matched_file])
                    if name == "intel64"and fam_dict[filename] == fam_dict[matched_file]:
                        continue


                    already_matched[sign] = True
                   


 
                    matched_address = (int(address,16) & PAGE_MASK) +i
                    offset_info["filename"].append(filename)
                    offset_info["land_page"].append(address[:-3] + "000")
                    offset_info["land_address"].append(address)
                    offset_info["matched_file"].append(matched_file)
                    offset_info["matched_family"].append(fam_dict.get(filename))
                    #offset_info["matched_offset"].append(hex(matched_address))
                    offset_info["matched_offset"].append(hex(i))
                    offset_info["zone_lenght"].append(hex(len(page)))
                    offset_info["matched_signature"].append(sign)
                    offset_info["distance"].append(hex(matched_address - int(address,16)))
                    found = True
                    
                    if detections[filename].get(matched_file) is None:
                        detections[filename][matched_file] = 1
                    else:
                        detections[filename][matched_file] += 1

            if not found:
                offset_info["filename"].append(filename)
                offset_info["land_page"].append(address[:-3] + "000")
                offset_info["land_address"].append(address)
                offset_info["matched_file"].append("NONE")
                #offset_info["matched_offset"].append(hex(matched_address))
                offset_info["matched_offset"].append("NONE")
                offset_info["zone_lenght"].append(hex(len(page)))
                offset_info["matched_signature"].append("NONE")
                offset_info["distance"].append("NONE")
                
        # check if we even have pages intercepted 
        if len(total_pages) == 0:
            del detections[filename]
        page_seen["filename"].append(filename)
        page_seen["page_seen"].append(len(total_pages))


page_df = pd.DataFrame(page_seen)
page_df.to_csv(f"test_outputs/page_seen_{name}_{zone}_{pack}_{split_train_test}.csv")

print("Completed analysis, getting results...")

running_samples = 0
matched_samples = 0
match_easy = 0
match_medium = 0
match_hard = 0
for filename, det in detections.items():
    running_samples += 1
    
    if det != {}:
        matched_samples += 1
        for matched_file, matches in det.items():
            #print(matched_file, matches, int(js.sign_info[matched_file]*HARD_MATCH_PERC))
            if matches > int(js.sign_info[matched_file]*HARD_MATCH_PERC):
                #print(matches,"/", js.sign_info[matched_file])
                match_easy += 1
                match_medium += 1
                match_hard += 1
                break
            if matches > int(js.sign_info[matched_file]*MEDIUM_MATCH_PERC):
                #print(matches,"/", js.sign_info[matched_file])
                match_medium += 1
                match_easy += 1
                break
            if matches > int(js.sign_info[matched_file]*EASY_MATCH_PERC):
                # print(matches,"/", js.sign_info[matched_file])
                match_easy += 1
                break

print("Total Filenames: ", len(all_filenames))
print("Total Test set samples: ", total_test_samples)

print(f"Running samples: {running_samples}/{total_test_samples}")
print(f"Percentange Running samples {running_samples/total_test_samples*100}")

print(f"At least one matched samples: {matched_samples}/{running_samples}")
print(f"Percentange At least one matched samples {matched_samples/running_samples*100}")

# print(f"Easy matched samples: {match_easy}/{running_samples}")
# print(f"Percentange Easy matched samples {match_easy/running_samples*100}")

# print(f"Medium matched samples: {match_medium}/{running_samples}")
# print(f"Percentange Medium matched samples {match_medium/running_samples*100}")

# print(f"Hard matched samples: {match_hard}/{running_samples}")
# print(f"Percentange Hard matched samples {match_hard/running_samples*100}")


with open(OUTPUT, "w") as fd:
    fd.write(json.dumps(detections, indent=2))
#
# #print(offset_info)
# df = pd.DataFrame(offset_info)
# print(df)
# df.to_csv(f"test_outputs/offset_info_{name}_{sys.argv[3]}_{sys.argv[2]}.csv")

## FULL SAMPLES

# TRUE 25 % - PLAIN

# PAGE
# Total Filenames:  2752
# Total Test set samples:  2064
# Running samples: 1954/2064
# Percentange Running samples 94.67054263565892
# At least one matched samples: 1888/1954
# Percentange At least one matched samples 96.62231320368475

# ZONE
# Total Filenames:  1416
# Total Test set samples:  1062
# Running samples: 1012/1062
# Percentange Running samples 95.29190207156309
# At least one matched samples: 916/1012
# Percentange At least one matched samples 90.51383399209486

# FILE
# Total Test set samples:  1443
# Matched samples: 407/1443
# Percentage Matched samples 28.205128205128204

## TRUE 25 % - PLAIN > 10 

# Total Filenames:  2752
# Total Test set samples:  2064
# Running samples: 1064/2064
# Percentange Running samples 51.55038759689923
# At least one matched samples: 929/1064
# Percentange At least one matched samples 87.31203007518798

# Total Filenames:  1416
# Total Test set samples:  1062
# Running samples: 582/1062
# Percentange Running samples 54.80225988700565
# At least one matched samples: 460/582
# Percentange At least one matched samples 79.0378006872852

# TRUE 25 % - PACK

# PAGE
# Completed analysis, getting results...
# Total Filenames:  2778
# Total Test set samples:  2084
# Running samples: 2063/2084
# Percentange Running samples 98.99232245681382
# At least one matched samples: 2063/2063
# Percentange At least one matched samples 100.0

# ZONE
# Total Filenames:  2923
# Total Test set samples:  2055
# Running samples: 2053/2055
# Percentange Running samples 99.90267639902677
# At least one matched samples: 2053/2053
# Percentange At least one matched samples 100.0

# FALSE 25% - BIN

# PAGE
# Total Filenames:  772
# Total Test set samples:  579
# Running samples: 546/579
# Percentange Running samples 94.30051813471503
# At least one matched samples: 62/546
# Percentange At least one matched samples 11.355311355311356

# ZONE
# Total Filenames:  772
# Total Test set samples:  579
# Running samples: 546/579
# Percentange Running samples 94.30051813471503
# At least one matched samples: 62/546
# Percentange At least one matched samples 11.355311355311356



## NEW

## TRUE POS

## 25 % TRAIN
# Total Test set samples:  136
# Running samples: 92/136
# Percentange Running samples 67.64705882352942
# At least one matched samples: 69/92
# Percentange At least one matched samples 75.0
# Easy matched samples: 41/92
# Percentange Easy matched samples 44.565217391304344
# Medium matched samples: 18/92
# Percentange Medium matched samples 19.565217391304348
# Hard matched samples: 5/92
# Percentange Hard matched samples 5.434782608695652

## 50% TRAIN
# Total Test set samples:  91
# Running samples: 64/91
# Percentange Running samples 70.32967032967034
# At least one matched samples: 55/64
# Percentange At least one matched samples 85.9375
# Easy matched samples: 30/64
# Percentange Easy matched samples 46.875
# Medium matched samples: 17/64
# Percentange Medium matched samples 26.5625
# Hard matched samples: 5/64
# Percentange Hard matched samples 7.8125

## 75% TRAIN
# Total Test set samples:  46
# Running samples: 34/46
# Percentange Running samples 73.91304347826086
# At least one matched samples: 28/34
# Percentange At least one matched samples 82.35294117647058
# Easy matched samples: 16/34
# Percentange Easy matched samples 47.05882352941176
# Medium matched samples: 10/34
# Percentange Medium matched samples 29.411764705882355
# Hard matched samples: 2/34
# Percentange Hard matched samples 5.88235294117647

# FALSE_POS

## 25% TRAIN
# Completed analysis, getting results...
# Total Test set samples:  579
# Running samples: 546/579
# Percentange Running samples 94.30051813471503
# At least one matched samples: 39/546
# Percentange At least one matched samples 7.142857142857142
# Easy matched samples: 0/546
# Percentange Easy matched samples 0.0
# Medium matched samples: 0/546
# Percentange Medium matched samples 0.0
# Hard matched samples: 0/546
# Percentange Hard matched samples 0.0

## 50% TRAIN
# Total Test set samples:  386
# Running samples: 364/386
# Percentange Running samples 94.30051813471503
# At least one matched samples: 9/364
# Percentange At least one matched samples 2.4725274725274726
# Easy matched samples: 0/364
# Percentange Easy matched samples 0.0
# Medium matched samples: 0/364
# Percentange Medium matched samples 0.0
# Hard matched samples: 0/364
# Percentange Hard matched samples 0.0

## 75% TRAIN
# Total Test set samples:  193
# Running samples: 182/193
# Percentange Running samples 94.30051813471503
# At least one matched samples: 4/182
# Percentange At least one matched samples 2.197802197802198
# Easy matched samples: 0/182
# Percentange Easy matched samples 0.0
# Medium matched samples: 0/182
# Percentange Medium matched samples 0.0
# Hard matched samples: 0/182
# Percentange Hard matched samples 0.0

## 90%
# Completed analysis, getting results...
# Total Test set samples:  78
# Running samples: 76/78
# Percentange Running samples 97.43589743589743
# At least one matched samples: 2/76
# Percentange At least one matched samples 2.631578947368421
# Easy matched samples: 0/76
# Percentange Easy matched samples 0.0
# Medium matched samples: 0/76
# Percentange Medium matched samples 0.0
# Hard matched samples: 0/76
# Percentange Hard matched samples 0.0

## OLD

# /usr/bin
# Completed analysis, getting results...
# Total Test set samples:  528
# Running samples: 507/528
# Percentange Running samples 96.02272727272727
# At least one matched samples: 440/507
# Percentange At least one matched samples 86.78500986193293
# Easy matched samples: 0/507
# Percentange Easy matched samples 0.0
# Medium matched samples: 0/507
# Percentange Medium matched samples 0.0
# Hard matched samples: 0/507
# Percentange Hard matched samples 0.0

# 75% TRAIN
# Total Test set samples:  30
# Running samples: 30/30
# Percentange Running samples 100.0
# At least one matched samples: 30/30
# Percentange At least one matched samples 100.0
# Easy matched samples: 14/30
# Percentange Easy matched samples 46.666666666666664
# Medium matched samples: 3/30
# Percentange Medium matched samples 10.0
# Hard matched samples: 0/30
# Percentange Hard matched samples 0.0

# 50% TRAIN
# Total Test set samples:  59
# Running samples: 59/59
# Percentange Running samples 100.0
# At least one matched samples: 50/59
# Percentange At least one matched samples 84.7457627118644
# Easy matched samples: 21/59
# Percentange Easy matched samples 35.59322033898305
# Medium matched samples: 7/59
# Percentange Medium matched samples 11.864406779661017
# Hard matched samples: 0/59
# Percentange Hard matched samples 0.0


# 90% TRAIN
# Total Test set samples:  12
# Running samples: 12/12
# Percentange Running samples 100.0
# At least one matched samples: 12/12
# Percentange At least one matched samples 100.0
# Easy matched samples: 5/12
# Percentange Easy matched samples 41.66666666666667
# Medium matched samples: 2/12
# Percentange Medium matched samples 16.666666666666664
# Hard matched samples: 0/12
# Percentange Hard matched samples 0.0
