import os
import sys
from binascii import hexlify
import json
import importlib
import csv

SIGNATURE_SIZE = 32 

if sys.argv[1] == "tp":
    DIRECTORY = "/home/user/full_malware_elf/intel_malware_done/"
    name = "intel64"
elif sys.argv[1] == "fp":
    DIRECTORY = "/tmp/usr_bin_copy"
    name = "bin"
else:
    print("bad args")
    exit(1)

split_train_test = sys.argv[2]
if split_train_test not in ["25", "50", "75", "90"]:
    print("bad split")
    exit(-1)

sign_file = sys.argv[3]
if sign_file not in ["page", "zone"]:
    print("bad sign file")
    exit(-1)

js = importlib.import_module(f"signatures.flow_sign_{sign_file}_m{split_train_test}_g{split_train_test}")
TRAIN_FILE = f"signatures/train_set_{sign_file}_m{split_train_test}_g{split_train_test}.csv"

OUTPUT =f"file_sign{sign_file}_{split_train_test}_plain_{name}.json"

split_train_test = int(split_train_test)/100
########################### Prepare training sets #############################

print("Preparing train sets...")
if name == "intel64":
    train_dict={}
    with open(TRAIN_FILE,'r') as f:
        reader = csv.reader(f)
        next(reader) # toss headers
        for file, train in reader:
            train_dict[file] = eval(train)

directory = os.fsencode(DIRECTORY)

TOTAL_FILENAMES = 520

detections = {}
already_matched = {}
total_files = 0
for file in os.listdir(directory):
    filename = os.fsdecode(file)
    
    # skip train set filenames and filenames we don't have signatures for
    if name == "intel64":
        if train_dict.get(filename) is not None and train_dict[filename]:
            #print(f"skip {filename}")
            continue
    else:
        if total_files > TOTAL_FILENAMES*(1 - split_train_test):
            continue
    
    #print(f"check {filename}")

    with open(os.path.join(directory, file), "rb") as fd:
        page = hexlify(fd.read())

    detections[filename] = {}
    for i in range(0, len(page)-SIGNATURE_SIZE, 2):
        
        sign = page[i:i+SIGNATURE_SIZE].decode('utf-8')
        if js.sign_match.get(sign) is not None:

            if already_matched.get(sign) is not None: # Match signature only once
                continue

            already_matched[sign] = True

            matched_file = js.sign_match[sign]

            if detections[filename].get(matched_file) is None:
                detections[filename][matched_file] = 1
            else:
                detections[filename][matched_file] += 1

    total_files += 1
    
running_samples = 0
matched_samples = 0

for filename, det in detections.items():
    running_samples += 1
    
    if det != {}:
        matched_samples += 1


print("Total Test set samples: ", total_files)

print(f"Matched samples: {matched_samples}/{running_samples}")
print(f"Percentage Matched samples {matched_samples/running_samples*100}")


with open(OUTPUT, "w") as fd:
    fd.write(json.dumps(detections, indent=2))
    
