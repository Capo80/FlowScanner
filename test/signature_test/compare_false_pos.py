import json
import sys
import pandas as pd
import ast

split_train_test = sys.argv[1]

if sys.argv[2] == "fp":
    suf = "_bin"
else:
    suf = "_intel64"

pack = sys.argv[3]
if pack != "pack" and pack != "plain":
    print("bad args 3")
    exit()

sign_file = sys.argv[4]
if sign_file != "page" and sign_file != "zone":
    print("bad args 4")
    exit()
with open(f"test_outputs/file_sign{sign_file}_{split_train_test}_plain{suf}.json") as fd:    
    file_detections_dict = json.loads(fd.read())

with open(f"test_outputs/zone_sign{sign_file}_{split_train_test}_{pack}{suf}.json") as fd:    
    zone_detections_dict = json.loads(fd.read())

with open(f"test_outputs/page_sign{sign_file}_{split_train_test}_{pack}{suf}.json") as fd:    
    page_detections_dict = json.loads(fd.read())

FAMILY_CSV = "traces/families.csv"
fam_df = pd.read_csv(FAMILY_CSV)
fam_dict = dict(zip(fam_df['File'], fam_df['Folder']))

total = 0
page_detections = 0
zone_detections = 0
file_detections = 0
family_detections_total = {}
family_detections_page = {}
family_detections_zone = {}
family_detections_file = {}
zone_errors = 0
zone_see_page = 0
for key, det in zone_detections_dict.items():
    

    if zone_detections_dict.get(key) is not None:

        if page_detections_dict.get(key) != {}:
            page_detections += 1

        if zone_detections_dict.get(key) != {}:
            zone_detections += 1

        if file_detections_dict.get(key) is not None and file_detections_dict[key]:
            file_detections += 1


        total += 1



# if total == 0:
#
#     for key, det in page_detections_dict.items():
#
#
#         family = fam_dict[key]
#         if det:
#             page_detections += 1
#             if family_detections_page.get(family) is None:
#                 family_detections_page[fam_dict[key]] = 1
#             else:
#                 family_detections_page[fam_dict[key]] += 1
#
#         if file_detections_dict.get(key) is not None and file_detections_dict[key]:
#             file_detections += 1
#             if family_detections_file.get(family) is None:
#                 family_detections_file[fam_dict[key]] = 1
#             else:
#                 family_detections_file[fam_dict[key]] += 1
#
#         total += 1
#         if family_detections_total.get(family) is None:
#             family_detections_total[fam_dict[key]] = 1
#         else:
#             family_detections_total[fam_dict[key]] += 1


samples_page = len(page_detections_dict.keys())
samples_zone = len(zone_detections_dict.keys())
samples_file = len(file_detections_dict.keys())

print("Total tunning samples in page: ", samples_page)
print("Total tunning samples in zone: ", samples_zone)
print("Total tunning samples in file: ", samples_file)

print(f"Zone detection: {zone_detections}/{samples_zone}")
print(f"Percentange Zone detection {zone_detections/samples_zone*100}")

print(f"Page detection: {page_detections}/{samples_zone}")
print(f"Percentange Page detection {page_detections/samples_zone*100}")

print(f"File detection: {file_detections}/{samples_zone}")
print(f"Percentange Page detection {file_detections/samples_zone*100}")


