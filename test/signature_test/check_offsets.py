import json
import sys
import pandas as pd

split_train_test = sys.argv[1]

if sys.argv[2] == "fp":
    suf = "_bin"
else:
    suf = "_intel64"
# with open(f"test_outputs/page_{split_train_test}{suf}.json") as fd:    
#     file_detections_dict = json.loads(fd.read())

page_df = pd.read_csv("test_outputs/offset_info_intel64_page_25.csv")
zone_df = pd.read_csv("test_outputs/offset_info_intel64_zone_25.csv")

with open(f"test_outputs/zone_{split_train_test}{suf}.json") as fd:    
    zone_detections_dict = json.loads(fd.read())

with open(f"test_outputs/page_{split_train_test}{suf}.json") as fd:    
    page_detections_dict = json.loads(fd.read())


total = 0
page_detections = 0
zone_detections = 0
file_detections = 0
for key, det in page_detections_dict.items():
    
    if det:
        page_detections += 1
        
    if zone_detections_dict.get(key) is None:


        if det:
            page_detections += 1
            print(page_df.loc[page_df["filename"] == key])

        if zone_detections_dict[key]:
            zone_detections += 1
            print(zone_df.loc[zone_df["filename"] == key])
        # if file_detections_dict[key]:
        #     file_detections += 1

        total += 1
    
    

