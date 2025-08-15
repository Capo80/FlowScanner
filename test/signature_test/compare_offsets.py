import json
import sys
import pandas as pd
import ast


if sys.argv[1] == "fp":
    suf = "bin"
else:
    suf = "intel64"
# with open(f"test_outputs/page_{split_train_test}{suf}.json") as fd:    
#     file_detections_dict = json.loads(fd.read())

page_df = pd.read_csv(f"test_outputs/offset_info_{suf}_page_{sys.argv[2]}.csv")
zone_df = pd.read_csv(f"test_outputs/offset_info_{suf}_zone_{sys.argv[2]}.csv")


total = 0
raw_page_matched = 0
raw_zone_matched = 0
page_matched = 0
zone_matched = 0


big_enough = 0
total_big = 0

already_seen_page = {}
already_match_page = {}
already_match_zone = {}
for index, row in page_df.iterrows():
    
    land_page = row["land_page"]
    filename = row["filename"]

    matching = zone_df.loc[(zone_df["filename"] == row["filename"]) &
                           (zone_df["land_page"] == row["land_page"])]

    if not matching.empty:


        for index_zone, row_zone in matching.iterrows():
            if int(str(row_zone["zone_lenght"]),16) > 0x20:
                big_enough += 1 
            total_big += 1
            
        if (filename + land_page) not in already_seen_page:
            total += 1
            already_seen_page[filename + land_page] = True

        if (row["matched_signature"] != "NONE"):
            raw_page_matched += 1
            if (filename + land_page) not in already_match_page:
                page_matched += 1
                already_match_page[filename + land_page] = True

        #print(matching)
        if (matching["matched_signature"] != "NONE").any():
            #print(matching, row)
            raw_zone_matched += 1
            if (filename + land_page) not in already_match_zone:
                zone_matched += 1
                already_match_zone[filename + land_page] = True


print(f"PAGE {raw_page_matched}/{total} - {raw_page_matched/total*100}")
print(f"ZONE {raw_zone_matched}/{total} - {raw_zone_matched/total*100}")

print(f"PAGE {page_matched}/{total} - {page_matched/total*100}")
print(f"ZONE {zone_matched}/{total} - {zone_matched/total*100}")


print(f"BIG {big_enough}/{total_big}")