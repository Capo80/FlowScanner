from heapq import merge
import pandas as pd
import sys

page_df = pd.read_csv(f"test_outputs/page_seen_{sys.argv[1]}_page_25.csv", index_col=0)
zone_df = pd.read_csv(f"test_outputs/page_seen_{sys.argv[1]}_zone_25.csv", index_col=0)

merged_df = pd.merge(page_df, zone_df, on="filename")
#merged_df = merged_df[(merged_df["page_seen_x"] != 0)]
merged_df = merged_df[(merged_df["page_seen_x"] > 3)]
print("page more", len(merged_df[merged_df["page_seen_x"] > merged_df["page_seen_y"]]))
print("same", len(merged_df[merged_df["page_seen_x"] == merged_df["page_seen_y"]]))
print("zone more", len(merged_df[merged_df["page_seen_x"] < merged_df["page_seen_y"]]))
print("total", len(merged_df))
print(merged_df)