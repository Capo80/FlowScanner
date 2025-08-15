from ctypes import util
from curses import nocbreak
import pandas as pd
import json
import ast
import sys

memory_util = "data/processed_data/intel64_utilization.csv"


# extract result based on status and string in probe output
def extract_results(csv_file, probe_name, process_utilization):
    # Read the CSV file
    df = pd.read_csv(csv_file)
    util_df = pd.read_csv(memory_util)
    
    # Initialize lists to store extracted data
    results = []
    filenames = []
    families = []
    
    utilization = {
        "Filename" : [],
        "Pages Used" : [],
        "Average Used" : [],
    }

    total = 0
    detections = 0
    # Iterate through each row
    for index, row in df.iterrows():
        # Load JSON from the "full result" column
        full_result_json = ast.literal_eval(row[4])
        
        # Extract required fields
        probe_results = full_result_json['probe_results']
        antivirus_results = probe_results['antivirus'][probe_name]
            
        detection_result = antivirus_results['status']
        filename = row[1]

        if detection_result == -1:
            continue

        antivirus_output = antivirus_results['results']


        if process_utilization:
            page_utilization = antivirus_output['page_utilization']

            utilization["Filename"].append(filename)
            utilization["Pages Used"].append(len(page_utilization.keys()))
            if len(page_utilization.keys()) != 0:
                utilization["Average Used"].append(sum(page_utilization.values()) / len(page_utilization.keys()))
            else:
                utilization["Average Used"].append(0)


        file_row = util_df.loc[util_df['Filename'] == filename]

        if (file_row.empty or (file_row["Pages Used"] <= 3).bool()):
            continue

        #if (file_row["Average Used"] < 100).bool():
        #    continue


        total += 1
        if (detection_result == 1):

            yara_result = antivirus_output['yara']

            for match in yara_result:
                if filename in match:
                    detections += 1
                    #print(match, filename)
                    break

    return (detections, total, utilization)


if sys.argv[1] == "page":
    csv_file_path = "data/jits_page_intel64.csv"
    probe_name = "FlowScanner"

if sys.argv[1] == "zone":
    csv_file_path = "data/jits_zone_intel64.csv"
    probe_name = "FlowScanner"

detections, total, utilization = extract_results(csv_file_path, probe_name, False)

df = pd.DataFrame(utilization)
if not df.empty:
    df.to_csv(memory_util)

print(f"Result: {detections}/{total}")
print(f"Percentange: {detections/total*100}%")


# Save the new DataFrame to a new CSV file
