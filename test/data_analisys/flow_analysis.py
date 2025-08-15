from ctypes import util
from curses import nocbreak
import pandas as pd
import json
import ast
import sys

memory_util = "data/processed_data/intel64_utilization.csv"


# extract result based on status and string in probe output
def check_flow(csv_zone, csv_page, probe_name):
    # Read the CSV file
    df_zone = pd.read_csv(csv_zone,names=["id", "filename", "url", "packed", "full_result"])
    df_page = pd.read_csv(csv_page,names=["id", "filename", "url", "packed", "full_result"])
    
    total = 0
    similar = 0
    page_detections = 0
    zone_detections = 0
    good_zone = 0
    good_page = 0
    # Iterate through each row
    for index, row in df_page.iterrows():
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

        full_data = antivirus_output['full_data']

        zone_result_ = ast.literal_eval(df_zone.loc[df_zone["filename"] == filename]["full_result"].iloc[0])['probe_results']['antivirus'][probe_name]
        if zone_result_['status'] == -1:
            continue


        zone_result = ast.literal_eval(df_zone.loc[df_zone["filename"] == filename]["full_result"].iloc[0])['probe_results']['antivirus'][probe_name]['results']

        zone_total_pages = len(zone_result["page_utilization"].keys())


        total += 1
        if ( len(full_data) - zone_total_pages < 10):
            similar += 1

            if len(full_data) > 10:
                good_page += 1
            
            if zone_total_pages > 10:

                good_zone += 1

                found = 0
                if detection_result == 1:
                    yara_result = antivirus_output['yara']
                    for match in yara_result:
                        if filename in match:
                            page_detections += 1
                            #print(match, filename)
                            found = 1
                            break
                print(filename, zone_total_pages, len(full_data), ",", zone_result_['status'], found)
                
                if zone_result_['status'] == 1:
                    yara_result = zone_result['yara']
                    for match in yara_result:
                        if filename in match:
                            zone_detections += 1
                            #print(match, filename)
                            break

    print(f"Similar page number: {similar}/{total}")
    print(f"Percentange Similar: {similar/total*100}%")

    print(f"Good page number: {good_page}/{similar}")
    print(f"Percentange good page: {good_page/similar*100}%")

    print(f"Good zone number: {good_zone}/{similar}")
    print(f"Percentange good zone: {good_zone/similar*100}%")

    print(f"Similar detection Page: {page_detections}/{good_zone}")
    print(f"Percentange Similar Page: {page_detections/good_zone*100}")
    
    print(f"Similar detection Zone: {zone_detections}/{good_zone}")
    print(f"Percentange Similar Zone: {zone_detections/good_zone*100}")
    #return (detections, total)


csv_page = "data/jits_page_intel64_full.csv"

csv_zone = "data/jits_zone_intel64.csv"

probe_name = "FlowScanner"

check_flow(csv_zone, csv_page, probe_name)

# df = pd.DataFrame(utilization)
# if not df.empty:
#     df.to_csv(memory_util)


# Save the new DataFrame to a new CSV file
