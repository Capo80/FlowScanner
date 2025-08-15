import pandas as pd
import json
import ast
import sys

# extract result based on status and string in probe output
def extract_results(csv_file, probe_name, is_yara):
    # Read the CSV file
    df = pd.read_csv(csv_file)
    
    # Initialize lists to store extracted data
    results = []
    filenames = []
    families = []
    
    total = 0
    detections = 0
    # Iterate through each row
    for index, row in df.iterrows():
        # Load JSON from the "full result" column
        full_result_json = ast.literal_eval(row[4])
        
        # Extract required fields
        probe_results = full_result_json['probe_results']
        if is_yara:
            antivirus_results = probe_results['metadata'][probe_name]
        else:
            antivirus_results = probe_results['antivirus'][probe_name]
            
        detection_result = antivirus_results['status']
        filename = row[1]

        total += 1
        if (detection_result == 1):
            if is_yara:
                if len(antivirus_results["results"]["yabin_intel64_wild_yar"]) != 0:
                    detections += 1
            else:
                detections += 1

        # families.append(family)
    
    return (detections, total)

csv_file_path = sys.argv[1] 
probe_name = "JITScanner"

#csv_file_path = "data/false_pos_yara_filtered.csv"
#probe_name = "Yara"

detections, total = extract_results(csv_file_path, probe_name, False)

print(f"Result: {detections}/{total}")
print(f"Percentange: {detections/total*100}%")
# Save the new DataFrame to a new CSV file
