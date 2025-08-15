import pandas as pd
import json
import ast

# extract result based on status and string in probe output
def extract_results(csv_file, probe_name):
    # Read the CSV file
    df = pd.read_csv(csv_file)
    
    # Prepare dict for new dataset
    memory = {
        "filename" : [],
        "page_address" : [],
        "used_bytes" : [],
    }
    
    # Iterate through each row
    for index, row in df.iterrows():
        # Load JSON from the "full result" column
        full_result_json = ast.literal_eval(row[4])
        
        # Extract required fields
        probe_results = full_result_json['probe_results']
        antivirus_results = probe_results['antivirus'][probe_name]
        detection_result = antivirus_results['results']
        page_utilizazion = detection_result['page_utilization']
        filename = row[1]

        for address, used in page_utilizazion.items():
            memory["filename"].append(filename)
            memory["page_address"].append(address)
            memory["used_bytes"].append(used)

        # families.append(family)
    
    return pd.DataFrame(memory)

# Example usage:
csv_file_path = "data/jits_false_pos_zone.csv"
output_file = "data/memory_usage.csv"
probe_name = "FlowScanner"

df = extract_results(csv_file_path, probe_name)

df.to_csv(output_file)
