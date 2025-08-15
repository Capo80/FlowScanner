import os

# Path to the CSV file
csv_path = 'flow_trace_zone_bin.csv'

# Path to the folder containing the files
folder_path = '/tmp/usr_bin_copy'

# Read the second column (filenames) from the CSV
valid_filenames = set()
with open(csv_path, 'r') as file:
    for line in file:
        columns = line.strip().split(',')
        if len(columns) > 1:  # Ensure there is a second column
            valid_filenames.add(columns[1])

# Iterate through the folder and delete files not in the valid_filenames set
for file in os.listdir(folder_path):
    file_path = os.path.join(folder_path, file)
    # Check if it's a file and not in the valid_filenames
    if os.path.isfile(file_path) and file not in valid_filenames:
        os.remove(file_path)
        print(f"Deleted: {file}")
    else:
        print(f"Kept: {file}")

print("Deletion complete.")
