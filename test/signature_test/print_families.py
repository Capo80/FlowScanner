import csv
from collections import Counter

# Path to the CSV file
csv_path = 'traces/families.csv'

# Read the folder column from the CSV
folder_counts = Counter()
with open(csv_path, 'r') as file:
    reader = csv.DictReader(file)  # Assumes your CSV has headers
    for row in reader:
        folder = row['Folder']  # Replace 'Folder' with the actual column name
        folder_counts[folder] += 1

# Separate minor families and major families
minor_count = 0
result = {}
for folder, count in folder_counts.items():
    if count < 10:
        minor_count += count
    else:
        result[folder] = count

# Add "minor families" entry
if minor_count > 0:
    result['minor families'] = minor_count

for folder, count in result.items():
    print(f"{folder} & {count} \\\\")
# Print the result
# for folder, count in result.items():
    # print(f"{folder}: {count}")

