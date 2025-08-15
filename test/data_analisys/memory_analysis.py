import pandas as pd
import numpy as np

# Load the CSV file into a DataFrame
df = pd.read_csv('data/processed_data/memory_usage.csv')

# Group by the 'filename' and calculate the mean and max for 'used_bytes'
grouped = df.groupby('filename')['used_bytes'].agg(['mean', 'max']).reset_index()

# Save the result to a new CSV file
grouped.to_csv('data/processed_data/memory_summary.csv', index=False)

# we have some errors in the data - a page can be at max 4096 bytes
df.drop(df[df["used_bytes"] > 4096].index, inplace=True)
grouped.drop(grouped[grouped["max"] > 4096].index, inplace=True)

# Calculate the overall mean of the 'used_bytes' column
overall_mean_used_bytes = np.mean(df['used_bytes'])

# Calculate the mean of the max values for each file
mean_of_max_values = np.mean(grouped['max'])

# Print the results
print(f"Overall mean of 'used_bytes': {overall_mean_used_bytes}")
print(f"Mean of the max values: {mean_of_max_values}")

print("Summary statistics have been saved to 'summary_stats.txt'.")
