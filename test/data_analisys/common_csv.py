import pandas as pd

FILE_1 = 'data/false_pos_yara'
FILE_2 = 'data/jits_false_pos_zone'
FILE_3 = 'data/jits_false_pos_page'
# Load the CSV files into DataFrames
df1 = pd.read_csv(FILE_1 + ".csv")
df2 = pd.read_csv(FILE_2 + ".csv")
df3 = pd.read_csv(FILE_3 + ".csv")

# Extract the filenames from the first column
filenames1 = set(df1.iloc[:, 1])
filenames2 = set(df2.iloc[:, 1])
filenames3 = set(df3.iloc[:, 1])

# Find the intersection of filenames present in all three files
common_filenames = filenames1 & filenames2 & filenames3

# Filter the DataFrames to keep only rows with common filenames
df1_filtered = df1[df1.iloc[:, 1].isin(common_filenames)]
df2_filtered = df2[df2.iloc[:, 1].isin(common_filenames)]
df3_filtered = df3[df3.iloc[:, 1].isin(common_filenames)]

# Save the filtered DataFrames to new CSV files
df1_filtered.to_csv(FILE_1 + "_filtedred.csv", index=False)
df2_filtered.to_csv(FILE_2 + "_filtedred.csv", index=False)
df3_filtered.to_csv(FILE_3 + "_filtedred.csv", index=False)

print("Filtered CSV files have been saved as 'file1_filtered.csv', 'file2_filtered.csv', and 'file3_filtered.csv'.")
