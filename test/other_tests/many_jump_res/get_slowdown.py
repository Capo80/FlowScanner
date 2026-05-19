import pandas as pd
import numpy as np

# 1. Load the dataset
# Make sure 'many_jumps_res.csv' is in the same folder
df = pd.read_csv('many_jumps_res.csv')

# 2. Robust conversion of Total_Cycles to numeric
# This removes any potential commas, spaces, or non-digit characters
if df['Total_Cycles'].dtype == object:
    df['Total_Cycles'] = df['Total_Cycles'].astype(str).str.replace(r'[^\d.]', '', regex=True)

df['Total_Cycles'] = pd.to_numeric(df['Total_Cycles'], errors='coerce')

# 3. Pivot the table to get Methods as columns
# Index now includes 'Iterations' as requested
pivot_df = df.pivot_table(index=['K_Jumps', 'Nops', 'Iterations'], 
                         columns='Method', 
                         values='Total_Cycles').reset_index()

# 4. Identify the tool columns (all methods except 'Native')
tools = [m for m in df['Method'].unique() if m != 'Native' and pd.notnull(m)]

# 5. Prepare the final display DataFrame
# We ensure 'Native' exists to avoid KeyErrors
if 'Native' not in pivot_df.columns:
    print("Warning: 'Native' column not found in pivoted data.")
    # Create an empty Native column if missing to prevent code from crashing
    pivot_df['Native'] = np.nan

final_df = pivot_df[['K_Jumps', 'Nops', 'Iterations', 'Native']].copy()

# Format Native Cycles: Convert to integer string without commas/decimals
def format_as_int_string(val):
    if pd.isna(val) or np.isinf(val): return "-"
    return str(int(round(val)))

final_df['Native Cycles'] = final_df['Native'].apply(format_as_int_string)

# 6. Calculate slowdown factors for each tool and append 'X'
for tool in tools:
    if tool in pivot_df.columns:
        # Calculate ratio: Tool Cycles / Native Cycles
        ratio = pivot_df[tool] / pivot_df['Native']
        
        # Round to integer, handle missing values, and add 'X'
        def format_slowdown(x):
            if pd.isna(x) or np.isinf(x): return "-"
            return f"{int(round(x))}x"
            
        final_df[tool] = ratio.apply(format_slowdown)

# 7. Final cleanup and column renaming for LaTeX
# Remove the helper 'Native' column and rename headers
final_df = final_df.drop(columns=['Native'])
final_df = final_df.rename(columns={
    'K_Jumps': 'K Jumps',
    'Nops': 'Nops',
    'Iterations': 'Iter'
})

# 8. Generate the LaTeX table
latex_table = final_df.to_latex(
    index=False, 
    caption='Execution cycles baseline and relative slowdown factor (X) including iterations',
    label='tab:slowdown_iterations',
    escape=False,
    column_format='r' * len(final_df.columns)
)

# 9. Print the result
print(latex_table)
