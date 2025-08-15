import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

matplotlib.rcParams.update({'font.size': 25})


# Load the summary CSV file
summary_df = pd.read_csv('data/processed_data/memory_summary.csv')

summary_df.drop(summary_df[summary_df["max"] > 4096].index, inplace=True)

summary_df.sort_values(by='mean', ascending=False, inplace=True)

# Calculate the overall mean and median for the 'mean' column
overall_mean_mean = summary_df['mean'].mean()
overall_median_mean = summary_df['mean'].median()

# Create the first box plot for mean used_bytes
plt.figure(figsize=(10, 6))
sns.barplot(x='filename', y='mean', data=summary_df, width=1)
plt.axhline(y=overall_mean_mean, color='r', linestyle='--', label=f'Mean: {overall_mean_mean:.2f}')
plt.axhline(y=overall_median_mean, color='b', linestyle='-', label=f'Median: {overall_median_mean:.2f}')
tick_step = 200
plt.xticks(np.arange(0, summary_df.shape[0], step=tick_step), np.arange(0, summary_df.shape[0], step=tick_step))
plt.title('Average Used Bytes\nper Page of CmdLine Applications')
plt.xlabel('CmdLine Applications\n(Sorted by Average Used Bytes)')
plt.ylabel('Average Used Bytes')
plt.legend()
plt.tight_layout()
plt.savefig('boxplot_mean_used_bytes.pdf')
plt.show()

summary_df.sort_values(by='max', ascending=False, inplace=True)

overall_mean_max = summary_df['max'].mean()
overall_median_max = summary_df['max'].median()

# Create the second box plot for max used_bytes
plt.figure(figsize=(10, 6))
sns.barplot(x='filename', y='max', data=summary_df, width=1)
plt.axhline(y=overall_mean_max, color='r', linestyle='--', label=f'Mean: {overall_mean_max:.2f}')
plt.axhline(y=overall_median_max, color='b', linestyle='-', label=f'Median: {overall_median_max:.2f}')
tick_step = 200
plt.xticks(np.arange(0, summary_df.shape[0], step=tick_step), np.arange(0, summary_df.shape[0], step=tick_step))
plt.title('Max Used Bytes\nper Page of CmdLine Applications')
plt.xlabel('CmdLine Applications\n(Sorted by Max Used Bytes)')
plt.ylabel('Max Used Bytes')
plt.legend()
plt.tight_layout()
plt.savefig('boxplot_max_used_bytes.pdf')
plt.show()
