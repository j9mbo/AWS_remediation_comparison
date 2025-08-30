import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Raw trial data
# --- Automated Architectures ---
eventbridge_s3_ttd = [8.292, 6.431, 9.78, 7.83, 9.3, 8.318, 5.437, 8.417, 8.798, 5.498, 6.165, 7.385, 6.348, 8.392, 5.314, 9.988, 9.06, 8.559, 5.225, 6.591]
eventbridge_s3_ttr = [0.955, 0.824, 0.803, 0.824, 0.817, 0.868, 0.820, 0.851, 0.850, 0.835, 0.819, 0.885, 0.880, 0.835, 0.830, 0.821, 0.858, 0.815, 0.813, 0.898]

eventbridge_sg_ttd = [3.833, 3.193, 1.859, 4.155, 3.107, 2.612, 1.914, 3.529, 3.101, 3.053, 3.164, 4.277, 2.246, 3.968, 4.072, 3.381, 3.123, 2.298, 2.810, 4.221]
eventbridge_sg_ttr = [0.572, 0.302, 0.309, 0.313, 0.290, 0.297, 0.259, 0.333, 0.331, 0.327, 0.279, 0.278, 0.309, 0.306, 0.280, 0.283, 0.315, 0.271, 0.296, 0.274]

config_s3_ttd = [96, 79, 34, 140, 36, 72, 141, 106, 69, 26, 68, 66, 91, 108, 40, 111, 89, 90, 95, 60]
config_s3_ttr = [1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 2, 1, 2, 1, 2, 1, 1]

config_sg_ttd = [18, 76, 125, 122, 40, 113, 127, 158, 99, 68, 120, 30, 103, 108, 85, 94, 105, 111, 113, 53]
config_sg_ttr = [1, 0.5, 1, 1, 1, 0.5, 1, 1, 1, 1, 0.5, 1, 1, 0.5, 1, 1, 1, 1, 1, 1]

# --- Manual Scenario Data ---
manual_s3_ttd = [180] * 20
manual_s3_ttr = [54, 52.1, 54.4, 57.1, 51.8, 51.8, 57.2, 54.8, 51.1, 54.1, 51.1, 51.1, 53.2, 46.8, 47.3, 50.8, 49.5, 53.4, 49.8, 48.3]

manual_sg_ttd = [180] * 20
manual_sg_ttr = [48.7, 44.4, 45.2, 41.4, 43.6, 45.3, 42.1, 45.9, 43.5, 44.3, 43.5, 49.6, 45, 42.4, 47.1, 41.9, 45.5, 40.1, 41.7, 45.5]

# Build DataFrame
records = []
# Append EventBridge data
for ttd, ttr in zip(eventbridge_s3_ttd, eventbridge_s3_ttr):
    records.append({'Architecture':'EventBridge', 'Scenario':'S3 Bucket', 'TTD':ttd, 'TTR':ttr})
for ttd, ttr in zip(eventbridge_sg_ttd, eventbridge_sg_ttr):
    records.append({'Architecture':'EventBridge', 'Scenario':'Security Group', 'TTD':ttd, 'TTR':ttr})
    
# Append AWS Config data
for ttd, ttr in zip(config_s3_ttd, config_s3_ttr):
    records.append({'Architecture':'AWS Config', 'Scenario':'S3 Bucket', 'TTD':ttd, 'TTR':ttr})
for ttd, ttr in zip(config_sg_ttd, config_sg_ttr):
    records.append({'Architecture':'AWS Config', 'Scenario':'Security Group', 'TTD':ttd, 'TTR':ttr})

# Append Manual data
for ttd, ttr in zip(manual_s3_ttd, manual_s3_ttr):
    records.append({'Architecture':'Manual', 'Scenario':'S3 Bucket', 'TTD':ttd, 'TTR':ttr})
for ttd, ttr in zip(manual_sg_ttd, manual_sg_ttr):
    records.append({'Architecture':'Manual', 'Scenario':'Security Group', 'TTD':ttd, 'TTR':ttr})


df = pd.DataFrame(records)
# T_ART is the Total Time (Time to Detect + Time to Remediate)
df['T_ART'] = df['TTD'] + df['TTR']

# Style
sns.set_style('whitegrid')

### Bar Chart: Mean T_ART ###
plt.figure(figsize=(10, 7))
sns.barplot(
    data=df, x='Scenario', y='T_ART', hue='Architecture',
    errorbar='sd', palette='Set2', capsize=0.1
)
plt.ylabel('Mean Total Time (s)')
plt.xlabel('Scenario')
plt.title('Mean Total Time by Architecture and Scenario')
plt.tight_layout()
plt.show()

### Box Plots with Strip Overlay ###
g = sns.catplot(
    data=df, kind='box', x='Architecture', y='T_ART',
    col='Scenario', palette='Set3', sharey=False,
    height=6, aspect=0.9,
    order=['EventBridge', 'AWS Config', 'Manual'] # Ensure consistent order
)
g.fig.suptitle('Distribution of Total Time by Architecture & Scenario', y=1.03)

# CORRECTED LOOP:
# Iterate over the axes and the column names (which are the scenario names)
for ax, scenario_name in zip(g.axes.ravel(), g.col_names):
    # The 'scenario_name' variable already holds the correct value, e.g., 'S3 Bucket'.
    # We use it directly to filter the data for the stripplot.
    sns.stripplot(
        data=df[df['Scenario'] == scenario_name],
        x='Architecture', y='T_ART',
        color='black', size=4, jitter=True, ax=ax,
        order=['EventBridge', 'AWS Config', 'Manual'] # Ensure consistent order for stripplot too
    )
    ax.set_ylabel('Total Time (s)')
    ax.set_xlabel('Architecture')
    # Rotate x-axis labels for better fit
    ax.set_xticklabels(ax.get_xticklabels(), rotation=15, ha="right")


plt.tight_layout(rect=[0, 0, 1, 0.97]) # Adjust layout to prevent title overlap
plt.show() 