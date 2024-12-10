import time, os, sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Generate random time series data
np.random.seed(42)
timestamps = pd.date_range(start='2023-01-01', periods=1000, freq='H')
values = np.random.randn(1000)

# Create a DataFrame with the random time series data
df = pd.DataFrame({'timestamp': timestamps, 'value': values})

# Calculate the time differences in seconds between consecutive timestamps
df['time_diff'] = df['timestamp'].diff().dt.total_seconds()

# Drop the first row which will have NaN time_diff
df = df.dropna(subset=['time_diff'])

# Function to perform Time-Dependent Density Estimation for a given column and save as JPEG
def plot_time_dependent_density(column):
    try:
        # Ensure the column is numeric
        df[column] = pd.to_numeric(df[column], errors='coerce')
        df.dropna(subset=[column], inplace=True)
        
        # Calculate rolling mean and standard deviation with a window size of 50
        rolling_mean = df[column].rolling(window=50).mean()
        rolling_std = df[column].rolling(window=50).std()
        
        plt.figure(figsize=(10, 6))
        
        # Plot rolling mean and standard deviation
        plt.plot(df['timestamp'], rolling_mean, label=f'Rolling Mean of {column}')
        plt.fill_between(df['timestamp'], rolling_mean - rolling_std, rolling_mean + rolling_std,
                         color='gray', alpha=0.2, label=f'Rolling Std Dev of {column}')
        
        plt.xlabel('Timestamp')
        plt.ylabel(column)
        plt.title(f'Time-Dependent Density Estimation of {column}')
        plt.legend()
        plt.grid(True)
        
        # Save the figure as JPEG
        filename = f'time_dependent_density_{column}.svg'
        plt.savefig(filename, format='svg')
        plt.show()
        plt.close()
        
        print(f"Saved Time-Dependent Density Estimation plot for column {column} as {filename}")
    except ValueError as e:
        print(f"Could not plot Time-Dependent Density Estimation for column {column}: {e}")

def main():
    # Example usage with the random values
    plot_time_dependent_density('value')
if __name__ == "__main__":
    print("[" + __file__ + "]'s last modified: %s" % time.ctime(os.path.getmtime(__file__)))
    main()
    