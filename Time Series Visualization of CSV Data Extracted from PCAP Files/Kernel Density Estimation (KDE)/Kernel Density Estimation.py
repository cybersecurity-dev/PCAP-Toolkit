import numpy as np
import time, os, sys
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

from scipy.stats import norm, gaussian_kde
from statsmodels.tsa.ar_model import AutoReg
from sklearn.mixture import GaussianMixture

#Kernel Density Estimation (KDE)
def plot_kde_seaborn(df, filename, column, output_dir):
    data = df
    # Extract relevant columns
    ingoing_column_name = f'{column}_ingoing'
    outgoing_column_name = f'{column}_outgoing'
    
    ingoing = data[ingoing_column_name]
    outgoing = data[outgoing_column_name]
    
    plt.figure(figsize=(12, 6))
    sns.kdeplot(ingoing, label=f'{column}_ingoing', fill=True)
    sns.kdeplot(outgoing, label=f'{column}_outgoing', fill=True)
    plt.xlabel(f'{column}_ingoing|outgoing')
    plt.title("Kernel Density Estimation (KDE)")
    plt.legend()    
    plot_filename = f'{filename}_{column}_kde_sns.svg'
    
    plt.savefig(os.path.join(output_dir, plot_filename))
    plt.show()
    plt.close()

def main(in_csv, out_dir):
    columns_bypass = ['timestamp', 'time_diff', 'source_ip', 'destination_ip']
    for filename in os.listdir(in_dir):
        if filename.endswith(".csv"):
            filename_without_ext, ext = os.path.splitext(filename)
            print(f"CSV File:\t{filename_without_ext}")
            packet_data = []
            csv_file_path = os.path.join(in_dir, filename)
            df = pd.read_csv(csv_file_path)
            data = df
            data['timestamp'] = pd.to_datetime(data['timestamp'])
            for column in data.columns:
                if (data[column] == 0).all():
                    columns_bypass.append(column)
            # Iterate over each column (excluding 'timestamp' and 'time_diff') and plot KDE
            for column in data.columns:
                if column not in columns_bypass:
                    try:
                        parts = column.split("_", 2)
                        protocol_name = "_".join(parts[:2])
                        plot_kde_seaborn(data, filename_without_ext, protocol_name, out_dir)
                    except ValueError as e:
                        print(f"Could not plot KDE for column {column}: {e}")

if __name__ == "__main__":
  print("[" + __file__ + "]'s last modified: %s" % time.ctime(os.path.getmtime(__file__)))
  # Check if a parameter is provided
  if len(sys.argv) == 4 :
    in_dir = sys.argv[1]
    if not os.path.exists(in_dir):
        print(f"Directory: '{in_dir}' does not exist.")
        exit()
    print(f"\nCSV Directory:\t\t{in_dir}")

    out_dir = sys.argv[2]
    if not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    print(f"SVG Files will save:\t{out_dir}")
    
    IS_MALWARE = sys.argv[3]
    print(f"DATASET is malware:\t{IS_MALWARE}\n\n")
    main(in_dir, out_dir)
  else:
    print("No input directory and output directory provided.")