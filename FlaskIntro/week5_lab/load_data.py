"""
Data Source:
- Local CSV file: police_killings.csv

Description:
- This script loads a dataset into a pandas DataFrame and displays:
  1. The first 5 rows of the data
  2. Summary statistics
  3. The count of missing values per column
"""

import pandas as pd

def main():
    # Load the dataset
    df = pd.read_csv("police_killings.csv", encoding="latin-1")

    # Display the first 5 rows
    print("First 5 rows of the dataset:")
    print(df.head(), "\n")

    # Display summary statistics
    print("Summary statistics:")
    print(df.describe(), "\n")

    # Display count of missing values
    print("Missing values per column:")
    print(df.isnull().sum())

if __name__ == "__main__":
    main()
