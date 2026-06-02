import pandas as pd

# Read the CSV file
df = pd.read_csv("results/benchmark.csv")


# Calculate averages for numeric columns
averages = df.mean(numeric_only=True)

# Print filtered rows
print("Filtered Rows:")
print(df)
print(f"Row Count: {len(df)}")

# Print averages
print("\nColumn Averages:")
print(averages)
print(df)