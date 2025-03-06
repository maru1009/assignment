import pandas as pd

# Load the dataset from the CSV file
data = pd.read_csv('malicious_phish.csv')

# Optionally strip any leading/trailing whitespace from column names
data.columns = data.columns.str.strip()

# Print the columns to check for the correct column name
print(data.columns)

# Filter the dataset to exclude rows with 'defacement' and 'malware'
filtered_df = data[data['type'].isin(['benign', 'phishing'])]

# Export the filtered dataset to a new CSV file
filtered_df.to_csv('malicious_phish.csv', index=False)

# Optionally, print the filtered dataframe to confirm
print(filtered_df)
