import csv

def export_to_csv(data, filename):
    # Specify the field names for the CSV file
    fieldnames = ['column1', 'column2', 'column3']  # Replace with your actual field names

    # Open the CSV file in write mode
    with open(filename, 'w', newline='') as csvfile:
        # Create a CSV writer object
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write the header row
        writer.writeheader()

        # Write the data rows
        for row in data:
            writer.writerow(row)

# Example usage
scan_results = [
    {'column1': 'value1', 'column2': 'value2', 'column3': 'value3'},
    {'column1': 'value4', 'column2': 'value5', 'column3': 'value6'},
    # Add more rows as needed
]

export_to_csv(scan_results, 'scan_results.csv')