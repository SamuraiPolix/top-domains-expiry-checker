import csv
import whois
from zipfile import ZipFile
from datetime import datetime, timedelta

def check_domain_expiry(domain):
    try:
        domain_info = whois.whois(domain)

        # Extract the expiration date
        expiration_date = domain_info.expiration_date

        # Handle cases where the expiration date is a list
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        return expiration_date

    except whois.parser.PywhoisError:
        return None

def filter_domains(input_csv, output_csv):
    with open(input_csv, 'r') as infile, open(output_csv, 'w', newline='') as outfile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames + ['Expiry Date']

        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            domain = row['Domain']
            expiry_date = check_domain_expiry(domain)

            if expiry_date:
                # Check if the domain is about to expire in the next 30 days
                if (expiry_date - datetime.now()).days <= 30:
                    row['Expiry Date'] = expiry_date.strftime('%Y-%m-%d')
                    writer.writerow(row)

if __name__ == "__main__":
    # Replace with the actual path to your input and output CSV files
    # https://www.domcop.com/files/top/top10milliondomains.csv.zip
    input_csv_path = "top10milliondomains.csv.zip"
    with ZipFile(input_csv_path, 'r') as zip_ref:
        zip_ref.extractall()
    input_csv_path = "top10milliondomains.csv"
    output_csv_path = "output.csv"

    filter_domains(input_csv_path, output_csv_path)
    print(f"Filtered domains saved to {output_csv_path}")
