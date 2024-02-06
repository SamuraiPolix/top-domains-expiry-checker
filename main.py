import requests
import os
import csv
import whoisdomain as whois
from zipfile import ZipFile
from datetime import datetime, timedelta


def check_domain_expiry(domain):
    try:
        domain_info = whois.query(domain)

        # Extract the expiration date
        expiration_date = domain_info.expiration_date

        # Handle cases where the expiration date is a list
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        return expiration_date

    except:
        print(domain, " failed")
        return None


def filter_domains(input_csv, output_csv):
    with open(input_csv, 'r') as infile, open(output_csv, 'w', newline='') as outfile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames + ['Expiry Date']

        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        i = -1
        for row in reader:
            i += 1
            domain = row['Domain']
            expiry_date = check_domain_expiry(domain)
            print(i)
            if expiry_date:
                # Check if the domain is about to expire in the next 30 days
                if (expiry_date - datetime.now()).days <= 30:
                    row['Expiry Date'] = expiry_date.strftime('%Y-%m-%d')
                    writer.writerow(row)
                    print("\n", domain, " expires soon!")


# Download a file from a direct URL to the current working directory.
def download_file(url, filename=None):
    # If filename is not provided, extract it from the URL
    if not filename:
        filename = url.split("/")[-1]

    print("Downloading the list of websites")

    # Make a request to the URL
    response = requests.get(url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Save the file in the current working directory
        with open(filename, 'wb') as file:
            file.write(response.content)

        print(f"File downloaded successfully: {filename}")
        return os.path.abspath(filename)
    else:
        print(f"Failed to download file. Status code: {response.status_code}")
        return None


if __name__ == "__main__":
    download_link = "https://www.domcop.com/files/top/top10milliondomains.csv.zip"
    input_csv_path = "top10milliondomains.csv"
    output_csv_path = "output.csv"

    if not os.path.exists(input_csv_path):
        zip_file = download_file(download_link)
        with ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall()

    filter_domains(input_csv_path, output_csv_path)
    print(f"Filtered domains saved to {output_csv_path}")
