import argparse
import os
import requests
import csv
import random
from parse_json import parse_json

"""
Pull down a list of domains from Majestic Million and sample them (and optionally deconflict with another dataset). 

Usage: python3.10 get_benign_domains.py --source 'http://downloads.majestic.com/majestic_million.csv' --num_domains 32000 --output_file '../../data/raw/dga_benign_domain_data.csv' --deconflict True --deconflict_file '../../data/raw/benign_whois_data.txt'

Todo:
* Handle other source types.
* Handle other deconflict file types.
* Dynamically locate domain field in csv.
* Modularize.
"""

# Allow to run as a standalone script
if __name__ == "__main__":
    # Use Argparse to handle cli inputs
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', help='The url to use as a source for benign domains.')
    parser.add_argument('--num_domains', type=int, help='The number of benign domains to save.')
    parser.add_argument('--output_file', help='The filename to save the results to.')
    parser.add_argument('--deconflict', nargs="?", default=False, help='Should the list of domains generated be deconflicted from another source?')
    parser.add_argument('--deconflict_file', help='Which file should be used to deconflict.')
    parser.add_argument('--verbose', nargs="?", default=False, help='Print verbose information.')
    args = parser.parse_args()
    source = args.source
    num_domains = args.num_domains
    output_file = args.output_file
    deconflict = args.deconflict
    deconflict_file = args.deconflict_file
    verbose = args.verbose

    benign_domain_list = [] 
    with requests.Session() as s:
        download_source = s.get(source)
        decoded_content = download_source.content.decode('utf-8')
        csv_file = csv.reader(decoded_content.splitlines(), delimiter=',')
        benign_domain_count = 0
        for row in list(csv_file):
            if benign_domain_count != 0:
                benign_domain_list.append(row[2])
            benign_domain_count += 1

    if deconflict:
        with open(deconflict_file) as df:
            deconflict_data = df.read()

            deconflict_data_list = []
            while True:
                obj, remaining = parse_json(deconflict_data)
                deconflict_data_list.append(obj)
                deconflict_data = remaining
                if not remaining.strip():
                    break

        deconflict_domain_list = []
        for entry in deconflict_data_list:
            deconflict_domain = list(entry.keys())[0]
            deconflict_domain_list.append(deconflict_domain)

        benign_domain_list = [x for x in benign_domain_list if x not in deconflict_domain_list]

    # Sample benign_domain list
    sampled_benign_domains = random.choices(benign_domain_list, k=num_domains)

    # Write sampled benign domains to file
    f = open(output_file, 'w')
    # Add header for CSV
    f.write("domain,algorithm,dga" + '\n')
    for domain in sampled_benign_domains:
        if verbose: print(domain)
        f.write(domain + ',' + "NA" + ',' + 'False' + '\n')
    f.close()

    if verbose: print("Number of sampled domains: " + str(len(sampled_benign_domains)))
    if verbose: print("First domain in sampled list: " + sampled_benign_domains[0])

