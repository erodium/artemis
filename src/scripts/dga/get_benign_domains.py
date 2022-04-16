import argparse
import os
import requests
import csv
import random
import pandas as pd

"""
Pull down a list of domains from Majestic Million and sample them (and optionally deconflict with another dataset). 

Usage: get_benign_domains.py --source 'http://downloads.majestic.com/majestic_million.csv' --num_domains 32000 --output_file '../../../data/raw/dga_benign_domain_data.csv' --deconflict True --deconflict_file '../../../data/raw/benign_whois_data.txt' --domain_feature_name 'domain' --identifier_feature_name 'malicious' --identifier_feature_value = 'False'

Todo:
* Handle other source types.
* Handle other deconflict file types.
* Dynamically locate domain field in csv.
* Modularize.
* Automatically count the number of DGA domains created and generate the same number of Majestic domains.
* Create defaults to shorten required fields in CLI.
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
    parser.add_argument('--domain_feature_name', help='Feature name in deconflict file that holds the domain names.')
    parser.add_argument('--identifier_feature_name', help='Feature name in deconflict file that identifies the domain name as benign.')
    parser.add_argument('--identifier_feature_value', help='Value in identifier feature that indicates that a domain name is benign.')
    parser.add_argument('--verbose', nargs="?", default=False, help='Print verbose information.')
    args = parser.parse_args()
    source = args.source
    num_domains = args.num_domains
    output_file = args.output_file
    deconflict = args.deconflict
    deconflict_file = args.deconflict_file
    domain_feature_name = args.domain_feature_name
    identifier_feature_name = args.identifier_feature_name
    identifier_feature_value = args.identifier_feature_value
    verbose = args.verbose

    # Convert feature value.
    if identifier_feature_value == "False":
        identifier_feature_value = False
    elif identifier_feature_value == "True":
        identifier_feature_value = True
    else:
        print("identifier_feature_value value specified is unrecognized.")
        exit()

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
        col_list = [domain_feature_name, identifier_feature_name]
        deconflict_df = pd.read_csv(deconflict_file, usecols=col_list)
        deconflict_domain_list = deconflict_df['domain'].tolist()
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

