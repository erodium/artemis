from ipwhois import IPWhois
import sys
import argparse
import json
from src.scripts.parse_json import parse_json
from time import sleep

"""
Will use IP Whois and ASN details to identify an organization and location 
for the IP address provided. More elegant/accurate (but paid) options do exist. 

Usage: get_ip_data.py --dns_file=input.txt --output_file=output.txt

Example Output:
{"domain.com": {"A": {"CC": "US", "Org": "Company LLC"}, "MX": {"CC": "US", "Org": "Company LLC"}}

Todo:
* Could rewrite to utilize another, likely more accurate, geo IP solution
* Add required modules to requirements.txt
* Handle rate limiting
* Better exception and error handling
* NA is a country code, although not likely to show up. Should still switch to a better value for not available.
"""


def obtain_ip_data(ip_address, verbose=False):
    cur_results = {}
    try:
        obj = IPWhois(ip_address)
        whois_data = obj.lookup_rdap(depth=1, rate_limit_timeout=30)
        country_code = whois_data.get('asn_country_code', "NA")
        entity = whois_data.get('entities', ["NA"])[0]
        org = whois_data.get('objects', {}).get(entity, {}).get('contact', {}).get('name', "NA")
        cur_results = {'CC': country_code, 'Org': org}
    except:
        cur_results = {'CC': 'NA', 'Org': 'NA'}
    if verbose:
        print("Current Results:", cur_results)
    return cur_results


# Allow to run as a standalone script
if __name__ == "__main__":
    # Use Argparse to handle cli inputs
    parser = argparse.ArgumentParser(description="""
        Make sure you have a blank output_file to start, or this will just append rows to the end if the file.
        """)
    parser.add_argument('--dns_file', help='The dns filename to parse.')
    parser.add_argument('--output_file', help='The filename to save the results to.')
    parser.add_argument('--start_at', default=0, help='The row to start at')
    parser.add_argument('--end_at', default=-1, help='The row to end at')
    parser.add_argument('--verbose', nargs="?", default=False, help='Print verbose information.')
    args = parser.parse_args()
    dns_file = args.dns_file
    output_file = args.output_file
    verbose = args.verbose

    with open(dns_file) as f:
        if verbose:
            print("Opening file: ", dns_file)
        data = f.read()

    domain_list = []

    while True:
        if verbose:
            print("Parsing json")
        obj, remaining = parse_json(data)
        domain_list.append(obj)
        data = remaining
        if not remaining.strip():
            break
    if verbose:
        print("Total records to process:", len(domain_list))

    results_list = []
    current_row = 0
    if args.end_at < 1:
        last_row = len(domain_list) + 1
    else:
        if args.end_at < 0:
            last_row = len(domain_list)
        else:
            last_row = int(args.end_at)
    if verbose:
        print("Starting at row {} and ending at row {}".format(args.start_at, last_row))

    for domain_data in domain_list:
        current_row += 1
        if int(args.start_at) <= current_row <= last_row:
            domain_name = list(domain_data.keys())[0]
            results = {}
            for record_type in domain_data[domain_name]:
                print("Checking record type:", record_type, "for", domain_data[domain_name])
                ip_address = domain_data[domain_name][record_type]["IP"]
                if ip_address != "NA":
                    if verbose:
                        print(ip_address, "not NA!")
                    results[record_type] = obtain_ip_data(ip_address, verbose=verbose)
                else:
                    if verbose:
                        print(ip_address, "is NA!")
                    results[record_type] = {'CC': 'NA', 'Org': 'NA'}
                sleep(0.5)
            if verbose:
                print(current_row, domain_name)
            results_list.append({domain_name: results})
            if verbose:
                print("Added", domain_name, ":", len(results_list), "total records")
        else:
            if verbose:
                print("Skipping row", current_row)

        if verbose:
            print("Writing file to", output_file)
        with open(output_file, 'a') as outfile:
            outfile.write('\n'.join(json.dumps(i) for i in [{domain_name: results}]) + '\n')