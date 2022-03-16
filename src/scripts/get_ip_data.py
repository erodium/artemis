from ipwhois import IPWhois
import sys
import argparse
import json
from parse_json import parse_json

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
    results = {}
    try:
        obj = IPWhois(ip_address)
        try:
            whois_data = obj.lookup_rdap(depth=1)
            try: 
                country_code = whois_data['asn_country_code']
            except:
                country_code = "NA"
            try:
                entity = whois_data['entities'][0]
                org = whois_data['objects'][entity]['contact']['name']
            except:
                org = "NA"
            results = {'CC': country_code, 'Org': org}
        except:
            results = {'CC': 'NA', 'Org': 'NA'}
    except:
        results = {'CC': 'NA', 'Org': 'NA'}
    
    if verbose: print(results)

    return results

# Allow to run as a standalone script
if __name__ == "__main__":
    # Use Argparse to handle cli inputs
    parser = argparse.ArgumentParser()
    parser.add_argument('--dns_file', help='The dns filename to parse.')
    parser.add_argument('--output_file', help='The filename to save the results to.')
    parser.add_argument('--verbose', nargs="?", default=False, help='Print verbose information.')
    args = parser.parse_args()
    dns_file = args.dns_file
    output_file = args.output_file
    verbose = args.verbose

    with open(dns_file) as f:
       data = f.read()

    domain_list = []

    while True:
        obj, remaining = parse_json(data)
        domain_list.append(obj)
        data = remaining
        if not remaining.strip():
            break

    results_list = []
    for domain_data in domain_list:
        domain_name = list(domain_data.keys())[0]
        results = {}
        for record_type in domain_data[domain_name]:
            ip_address = domain_data[domain_name][record_type]["IP"]
            if ip_address != "NA":
                results[record_type] = obtain_ip_data(ip_address, verbose=verbose)
            else:
                results[record_type] = {'CC': 'NA', 'Org': 'NA'}
        results_list.append({domain_name: results})

    with open(output_file, 'w') as fp:
        fp.write('\n'.join(json.dumps(i) for i in results_list) + '\n')
