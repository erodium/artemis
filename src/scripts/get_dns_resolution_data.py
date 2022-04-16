import dns.resolver
import sys
import argparse
import json
from parse_json import parse_json

"""
Return the first IP address for a specific DNS record type (e.g. MX, A)
and the number of records that exist for that record type. If no record
type is specified, obtain values for all default types (A and MX) for the 
provided domain name. Return results as a dictionary of tuples, where the 
first value in the tuple is the first IP resolved and the second value is 
the number of records available.

Usage: get_dns_resolution_data.py --whois_file=../../data/raw/input.txt --output_file=../../data/raw/output.txt

Example Output: 
{"domain.com": {"A": {"IP": "192.168.0.1", "Count": 1}, "MX": {"IP": "10.0.0.1", "Count": 5}}}

Todo:
* Better exception and error handling
* Better logic for multiple records returned, instead of just choosing the first
* Other record types (e.g. www CNAME)
* Move certain default values to centralized config file
* Rate limit handling (Google name servers allow 1500 QPS)
"""


def resolve_dns_records(domain_name, requested_record_type="ALL", custom_nameservers=['8.8.8.8', '8.8.4.4'],
                        verbose=False):
    supported_record_types = ["A", "MX"]
    results = {}

    if requested_record_type == "ALL":
        query_record_types = supported_record_types
    else:
        query_record_types = [requested_record_type]

    for record_type in query_record_types:
        answers = query_domain(domain_name, record_type, custom_nameservers)
        if answers != "NA":
            num_answers = len(answers)
            # Resolve MX hostname to IP
            if record_type == "MX":
                mx_answers = query_domain(answers[0].exchange, "A", custom_nameservers)
                if mx_answers != "NA":
                    results[record_type] = {'IP': mx_answers[0].to_text(), 'Count': num_answers}
                else:
                    results[record_type] = {'IP': mx_answers, 'Count': num_answers}
            else:
                results[record_type] = {'IP': answers[0].to_text(), 'Count': num_answers}
        else:
            results[record_type] = {'IP': answers, 'Count': 0}

    if verbose: print(domain_name + ": " + str(results))
    return results


def query_domain(domain_name, record_type, custom_nameservers):
    custom_resolver = dns.resolver.Resolver()
    custom_resolver.nameservers = custom_nameservers
    try:
        answers = dns.resolver.resolve(domain_name, record_type)
    except:
        answers = "NA"

    return answers

# Allow to run as a standalone script
if __name__ == "__main__":
    # Use Argparse to handle cli inputs
    parser = argparse.ArgumentParser()
    parser.add_argument('--whois_file', help='The whois filename to parse.')
    parser.add_argument('--output_file', help='The filename to save the results to.')
    parser.add_argument('--verbose', nargs="?", default=False, help='Print verbose information.')
    args = parser.parse_args()
    whois_file = args.whois_file
    output_file = args.output_file
    verbose = args.verbose

    with open(whois_file) as f:
        data = f.read()

    domain_list = []

    while True:
        obj, remaining = parse_json(data)
        domain_list.append(list(obj.keys())[0])
        data = remaining
        if not remaining.strip():
            break

    results_list = []
    for domain_name in domain_list:
        results = resolve_dns_records(domain_name, verbose=verbose)
        results_list.append({domain_name: results})

    with open(output_file, 'w') as fp:
        fp.write('\n'.join(json.dumps(i) for i in results_list) + '\n')
