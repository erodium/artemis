import argparse
import json
from .parse_json import parse_json
from .domain_tools import get_domain_parts
from .generate_entropy_data import generate_shannon_entropy_score
from dga.dga_functions import dga_prediction 

"""
Generate DGA probability values for domains from raw whois file.

Usage: generate_dga_data.py --whois_file whois_file_name.txt --output_file output.txt 

Todo:
"""

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
        domain_parts = get_domain_parts(domain_name)
        domain_without_tld = ''.join(domain_parts[:2])
        entropy_value = generate_shannon_entropy_score(domain_name)
        results = dga_prediction(domain=domain_name, entropy=entropy_value, verbose=verbose)
        results_list.append({domain_name: results})

    with open(output_file, 'w') as fp:
        fp.write('\n'.join(json.dumps(i) for i in results_list) + '\n')
