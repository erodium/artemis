import argparse
import json
from collections import Counter
from math import log
from .parse_json import parse_json
from .domain_tools import get_domain_parts

"""
Remove the TLD from the domain name (i.e., "testdomain" from test.domain.com), then generate a Shannon entropy score.

Usage: generate_entropy_data.py --whois_file=../../data/raw/input.txt --output_file=../../data/raw/output.txt

Example Output:
{"domain.com": 1.8182358320544893}

Todo:
* Is entropy on SubdomainDomain the best route? Can't simply strip subdomain because of shared domains (e.g., ddns.net).
"""

def generate_shannon_entropy_score(domain, verbose=False): 
    """
    Reference: https://www.reddit.com/r/learnpython/comments/g1sdkh/python_programming_challenge_calculating_shannon/
    Verified via: https://www.shannonentropy.netmark.pl
    """
    counts = Counter(domain)
    frequencies = ((i / len(domain)) for i in counts.values())
    results = - sum(f * log(f, 2) for f in frequencies)
    if verbose: print(domain + ": " + str(results))
    return results 
    

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
        results = generate_shannon_entropy_score(domain_without_tld, verbose=verbose)
        results_list.append({domain_name: results})

    with open(output_file, 'w') as fp:
        fp.write('\n'.join(json.dumps(i) for i in results_list) + '\n')

