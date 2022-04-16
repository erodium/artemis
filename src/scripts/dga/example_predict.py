import argparse
from dga_functions import dga_prediction 

"""
Example script that will use a prebuilt model to predict if a domain is a DGA.

Usage: example_predict.py --domain_name test.com --entropy_value 3.1 

Todo:
* Move functionality to dga_functions and retest
"""

# Allow to run as a standalone script
if __name__ == "__main__":
    # Use Argparse to handle cli inputs
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain_name', help='The domain name to predict.')
    parser.add_argument('--entropy_value', help='The entropy value for the domain name.')
    parser.add_argument('--verbose', nargs="?", default=False, help='Print verbose information.')
    args = parser.parse_args()
    domain_name = args.domain_name
    entropy_value = args.entropy_value
    verbose = args.verbose

    results = dga_prediction(domain=domain_name, entropy=entropy_value, verbose=verbose)

    print("Domain " + domain_name + " DGA probability is " + str(results))
