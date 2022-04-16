import argparse
import os
import shutil

"""
Combine raw DGA datasets into one file.

Usage: make_dga_dataset.py --raw_benign_domain_file="../../../data/raw/dga_benign_domain_data.csv" --raw_dga_domain_file="../../../data/raw/dga_dga_domain_data.csv" --output_file="../../../data/processed/dga_data.csv"

Todo:
* Fold this into a common make dataset script.
"""

# Allow to run as a standalone script
if __name__ == "__main__":
    # Use Argparse to handle cli inputs
    parser = argparse.ArgumentParser()
    parser.add_argument('--raw_benign_domain_file', help='The raw file containing benign domain data.')
    parser.add_argument('--raw_dga_domain_file', help='The raw file containing dga domain data.')
    parser.add_argument('--output_file', help='The filename to save the results to.')
    parser.add_argument('--verbose', nargs="?", default=False, help='Print verbose information.')
    args = parser.parse_args()
    raw_benign_domain_file = args.raw_benign_domain_file
    raw_dga_domain_file = args.raw_dga_domain_file
    output_file = args.output_file
    verbose = args.verbose

    raw_dga_data_files = [raw_benign_domain_file, raw_dga_domain_file]

    with open(output_file,'wb') as wfd:
        file_count = 0
        for f in raw_dga_data_files: 
            with open(f,'rb') as fd:
                # Strip the header from the second file
                if file_count !=0:
                    fd.readline()
                shutil.copyfileobj(fd, wfd)
            file_count += 1
