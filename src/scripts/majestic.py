import pandas as pd


def parse_majestic_csv(
        src_file='../data/pre/majestic_million_small.csv',
        dest_file='../data/pre/majestic_domains.txt'):
    df = pd.read_csv(src_file)
    domains = df.Domain.values.tolist()
    with open(dest_file, 'w') as f:
        for domain in domains:
            f.write("%s\n" % domain)
