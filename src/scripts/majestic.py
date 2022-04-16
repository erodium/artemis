import pandas as pd

def parse_majestic_csv(
        src_file='../../raw/majestic_million_small.csv',
        dest_file='../../raw/majestic_domains.txt',
        start_row=1,
        end_row=3000
                                                        ):
    currow = 0
    df = pd.read_csv(src_file)
    domains = df.Domain.values.tolist()
    with open(dest_file, 'w') as f:
        for domain in domains:
            currow += 1
            if currow > end_row:
                break
            if currow < start_row:
                continue
            f.write("%s\n" % domain)

