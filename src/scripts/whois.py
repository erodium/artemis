import json
import whois

from time import sleep


def get_whois_data(src_file=None, dest_file=None, start_at=1):
    """
    :param src_file: path for the list of domain names
    :param dest_file: path to place whois data file
    :return: Nah.

    Takes a source file that is a list of domain names (one per line)
    and uses python-whois to get the whois data, writing it to
    the destination file as jsonlines (one json per line).
    """
    with open(src_file) as f:
        domains = f.readlines()
    total_num = len(domains)
    print(f"Total domains: {total_num}")

    if start_at == 1:
        file_attribute = 'w'  # overwrite the file if it exists
    else:
        file_attribute = 'a'  # add to the file if it exists

    with open(dest_file, file_attribute) as f:
        on_domain = 1
        for domain in domains:
            ### This was used if the process stopped before gettting to the end.
            ###   It allows to pick back up at the end. Change the with open attribute to 'a'
            if on_domain < start_at:
                on_domain += 1
                continue
            print(on_domain, end="; ")
            try:
                domain = domain.strip()
                full_domain = domain
                print(full_domain, end="; ")
                if len(domain.split(".")) > 2:
                    print("shortening, ", end=" ")
                    domain = ".".join(domain.split(".")[-2:])
                print("using ", domain, end="; ")
                w = whois.whois(domain)
                print(w)
                domain_data = {}
                for k, v in w.items():
                    domain_data[k] = v
                f.write(json.dumps({full_domain: domain_data}, sort_keys=True, default=str) + "\n")
            except whois.parser.PywhoisError as e:
                print("error: ", e)
                f.write(json.dumps({full_domain: "error"})+"\n")
            finally:
                on_domain += 1
                sleep(4)
