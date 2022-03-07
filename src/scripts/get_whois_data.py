import json
import whois

from time import sleep

with open('../data/pre/domains.txt') as f:
    domains = f.readlines()

total_num = len(domains)

with open('../data/pre/whois_data.txt', 'a') as f:
    on_domain = 1
    for domain in domains:
        if on_domain < 959:
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
            for k,v in w.items():
                domain_data[k] = v
            f.write(json.dumps({full_domain:domain_data}, indent=4, sort_keys=True, default=str))
        except whois.parser.PywhoisError as e:
            print("error: ", e)
            f.write(json.dumps({full_domain:"error"}))
        finally:
            on_domain += 1
            sleep(10)


