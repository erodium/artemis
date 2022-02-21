import json
import whois

from time import sleep

with open('../data/domains.txt') as f:
    domains = f.readlines()

total_num = len(domains)

with open('../data/whois_data.txt', 'w') as f:
    on_domain = 1
    for domain in domains:
        print(on_domain, end=" ")
        try:
            orig_domain = domain.strip()
            if len(domain.split(".")) > 2:
                domain = ".".join(domain.split(".")[-2:])
            w = whois.whois(domain)
            domain_data = {}
            for k,v in w.items():
                domain_data[k] = v
            f.write(json.dumps({orig_domain:domain_data}, indent=4, sort_keys=True, default=str))
        except whois.PywhoisError as e:
            f.write({orig_domain:str(e)})
        finally:
            on_domain += 1
            sleep(10)


