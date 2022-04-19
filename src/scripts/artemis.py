import click
import whois
from artemis_data import process, change_whois_data, change_ip_data, calc_days_since
import pandas as pd
import json
from generate_entropy_data import generate_shannon_entropy_score
from get_dns_resolution_data import resolve_dns_records
from get_ip_data import obtain_ip_data
from datetime import datetime
from joblib import load
import numpy as np
from dga.dga_functions import dga_prediction


def calc_days_since_creation(creation_date):
    today = datetime.today()
    diff = today - datetime.strftime(creation_date, fmt='%Y-%m-%d')
    return diff


@click.command()
@click.argument('domain')
def cli(domain):
    if domain == "test":
        domain = "google.com"
        w_json = json.loads(test_entry)
        ips = test_ips
        mx_dns = {'CC': 'US', 'Org': 'Google LLC'}
    else:
        w_json = whois.whois(domain)
        ips = resolve_dns_records(domain)
        mx_ip = ips.get('MX').get('IP')
        mx_dns = obtain_ip_data(mx_ip)
    es = generate_shannon_entropy_score(domain)
    # Pass domain through DGA model and return the probability that it is a DGA.
    dga_probability = dga_prediction(domain=domain, entropy=es)[1]
    #w_final = process(w_json)
    mx_cc = mx_dns.get('CC').lower()
    model_loc = "models/rfc.joblib"
    clf = load(model_loc)
    enc = load("models/enc.joblib")
    mx_cc_enc = enc.transform([mx_cc])
    creation_date = w_json.get('creation_date')
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    creation_date = pd.to_datetime(creation_date).date()
    days_since_creation = calc_days_since(creation_date)
    features = [
        es, days_since_creation, creation_date.year, creation_date.month, creation_date.day, mx_cc_enc[0]
    ]
    predicted_malicious = clf.predict(np.array(features).reshape(1, -1))[0]
    if predicted_malicious:
        mal = "WILL be"
        warn = "WARNING! "
    else:
        warn = ""
        mal = "will NOT be"
    out = f"{warn}Artemis believes that {domain} {mal} malicious."
    click.echo(out)


test_entry = """
    {
        "domain_name": [
            "GOOGLE.COM",
            "google.com"
        ],
        "registrar": "MarkMonitor, Inc.",
        "whois_server": "whois.markmonitor.com",
        "referral_url": null,
        "updated_date": "2019-09-09 15:39:04",
        "creation_date": [
            "1997-09-15 04:00:00",
            "1997-09-15 07:00:00"
        ],
        "expiration_date": [
            "2028-09-14 04:00:00",
            "2028-09-13 07:00:00"
        ],
        "name_servers": [
            "NS1.GOOGLE.COM",
            "NS2.GOOGLE.COM",
            "NS3.GOOGLE.COM",
            "NS4.GOOGLE.COM",
            "ns3.google.com",
            "ns1.google.com",
            "ns4.google.com",
            "ns2.google.com"
        ],
        "status": [
            "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
            "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
            "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
            "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited",
            "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
            "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
            "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
            "serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)",
            "serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)",
            "serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)"
        ],
        "emails": [
            "abusecomplaints@markmonitor.com",
            "whoisrequest@markmonitor.com"
        ],
        "dnssec": "unsigned",
        "name": null,
        "org": "Google LLC",
        "address": null,
        "city": null,
        "state": "CA",
        "zipcode": null,
        "country": "US"
    }
    """

test_ips = {'A': {'IP': '172.217.1.206', 'Count': 1}, 'MX': {'IP': '209.85.202.26', 'Count': 5}}

if __name__ == '__main__':
    cli()
