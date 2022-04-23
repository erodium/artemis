import click
import json
import whois
import pandas as pd
from src.scripts.get_dns_resolution_data import resolve_dns_records
import src.scripts.get_ip_data as get_ip_data
# from src.scripts.dga.dga_functions import dga_prediction
from src.scripts.generate_entropy_data import generate_shannon_entropy_score
from joblib import load
import src.scripts.artemis_data as artemis_data

@click.command()
@click.argument('domain')
@click.option('-v', '--verbose', is_flag=True)
def cli(domain, verbose):
    if domain == "test":
        domain = "google.com"
        w_json = test_entry
        ips = test_ips
        dns = test_dns
    else:
        w_json = whois.whois(domain)
        ips = resolve_dns_records(domain, verbose=verbose)
        dns = get_ip_data.resolve_ip_data(ips, verbose)

    processed_json = artemis_data.process(json.loads(str(w_json)))
    processed_json['domain'] = domain
    whois_df = pd.DataFrame([processed_json])
    dns_data = {domain: dns}
    dns_df = pd.DataFrame([artemis_data.change_ip_data(dns_data)])
    merged_df = whois_df.merge(dns_df, on='domain')
    merged_df['entropy'] = generate_shannon_entropy_score(domain, verbose)
    cleaned_df = artemis_data.clean_data(merged_df)
    country_encoder = load('models/country_encoder.joblib')
    encoder_dict = load('models/enc_dict.joblib')
    encoded_df = cleaned_df.copy()
    for col in encoder_dict.keys():
        try:
            encoded_df[col] = encoder_dict[col].transform(encoded_df[col])
        except ValueError as ve:
            encoded_df[col] = -1
            click.echo(ve)
    for col in ['country', 'dns_rec_a_cc', 'dns_rec_mx_cc']:
        encoded_df[col] = country_encoder.transform(encoded_df[col])
    for col in artemis_data.get_ns_cols():
        if col in encoded_df.columns.tolist():
            encoded_df.drop(columns=col, inplace=True)
    for col in artemis_data.get_email_cols():
        if col in encoded_df.columns.tolist():
            encoded_df.drop(columns=col, inplace=True)
    encoded_df = encoded_df.drop(
        columns=['domain', 'updated_date', 'expiration_date', 'creation_date', 'days_since_creation'])
    community_predictor = load("models/community_predictor.joblib")
    col_order = community_predictor.feature_names_in_
    encoded_df = encoded_df[col_order]
    encoded_df['community'] = community_predictor.predict(encoded_df)
    community_df = pd.read_csv('data/processed/graph_community_features.csv')
    community_df = community_df.drop(columns='DomainRecord').drop_duplicates()
    c_df = community_df[community_df.community == encoded_df.iloc[0].community]
    cols = c_df.columns.tolist()
    for col in cols:
        encoded_df[col] = c_df[col]
    clf = load("models/rfc.joblib")
    col_order = clf.feature_names_in_
    final_df = encoded_df[col_order]
    predicted_malicious = clf.predict(final_df)
    if predicted_malicious == 1:
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
test_dns = {'A': {'CC': 'US', 'Org': 'Google LLC'}, 'MX': {'CC': 'US', 'Org': 'Google LLC'}}

if __name__ == '__main__':
    cli()
