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
        if verbose:
            click.echo(f"Received WHOIS data for {domain}: \n{w_json}")
        ips = resolve_dns_records(domain, verbose=verbose)
        if verbose:
            click.echo(f"Received IP addresses of type {type(ips)} for {domain}.")
        dns = get_ip_data.resolve_ip_data({domain: ips}, verbose)
        if verbose:
            click.echo(f"Received DNS data of {type(dns)}for {domain} IPs.")

    processed_json = artemis_data.process(json.loads(str(w_json)))
    processed_json['domain'] = domain
    whois_df = pd.DataFrame([processed_json])
    dns_data = {domain: dns}
    dns_df = pd.DataFrame([artemis_data.change_ip_data(dns_data)])
    merged_df = whois_df.merge(dns_df, on='domain')
    merged_df['entropy'] = generate_shannon_entropy_score(domain, verbose)
    if verbose:
        click.echo(merged_df.iloc[0])
    cleaned_df = artemis_data.clean_data(merged_df)
    country_encoder = load('models/country_encoder.joblib')
    encoder_dict = load('models/enc_dict.joblib')
    encoded_df = cleaned_df.copy()
    for col in encoder_dict.keys():
        try:
            encoded_df[col] = encoder_dict[col].transform(encoded_df[col])
        except ValueError as ve:
            encoded_df[col] = -1
            if verbose:
                err = f"During processing of {col}, {ve}"
                click.echo(err)
        except Exception as e:
            if verbose:
                err = f"During processing of {col}, {ve}"
                click.echo(err)
                raise e
    for col in ['country', 'dns_rec_a_cc', 'dns_rec_mx_cc']:
        try:
            encoded_df[col] = country_encoder.transform(encoded_df[col])
        except ValueError as ve:
            if verbose:
                err = f"Using country code ZZ for {domain} since {encoded_df[col]} is not known."
                click.echo(err)
            encoded_df[col] = country_encoder.transform(["zz"])
    for col in artemis_data.get_ns_cols():
        if col in encoded_df.columns.tolist():
            encoded_df.drop(columns=col, inplace=True)
    for col in artemis_data.get_email_cols():
        if col in encoded_df.columns.tolist():
            encoded_df.drop(columns=col, inplace=True)
    if verbose:
        click.echo("Completed df encoding.")
    encoded_df = encoded_df.drop(
        columns=['domain', 'updated_date', 'expiration_date', 'creation_date', 'days_since_creation'])
    encoded_df = encoded_df.fillna(-1)
    community_predictor = load("models/community_predictor.joblib")
    col_order = community_predictor.feature_names_in_
    encoded_df = encoded_df[col_order]
    predicted_community = community_predictor.predict(encoded_df)[0]
    encoded_df['community'] = predicted_community
    if verbose:
        click.echo(f"Predicting community {predicted_community} for {domain}.")
    community_df = pd.read_csv('data/processed/graph_community_features.csv')
    community_df = community_df.drop(columns='DomainRecord').drop_duplicates()
    c_df = community_df[community_df.community == predicted_community]
    cols = c_df.columns.tolist()
    c_df.index = encoded_df.index
    for col in cols:
        encoded_df[col] = c_df.iloc[0][col]
    clf = load("models/rfc.joblib")
    col_order = clf.feature_names_in_
    final_df = encoded_df[col_order]
    final_df = final_df.fillna(-1)
    try:
        predicted_malicious = clf.predict(final_df)
    except ValueError as ve:
        click.echo(final_df.iloc[0])
        raise ve

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
