import copy
import pandas as pd
import json
import numpy as np

from collections import Counter

creation_date_cols = ['creation_date', 'creation_date_1', 'creation_date_2', 'creation_date_3', 'creation_date_4']
updated_date_cols = ['updated_date', 'updated_date_1', 'updated_date_2', 'updated_date_3', 'updated_date_4']
expiration_date_cols = ['expiration_date', 'expiration_date_1', 'expiration_date_2']
bad_countries = []


def process(row):
    new_row = {'redacted': 0}  # flag whether row has redacted data
    for k, v in row.items():  # iterate through the row's items
        if k == 'name_servers' and isinstance(v, str):
            v = [x.strip() for x in v.split("\n")]
        if isinstance(v, list):  # of the value is a list
            if 'REDACTED FOR PRIVACY' not in v:  # if it wasn't redacted
                if k in ['creation_date', 'emails', 'expiration_date', 'name_servers', 'status',
                         'updated_date']:  # these fields have multiple values that are useful
                    for i in range(0, len(v)):  # explode them
                        new_row[f'{k}_{i + 1}'] = v[i]  # e.g., emails:[a,b] becomes emails_1:a, emails_2:b
                else:  # not a multi value field
                    vcomb = ";".join(v)  # concatenate the strings
                    new_row.update({k: vcomb})
            else:  # data was redacted
                new_row['redacted'] = 1  # flag it as redacted
                vcopy = copy.deepcopy(v)  # make a copy of the data
                while vcopy:  # while there's still data
                    val = vcopy.pop()  # pop one off
                    if val != 'REDACTED FOR PRIVACY':  # skip redacted
                        new_row.update({k: val})  # use the other value
        elif pd.isnull(v):  # if the value is null
            continue  # skip it
        elif isinstance(v, str):  # if it's a string
            if v == 'REDACTED FOR PRIVACY':  # and it's redacted
                new_row['redacted'] = 1  # flag as redacted
            new_row.update({k: v})
        else:  # if none of the above, just include it
            new_row.update({k: v})
    return new_row


def change_whois_data(obj):
    new_obj = {'domain': list(obj.keys())[0]}  # set the "domain" to domain.name
    new_vals = list(obj.values())[0]  # get the {...values...} part
    if isinstance(new_vals, dict):  # ensure it's a dict. could be "error" in some cases
        proc_vals = process(new_vals)  # process the line
        new_obj.update(proc_vals)
    return new_obj


def load_datafile(filepath, filetype):
    records = []
    with open(filepath) as f:  # open file
        for line in f.read().splitlines():  # for each line
            obj = json.loads(line)  # load the line, which looks like: {"domain.name": {...values...}}
            if filetype == 'whois':
                new_obj = change_whois_data(obj)
            elif filetype == 'entropy':
                new_obj = change_entropy_data(obj)
            elif filetype == 'ip':
                new_obj = change_ip_data(obj)
            records.append(new_obj)
    return pd.DataFrame(records)


def change_entropy_data(obj):
    new_obj = {"domain": list(obj.keys())[0], "entropy": list(obj.values())[0]}
    return new_obj


def change_ip_data(obj):
    if len(list(obj.values())) > 2:
        print(obj)
    domain = list(obj.keys())[0]
    new_obj = {"domain": domain}
    for rec_type, records in obj[domain].items():
        for k, v in records.items():
            new_obj[f"dns_rec_{rec_type.lower()}_{k.lower()}"] = v.lower()
    return new_obj


country_map = {
    "MALAYSIA": "MY",
    "BRAZIL": "BR",
    "FINLAND": "FI",
    "SPAIN": "ES",
    "GERMANY": "DE",
    "ROK": "KR",
    "KOREA (THE REPUBLIC OF)": "KR",
    "RUSSIAN FEDERATION (THE)": "RU",
    "AUSTRIA": "AT",
    "NETHERLANDS (THE)": "NL",
    "PORTUGAL": "PT",
    "ARMENIA": "AM",
    "CYPRUS": "CY",
    "CHINA": "CN",
    "RUSSIA": "RU"
}


def clean_country(country):
    c = country.upper()
    if len(country) > 2:
        if ";" in c:
            parts = c.split(';')
            if parts[0] == parts[1]:
                c = parts[0]
            elif parts[0] == 'GB' and parts[1] == 'UK':
                c = 'GB'
            elif parts[0] == 'CY' and parts[1] == 'CYPRUS':
                c = 'CY'
            else:
                bad_countries.append(c)
        elif "UNITED STATES" in c or "HERNDON" in c:
            c = "US"
        elif "REDACTED" in c or "PERSONAL DATA" in c:
            c = "XX"  # country ws redacted
        elif c in country_map.keys():
            c = country_map[c]
        elif "CYPRUS" in c:
            c = "CY"
        else:
            bad_countries.append(c)
    return c.lower()


def clean_dates(dt):
    if pd.isna(dt) or dt == "not defined":
        return pd.NA
    if dt == "before 19950101":
        dt = "19950101"
    elif dt == "before Aug-1996":
        dt = "19960801"
    elif isinstance(dt, float):
        print(dt)
    elif "T" in dt:
        dt = dt.split("T")[0]
    x = pd.to_datetime(dt, errors='coerce').date()
    return x


def calc_days_since(d):
    if not pd.isna(d):
        td = (pd.Timestamp.today().date() - d).days
        return td


def set_creation_date(row):
    mask = row[creation_date_cols].notnull()
    if mask.any():
        latest_creation_date = row[creation_date_cols][mask].max()
        first_creation_date = row[creation_date_cols][mask].min()
        days_between_creations = (latest_creation_date - first_creation_date).days
    else:
        latest_creation_date = pd.NaT
        days_between_creations = pd.NA
    row[creation_date_cols[0]] = latest_creation_date
    row['days_between_creations'] = days_between_creations
    return row


def set_updated_date(row):
    mask = row[updated_date_cols].notnull()
    if mask.any():
        latest_update_date = row[updated_date_cols][mask].max()
        first_update_date = row[updated_date_cols][mask].min()
        days_between_updates = (latest_update_date - first_update_date).days
    else:
        latest_update_date = pd.NaT
        days_between_updates = pd.NA
    row[updated_date_cols[0]] = latest_update_date
    row['days_between_updates'] = days_between_updates
    return row


def set_expiration_date(row):
    mask = row[expiration_date_cols].notnull()
    if mask.any():
        latest_expiration_date = row[expiration_date_cols][mask].max()
    else:
        latest_expiration_date = pd.NaT
    row[expiration_date_cols[0]] = latest_expiration_date
    return row


def check_for_changed_domain_name(row):
    ans = False
    if pd.notna(row.domain_name):
        parts = row.domain_name.split(";")
        if len(parts) > 1:
            part1 = parts[0].lower()
            part2 = parts[1].lower()
            ans = part1 == part2
    return int(ans)


def get_ns_cols(num=16):
    cols = []
    prefix = 'name_servers_'
    for i in range(0, num):
        field = prefix + str(i + 1)
        cols.append(field)
    return cols


def count_name_servers(row):
    num_ns = 0
    for col in get_ns_cols():
        if pd.notna(row[col]):
            num_ns += 1
    return num_ns


def check_name_servers(row):
    ns_suffixes = set()
    for col in get_ns_cols():
        if pd.notna(row[col]):
            domain = row[col]
            parts = domain.split(".")
            suffix = ".".join(parts[1:]).lower()
            ns_suffixes.add(suffix)
    return len(ns_suffixes)


def find_main_ns_domain(row):
    domains = Counter()
    for col in get_ns_cols():
        if pd.notna(row[col]):
            domain = row[col].split(".")[-2]
            domains[domain] += 1
    mc = domains.most_common(1)
    if len(mc) > 0:
        return mc[0][0].lower()
    return pd.NA


def get_status_cols():
    cols = ['status']
    prefix = "status_"
    for i in range(0, 12):
        cols.append(prefix + str(i + 1))
    return cols


def mark_status_flags(row):
    valid_statuses = ['serverDeleteProhibited', 'clientDeleteProhibited', 'serverRenewProhibited',
                      'clientRenewProhibited', 'clientTransferProhibited'
                      ]
    row_statuses = []
    for col in get_status_cols():
        if pd.notna(row[col]):
            row_statuses.append(row[col])
    new_statuses = {k: 0 for k in valid_statuses}
    for status in valid_statuses:
        for row_status in row_statuses:
            if status in row_status:
                new_statuses[status] = 1
    for status in valid_statuses:
        row[status] = new_statuses[status]
    return row


def clean_dnssec(val):
    if pd.isna(val):
        return "DNSSEC_NA"
    if ";" in val:
        parts = val.split(";")
        part1 = parts[0]
        part2 = parts[1]
        if part1.lower() == part2.lower():
            return part1.lower()
    return val


def get_email_cols(num=6):
    cols = ['emails']
    prefix = "emails_"
    for i in range(0, num):
        cols.append(prefix + str(i + 1))
    return cols


def count_emails(row):
    num_emails = 0
    for col in get_email_cols():
        if pd.notna(row[col]):
            num_emails += 1
    return num_emails


def find_email_domains(row):
    email_domains = set()
    for col in get_email_cols():
        if pd.notna(row[col]):
            email = row[col]
            email_parts = email.split("@")
            if len(email_parts) > 1:
                email_domains.add(email_parts[1])
            else:
                email_domains.add(email_parts[0])
    domain_str = ";".join(email_domains)
    if domain_str:
        return domain_str
    else:
        return "EMAIL_NAN"


def clean_data(df):
    clean_df = df.copy(deep=True)  # make a copy of the df
    # drop any where redacted is NaN; those don't contain whois record
    clean_df = clean_df.dropna(subset=['redacted', 'domain_name'])
    # drop any columns that are completely empty
    clean_df = clean_df.dropna(how='all', axis='columns')
    # Clean country
    clean_df['country'] = clean_df.country.fillna("zz")  # ZZ is no country
    clean_df['country'] = clean_df.country.apply(clean_country)
    print(f"{len(bad_countries)} records had countries that are ambiguous: {bad_countries}")
    for col in creation_date_cols + updated_date_cols + expiration_date_cols:
        clean_df[col] = clean_df[col].apply(clean_dates)
    clean_df['days_between_creations'] = pd.NA
    clean_df = clean_df.apply(set_creation_date, axis=1)
    creation_date_cols_to_drop = copy.deepcopy(creation_date_cols)
    creation_date_cols_to_drop.remove(creation_date_cols[0])
    clean_df = clean_df.drop(columns=creation_date_cols_to_drop)
    clean_df['days_since_creation'] = clean_df.creation_date.apply(calc_days_since)
    clean_df['days_between_updates'] = pd.NA
    clean_df = clean_df.apply(set_updated_date, axis=1)
    updated_date_cols_to_drop = copy.deepcopy(updated_date_cols)
    updated_date_cols_to_drop.remove(updated_date_cols[0])
    clean_df = clean_df.drop(columns=updated_date_cols_to_drop)
    clean_df['days_since_update'] = clean_df.updated_date.apply(calc_days_since)
    clean_df = clean_df.apply(set_expiration_date, axis=1)
    expiration_date_cols_to_drop = copy.deepcopy(expiration_date_cols)
    expiration_date_cols_to_drop.remove(expiration_date_cols[0])
    clean_df = clean_df.drop(columns=expiration_date_cols_to_drop)
    clean_df['days_until_expiration'] = clean_df.expiration_date.apply(
        lambda dt: pd.NA if pd.isna(dt) else (dt - pd.Timestamp.today().date()).days
    )
    clean_df['has_multiple_domain_names'] = clean_df.domain_name.apply(lambda x: ";" in x if pd.notna(x) else False)
    clean_df['has_multiple_domain_names'] = clean_df['has_multiple_domain_names'].astype(int)
    clean_df['multiple_domain_names_match'] = clean_df.apply(check_for_changed_domain_name, axis=1)
    clean_df = clean_df.drop(columns='domain_name')
    # Process name servers
    clean_df['number_name_servers'] = clean_df.apply(count_name_servers, axis=1)
    clean_df['num_different_ns_domains'] = clean_df.apply(check_name_servers, axis=1)
    clean_df['main_name_server_domain'] = clean_df.apply(find_main_ns_domain, axis=1)
    # Process Status
    clean_df = clean_df.apply(mark_status_flags, axis=1)
    clean_df = clean_df.drop(columns=get_status_cols())
    # Process Registrant Contact Name
    clean_df['registrant_contact_name'] = np.where(clean_df['registrant_contact_name'].isnull(), 0, 1)
    clean_df['registrar'] = clean_df.registrar.fillna('REGISTRAR_NAN').apply(str.lower)
    # Process dnssec
    clean_df['dnssec'] = clean_df.dnssec.apply(clean_dnssec).apply(str.lower)
    # Process emails
    clean_df['num_emails'] = clean_df.apply(count_emails, axis=1)
    clean_df['email_domains'] = clean_df.apply(find_email_domains, axis=1).apply(str.lower)
    clean_df['num_email_domains'] = clean_df.email_domains.apply(
        lambda x: len(x.split(";")) if x != "EMAIL_NAN" else 0
    )
    # Fill NAs
    # drop any columns with fewer than 300 rows having data
    clean_df = clean_df.dropna(how='any', thresh=300, axis='columns')
    clean_df['org'] = clean_df.org.fillna("ORG_NAN").apply(str.lower)
    clean_df['state'] = clean_df.state.fillna("STATE_NAN").apply(str.lower)
    clean_df['whois_server'] = clean_df.whois_server.fillna("WHOIS_NAN").apply(str.lower)
    clean_df['address'] = clean_df.address.fillna('ADDRESS_NAN').apply(str.lower)
    clean_df['city'] = clean_df.city.fillna("CITY_NAN").apply(str.lower)
    clean_df['name'] = clean_df.name.fillna("NAME_NAN").apply(str.lower)
    clean_df['zipcode'] = clean_df.zipcode.fillna("ZIP_NAN")
    clean_df['zipcode'] = clean_df.zipcode.astype(str).apply(str.lower)
    return clean_df
