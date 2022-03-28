import copy
import pandas as pd
import json

creation_date_cols = ['creation_date', 'creation_date_1', 'creation_date_2', 'creation_date_3', 'creation_date_4']
updated_date_cols = ['updated_date', 'updated_date_1', 'updated_date_2', 'updated_date_3', 'updated_date_4']
expiration_date_cols = ['expiration_date', 'expiration_date_1', 'expiration_date_2']
bad_countries = []


def process(row):
    new_row = {'redacted': False}  # flag whether row has redacted data
    for k, v in row.items():  # iterate through the row's items
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
                new_row['redacted'] = True  # flag it as redadted
                vcopy = copy.deepcopy(v)  # make a copy of the data
                while vcopy:  # while there's still data
                    val = vcopy.pop()  # pop one off
                    if val != 'REDACTED FOR PRIVACY':  # skip redacted
                        new_row.update({k: val})  # use the other value
        elif pd.isnull(v):  # if the value is null
            continue  # skip it
        elif isinstance(v, str):  # if it's a string
            if v == 'REDACTED FOR PRIVACY':  # and it's redacted
                new_row['redacted'] = True  # flag as redacted
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
    "ARMENIA": "AM"
}


def clean_country(country):
    c = country.upper()
    if len(country) > 2:
        if ";" in c:
            parts = c.split(';')
            if parts[0] == parts[1]:
                c = parts[0]
            else:
                bad_countries.append(c)
        elif "UNITED STATES" in c:
            c = "US"
        elif "REDACTED" in c or "PERSONAL DATA" in c:
            c = "XX"  # country ws redacted
        elif c in country_map.keys():
            c = country_map[c]
        else:
            bad_countries.append(c)
    return c


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


def clean_data(df):
    clean_df = df.copy(deep=True)  # make a copy of the df
    clean_df = clean_df.dropna(subset='redacted')  # drop any where redacted is NaN; those don't contain whois record
    clean_df['country'] = clean_df.country.fillna("ZZ")  # ZZ is no country
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
    return clean_df
