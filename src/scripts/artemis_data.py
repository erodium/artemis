import copy
import pandas as pd
import json


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
    "MALAYSIA":                  "MY",
    "BRAZIL":                    "BR",
    "FINLAND":                   "FI",
    "SPAIN":                     "ES",
    "GERMANY":                   "DE",
    "ROK":                       "KR",
    "KOREA (THE REPUBLIC OF)":   "KR",
    "RUSSIAN FEDERATION (THE)":  "RU",
    "AUSTRIA":                   "AT",
    "NETHERLANDS (THE)":         "NL",
    "PORTUGAL":                  "PT",
    "ARMENIA":                   "AM"
}

def clean_country(country):
    c = country.upper()
    if len(country) > 2:
        if ";" in c:
            print(c)
        elif "UNITED STATES" in c:
            c = "US"
        elif "REDACTED" in c:
            c = "XX" # country ws redacted
        elif c in country_map.keys():
            c = country_map[c]
        else:
            print(country)
    return c


def clean_data(df):
    clean_df = df.copy(deep=True)  # make a copy of the df
    clean_df = clean_df.dropna(subset='redacted')  # drop any where redacted is NaN; those don't contain whois record
    clean_df['country'] = clean_df.country.fillna("ZZ")  # ZZ is no country
    clean_df['country'] = clean_df.country.apply(clean_country)
    return clean_df
