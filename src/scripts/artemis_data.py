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


def load_whois_datafile(filepath):
    records = []
    with open(filepath) as f:  # open file
        for line in f.read().splitlines():  # for each line
            obj = json.loads(line)  # load the line, which looks like: {"domain.name": {...values...}}
            new_obj = {'domain': list(obj.keys())[0]}  # set the "domain" to domain.name
            new_vals = list(obj.values())[0]  # get the {...values...} part
            if isinstance(new_vals, dict):  # ensure it's a dict. could be "error" in some cases
                proc_vals = process(new_vals)  # process the line
                new_obj.update(proc_vals)
                records.append(new_obj)
    return pd.DataFrame(records)


def load_entropy_datafile(filepath):
    records = []
    with open(filepath) as f:
        for line in f.read().splitlines():
            obj = json.loads(line)
            new_obj = {"domain": list(obj.keys())[0], "entropy":list(obj.values())[0]}
            records.append(new_obj)
    return pd.DataFrame(records)
