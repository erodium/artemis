import sys
import pickle
import pandas as pd
import numpy as np
import blosc
from nltk.corpus import words
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.ensemble import RandomForestClassifier
sys.path.append('..')
sys.path.append('src/scripts')
sys.path.append('src/scripts/dga')
from generate_entropy_data import generate_shannon_entropy_score
from domain_tools import get_domain_parts
from dga_config import (
    ngram_size,
    dga_model_file
)

"""
Holds all of the common functions for DGA modeling.

Usage: Import via other scripts.

Todo:
* See below per function.
"""

# Todo: Stop searching when domain becomes all numbers or spaces
# Search for words in domain string. Remove the words from the domain when a match occurs,
# otherwise we could have more word characters in a domain than the length of a string.
# Should consider that shorter words may match first simply due to coming first in
# the dictionary. How can we account for that?
def find_words(domain, word_list, verbose=False):
    word_count = 0
    for word in word_list:
        if word in domain:
            word_count += len(word)
            domain = domain.replace(word, ' ')
            if verbose: print(word + " matched in " + domain)
            if verbose: print("updated domain is now " + domain)
    return(word_count)

def find_uncommon_letters(string_value):
    # https://en.wikipedia.org/wiki/Letter_frequency
    least_common_letters = ("q", "x", "z", "j", "w")
    letter_count = 0
    for i in range(0,len(string_value)):
        if string_value[i] in least_common_letters:
            letter_count += 1
    return(letter_count)

# Reproduce "masked n-gram" idea found in https://webdiis.unizar.es/~ricardo/files/papers/SRS-ESWA-19.pdf.
# Todo: Ensure we're not missing any character types.
# n = number; s = symbol; v = vowel, c = consonant
def mask_string(string_value):
    symbols = ("-")
    vowels = ("a","e","i","o","u")
    masked_domain = []
    for i in range(0,len(string_value)):
        masked_value = ""
        if string_value[i].isnumeric():
            masked_value = "n"
        elif string_value[i] in symbols:
            masked_value = "s"
        elif string_value[i] in vowels:
            masked_value = "v"
        else:
            masked_value = "c"
        masked_domain.append(masked_value)
    return ''.join(masked_domain)

# Function to allow interaction from other scripts to load existing model and 
# Todo: Handle domains that can't be rooted better than simply giving them a 0 value.
def dga_prediction(domain=None, entropy=None, dga_model_file=dga_model_file, ngram_size=ngram_size, verbose=False):
    domain_root = ''.join(get_domain_parts(domain)[:2])
    if verbose: print("domain_root: " + domain_root)
    if domain_root == '':
        results = 0
        return results
    length = len(domain_root)
    uncommon_letters = find_uncommon_letters(domain_root)

    word_list = set(words.words())
    word_length_threshold = 3
    # Remove words with less than 4 characters
    word_list = [x for x in word_list if len(x) > word_length_threshold ]
    word_count = find_words(domain_root, word_list)

    word_ratio = word_count / length

    masked_domain = mask_string(domain_root)
    if verbose: print("masked_domain: " + masked_domain)
    masked_ngrams = [masked_domain[i:i+ngram_size] for i in range(len(masked_domain)-ngram_size+1)]

    # Load and decompress specified model
    with open(dga_model_file, 'rb') as f:
        compressed_pickle = f.read()
    decompressed_pickle = blosc.decompress(compressed_pickle)
    model = pickle.loads(decompressed_pickle)

    # Create columns that match those supplied to the model
    columns = list(model.feature_names_in_)
    base_columns = columns[:5]
    base_columns.insert(0, "domain")
    ngram_columns = columns[5:]

    domain_df = pd.DataFrame(data=[[domain,entropy,length,uncommon_letters,word_count,word_ratio]], columns=base_columns).set_index('domain')
    domain_df['masked_ngrams'] = [masked_ngrams]

    # One-hot encode ngrams
    mlb = MultiLabelBinarizer()
    domain_df = domain_df.join(pd.DataFrame(mlb.fit_transform(domain_df.pop('masked_ngrams')),
                                                              index=domain_df.index, columns=mlb.classes_))

    # The following steps are so that the domain supplied for prediction have the same features as the provided model.
    missing_features = list(set(ngram_columns) - set(mlb.classes_))
    temp_df = pd.DataFrame(index=domain_df.index, columns=missing_features)
    temp_df = temp_df.replace(np.nan, 0)
    domain_df = domain_df.join(temp_df)
    reordered_columns = columns
    domain_df = domain_df.reindex(reordered_columns, axis=1)

    results = model.predict_proba(domain_df)[0][1]

    return results

# Allow to run as a standalone script
if __name__ == "__main__":
    print("This script is used to store common functions and doesn't contain its own functionality.")
