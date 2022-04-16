import argparse
import pandas as pd
import numpy as np
import pickle
import sys
import itertools
import blosc
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from nltk.corpus import words

sys.path.append('..')
from generate_entropy_data import generate_shannon_entropy_score
from domain_tools import get_domain_parts
from dga_functions import *

from config import (
    ngram_size,
    masked_ngram_values
)

"""
Use the dga dataset to build a RandomForestClassifier model that will be saved for re-use.

Usage: build_dga_model.py --processed_dga_file ../../../data/processed/dga_data.csv --output_model_file ../../../models/dga_model.sav  

Todo:
* Rerun after modularizing
"""

# Allow to run as a standalone script
if __name__ == "__main__":
    # Use Argparse to handle cli inputs
    parser = argparse.ArgumentParser()
    parser.add_argument('--processed_dga_file', help='The processed dga data file name.')
    parser.add_argument('--output_model_file', help='The filename to save the model to.')
    parser.add_argument('--verbose', nargs="?", default=False, help='Print verbose information.')
    args = parser.parse_args()
    processed_dga_file = args.processed_dga_file
    output_model_file = args.output_model_file
    verbose = args.verbose

    dga_dataset = pd.read_csv(processed_dga_file)
    dga_dataset.drop(columns=['algorithm'], inplace=True)

    word_list = set(words.words())
    word_length_threshold = 3
    # Remove words with less than 4 characters
    word_list = [x for x in word_list if len(x) > word_length_threshold ]

    # Generate features
    # Todo: Turn this into a function as well
    dga_dataset['entropy'] = dga_dataset['domain'].apply(lambda x: generate_shannon_entropy_score(x))
    dga_dataset['domain_root'] = dga_dataset['domain'].apply(lambda x: ''.join(get_domain_parts(x)[:2]))
    dga_dataset['length']= dga_dataset['domain_root'].str.len()
    # Consider making this a ratio of count/length (or the implications for leaving it as-is)
    dga_dataset['uncommon_letters'] = dga_dataset['domain_root'].apply(lambda x: find_uncommon_letters(x))
    dga_dataset['word_count'] = dga_dataset['domain_root'].apply(lambda x: find_words(x, word_list))
    dga_dataset['word_ratio'] = dga_dataset['word_count'] / dga_dataset['length']
    # Todo: Find better solution for domains that have no root, likely due to confusion with
    # what a TLD is. For now, drop NaN (only 84 rows).
    dga_dataset.dropna(inplace=True)

    # Create all possible combinations of masked n-gram values for features.
    ngram_combinations = [''.join(i) for i in itertools.product(masked_ngram_values, repeat = ngram_size)]

    dga_dataset['masked_domain'] = dga_dataset['domain_root'].apply(lambda x: mask_string(x))
    dga_dataset['masked_ngrams'] = dga_dataset['masked_domain'].apply(lambda x: [x[i:i+ngram_size] for i in range(len(x)-ngram_size+1)])

    # One-hot encode masked ngrams and combine with other features. Will not make sparse.
    # Todo: Make this a function that returns the one-hot encoded dataframe, since we do this same thing below.
    mlb = MultiLabelBinarizer()
    dga_dataset = dga_dataset.join(pd.DataFrame(mlb.fit_transform(dga_dataset.pop('masked_ngrams')),
                                   index=dga_dataset.index, columns=mlb.classes_))

    # Add in missing features to make sure this is compatible with the model created below.
    missing_features = list(set(ngram_combinations) - set(mlb.classes_))
    temp_dga_dataset = pd.DataFrame(index=dga_dataset.index, columns=missing_features)
    temp_dga_dataset = temp_dga_dataset.replace(np.nan, 0)

    dga_dataset = dga_dataset.join(temp_dga_dataset)

    # Prepare domain for modeling 
    dga_dataset = dga_dataset.set_index('domain').drop(columns=['domain_root', 'masked_domain'])

    y_col = 'dga'
    y = dga_dataset[y_col]
    X = dga_dataset[dga_dataset.columns.drop(y_col)]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    model = RandomForestClassifier()
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
    acc = accuracy_score(y_test, yhat)

    # Compress and save model to file
    pickled_data = pickle.dumps(model)
    compressed_p_data = blosc.compress(pickled_data)
    with open(output_model_file, "wb") as f:
        f.write(compressed_p_data)

    print('Model build complete. Accuracy of model is %.3f' % acc)
