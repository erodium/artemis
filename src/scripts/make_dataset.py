# -*- coding: utf-8 -*-
import click
import logging
import os
import pandas as pd
import sys
from pathlib import Path
from dotenv import find_dotenv, load_dotenv

from artemis_data import load_whois_datafile, load_entropy_datafile

whois_data_file_suffix = '_whois_data.txt'
entropy_data_file_suffix = '_entropy_data.txt'
ip_data_file_suffix = '_ip_data.txt'
final_data_filename = 'whois_data.csv'

@click.command()
@click.argument('input_filepath', type=click.Path(exists=True), required=False, )
@click.argument('output_filepath', type=click.Path())
def main(input_filepath, output_filepath):
    """ Runs data processing scripts to turn raw data from (../data/raw) into
        cleaned data ready to be analyzed (saved in ../data./processed).
    """
    logger = logging.getLogger(__name__)
    logger.info('Making final data set from raw data.')
    #TODO: Finish data processing script

    logger.info(f"Loading benign data from {input_filepath}.")
    benign_domain_df = load_whois_datafile(f"{input_filepath}/benign{whois_data_file_suffix}")
    benign_entropy_df = load_entropy_datafile(f"{input_filepath}/benign{entropy_data_file_suffix}")
    benign_merged_df = pd.merge(benign_domain_df, benign_entropy_df, on='domain')
    benign_merged_df['malicious'] = False
    logger.info(f"Loading malicious data from {input_filepath}.")
    malicious_domain_df = load_whois_datafile(f"{input_filepath}/malicious{whois_data_file_suffix}")
    malicious_entropy_df = load_entropy_datafile(f"{input_filepath}/malicious{entropy_data_file_suffix}")
    malicious_merged_df = pd.merge(malicious_domain_df, malicious_entropy_df, on='domain')
    malicious_merged_df['malicious'] = True
    logger.info("Concatenating malicious and benign data files.")
    final_df = pd.concat([benign_merged_df, malicious_merged_df])
    outfile = f"{output_filepath}/{final_data_filename}"
    final_df.to_csv(outfile, index=False)
    logger.info(f"Wrote merged datafile to {outfile}.")
    sys.exit()

if __name__ == '__main__':
    log_fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=log_fmt)

    # not used in this stub but often useful for finding various files
    project_dir = Path(__file__).resolve().parents[2]
    print(project_dir)
    # find .env automagically by walking up directories until it's found, then
    # load up the .env entries as environment variables
    load_dotenv(find_dotenv())

    main()
