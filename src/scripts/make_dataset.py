# -*- coding: utf-8 -*-
import click
import logging
import pandas as pd
import sys
from pathlib import Path
from dotenv import find_dotenv, load_dotenv

from artemis_data import load_datafile, clean_data

whois_data_file_suffix = '_whois_data.txt'
entropy_data_file_suffix = '_entropy_data.txt'
ip_data_file_suffix = '_ip_data.txt'
final_data_filename = 'final_whois_data.csv'


@click.command()
@click.argument('input_filepath', type=click.Path(exists=True), required=False, )
@click.argument('output_filepath', type=click.Path())
def main(input_filepath, output_filepath):
    """ Runs data processing scripts to turn raw data from (../data/raw) into
        cleaned data ready to be analyzed (saved in ../data./processed).
    """
    logger = logging.getLogger(__name__)
    logger.info('Making final data set from raw data.')
    # TODO: Finish data processing script

    logger.info(f"Loading benign data from {input_filepath}.")
    benign_domain_df = load_datafile(f"{input_filepath}/benign{whois_data_file_suffix}", filetype='whois')
    benign_entropy_df = load_datafile(f"{input_filepath}/benign{entropy_data_file_suffix}", filetype='entropy')
    benign_ip_df = load_datafile(f"{input_filepath}/benign{ip_data_file_suffix}", filetype='ip')
    benign_merged_df = pd.merge(benign_domain_df, benign_entropy_df, on='domain')
    benign_merged_df = pd.merge(benign_merged_df, benign_ip_df, on='domain')
    benign_merged_df = benign_merged_df.drop_duplicates(subset='domain', keep='last')
    benign_merged_df['malicious'] = 0
    logger.info(f"Loading malicious data from {input_filepath}.")
    malicious_domain_df = load_datafile(f"{input_filepath}/malicious{whois_data_file_suffix}", filetype='whois')
    malicious_entropy_df = load_datafile(f"{input_filepath}/malicious{entropy_data_file_suffix}", filetype='entropy')
    malicious_merged_df = pd.merge(malicious_domain_df, malicious_entropy_df, on='domain')
    malicious_ip_df = load_datafile(f"{input_filepath}/malicious{ip_data_file_suffix}", filetype='ip')
    malicious_merged_df = pd.merge(malicious_merged_df, malicious_ip_df, on='domain')
    malicious_merged_df = malicious_merged_df.drop_duplicates(subset='domain', keep='last')
    malicious_merged_df['malicious'] = 1
    logger.info("Concatenating malicious and benign data files.")
    interim_df = pd.concat([benign_merged_df, malicious_merged_df])
    logger.info("Adding the graph community data.")
    graph_df = pd.read_csv(f"{output_filepath}/graph_community_features.csv")
    graph_df = graph_df.rename(columns={"DomainRecord": 'domain'})
    graph_df = graph_df.drop(columns='malicious_ratio')
    interim2_df = pd.merge(interim_df, graph_df, on='domain')
    logger.info("Cleaning combined dataframe.")
    final_df = clean_data(interim2_df)
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
