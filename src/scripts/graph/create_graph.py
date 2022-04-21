import argparse
import subprocess
import time
import pandas as pd
import pyTigerGraph as tg
import paramiko
import os

if __name__ == "__main__":
    # Use Argparse to handle cli inputs
    parser = argparse.ArgumentParser()
    result = subprocess.run(['docker', 'ps'], stdout=subprocess.PIPE)
    if result.returncode == 1:
        print("Please install docker")
        exit(1)
    if str(result.stdout).find("tigergraph") == -1:
        print("Starting tigergraph container")
        data_dir = os.getcwd() + "/data/external"
        cmd = f"docker run -d -p 14022:22 -p 9000:9000 -p 14240:14240 --name tigergraph --ulimit nofile=1000000:1000000 -v {data_dir}:/home/tigergraph/data -t docker.tigergraph.com/tigergraph:latest"
        cmd_list = cmd.split(" ")
        result = subprocess.run(cmd_list, stdout=subprocess.PIPE)
        if result.returncode == 1:
            print("Unable to start TigerGraph container")
            exit(1)

    host = "localhost"
    port = 14022
    username = "tigergraph"
    password = "tigergraph"

    command = "/home/tigergraph/tigergraph/app/cmd/gadmin status"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port, username, password)

    stdin, stdout, stderr = ssh.exec_command(command)

    print("starting graph engine - 4 mins")
    time.sleep(240)

    conn = tg.TigerGraphConnection()
    print("clearing all graphs and data - takes about 5 mins")
    print(conn.gsql('drop all', options=[]))
    text_file = open(os.getcwd() + "/src/scripts/DBImportExport_Artemis.gsql", "r")
    artemis_graph_gsql = text_file.read()
    text_file.close()
    print("Installing schema and queries - 3 mins")
    print(conn.gsql(artemis_graph_gsql, options=[]))
    print(conn.gsql('INSTALL QUERY ALL', options=[]))
    # set train / test switch
    train_test = 'train'
    loading_job = """RUN LOADING JOB load_job_whois_data{field1} USING MyDataSource="/home/tigergraph/data/combined_whois_data{field2}.csv\""""
    print(conn.gsql(loading_job.format(field1=f"", field2=f"_{train_test}"), graphname='Artemis',
                    options=[]))

    list_of_explode_columns = ['country', 'emails', 'whois_server', 'domain_status', 'registrar',
                               'name_servers']

    for x in list_of_explode_columns:
        print(conn.gsql(loading_job.format(field1=f"_{x}", field2=f"_{x}_{train_test}"),
                        graphname='Artemis', options=[]))

    # Load entropy data
    loading_job = f'RUN LOADING JOB load_job_entropy USING MyDataSource="/home/tigergraph/data/benign_entropy_data_{train_test}.txt"'
    print(conn.gsql(loading_job, graphname='Artemis', options=[]))
    loading_job = f'RUN LOADING JOB load_job_entropy USING MyDataSource="/home/tigergraph/data/malicious_entropy_data_{train_test}.txt"'
    print(conn.gsql(loading_job, graphname='Artemis', options=[]))

    # Load MX / A org data
    loading_job = f'RUN LOADING JOB load_job_A_org USING MyDataSource="/home/tigergraph/data/combined_A_org_{train_test}.csv"'
    print(conn.gsql(loading_job, graphname='Artemis', options=[]))

    loading_job = f'RUN LOADING JOB load_job_MX_org USING MyDataSource="/home/tigergraph/data/combined_MX_org_{train_test}.csv"'
    print(conn.gsql(loading_job, graphname='Artemis', options=[]))

    conn.graphname = 'Artemis'

    # Run co_edge creation
    print(conn.runInstalledQuery("community_stuff", timeout=30000))
    print(conn.runInstalledQuery("delete_co_loop_edges", timeout=30000))

    params = "v_type=DomainRecord&e_type=co_registrar&e_type=c_org&e_type=co_nameserver&max_iter=10000&output_limit=0&print_accum=1&attr=community"

    if train_test == "train":
        result = conn.runInstalledQuery("tg_label_prop", params=params, timeout=30000)
        community_features = conn.runInstalledQuery("community_features_calc", timeout=30000)
        community_features = conn.runInstalledQuery("community_features_calc", timeout=30000)
    else:
        result = conn.runInstalledQuery("lfp_new_nodes_label_prop", params=params, timeout=30000)

    if train_test == "train":
        community_features_df = pd.DataFrame(community_features[0]['(@@group_entropy_final)'])
        community_features_df.to_csv("../data/processed/community_features.csv")
    else:
        community_features_df = pd.read_csv("../data/processed/community_features.csv")

    DomainRecordsGSQL = """INTERPRET QUERY () FOR GRAPH Artemis {
       t = select dr from DomainRecord:dr;
       print(t);
    }"""

    domain_records = conn.runInterpretedQuery(DomainRecordsGSQL)
    dr_dict = {}
    for x in domain_records[0]['(t)']:
        dr_dict[x['v_id']] = x['attributes']['community']
    domain_record_df = pd.DataFrame.from_dict(dr_dict, orient='index').reset_index()
    domain_record_df.columns = ['DomainRecord', 'community']

    graph_features_df = domain_record_df.merge(community_features_df, how='left', on='community')

    graph_features_df.to_csv(f'../data/processed/graph_community_features_{train_test}.csv',
                             index=False)












