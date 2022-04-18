import argparse
import os
import subprocess

"""
Script to generate DGA domains using https://github.com/baderj/domain_generation_algorithms

Usage: generate_dga_domains.py --dga_folder_root="../../../../domain_generation_algorithms/" --output_file="../../../data/raw/dga_dga_domain_data.csv"

Todo:
* Find a much more elegant (and likely secure) way 
"""

# Allow to run as a standalone script
if __name__ == "__main__":
    # Use Argparse to handle cli inputs
    parser = argparse.ArgumentParser()
    parser.add_argument('--dga_folder_root', help='The location where DGA algorithms live under.')
    parser.add_argument('--output_file', help='The filename to save the results to.')
    parser.add_argument('--verbose', nargs="?", default=False, help='Print verbose information.')
    args = parser.parse_args()
    dga_folder_root = args.dga_folder_root
    output_file = args.output_file
    verbose = args.verbose

    dga_script = "dga.py"
    python_binary = "python3.10"

    algorithm_folders = [x[0] for x in os.walk(dga_folder_root)]
   
    f = open(output_file, 'w')
    # Add header for CSV
    f.write("domain,algorithm,dga" + '\n')

    for dga_algorithm_path in algorithm_folders:
        algorithm_name = os.path.split(dga_algorithm_path)[-1]
        if verbose: print(algorithm_name)
        script_location = os.path.join(dga_algorithm_path, dga_script)
        if os.path.exists(script_location):
            cmd = subprocess.run([python_binary, script_location], capture_output=True)
            stdout = cmd.stdout.decode()
            chunked_stdout = stdout.split('\n')
            for entry in chunked_stdout:
                if entry != "":
                    f.write(entry + ',' + algorithm_name + ',' + 'True' + '\n')
        else:
            if verbose: print("No DGA script found in " + str(dga_algorithm_path))

    f.close()
