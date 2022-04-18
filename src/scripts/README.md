## Notes on artemis data generation scripts.

* generate_entropy_data.py: Built to run off of raw benign/malicious whois file (i.e., benign_whois_data.txt). Will generate entropy file for the class (i.e., benign_entropy_data.txt).
* get_dns_resolution_data.py: Built to run off of raw benign/malicious whois file (i.e., benign_whois_data.txt). Will generate dns resolution file for the class (i.e., benign_dns_resolution_data.txt).
* get_ip_dns_resolution_data.py: Run after dns resolution data generated, built to run off of the dns resolution file (i.e., benign_dns_resolution_data.txt) to generate IP data for the class (i.e., benign_ip_data.txt).
* generate_dga_data.py: Needs to run from root of project folder to properly pick up the DGA model. Built to run off of raw benign/malicious whois file (i.e., benign_dga_data.txt). Will generate entropy file for the class (i.e., benign_dga_data.txt).
