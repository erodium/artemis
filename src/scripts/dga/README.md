These tools are used to generate a DGA dataset, DGA model (RandomForestClassifier), and make predictions against the model.

## MODEL BUILD PREREQUISITES
1. Download a copy of the DGA generation algorithms from https://github.com/baderj/domain_generation_algorithms.

## MODEL BUILD PROCESS
1. Run generate_dga_domains.py
2. Run get_benign_domains.py
3. Run make_dga_dataset.py
4. Run build_dga_model.py
Note: Command line syntax and examples are noted within each script.

## PREDICTION PREREQUISITES
1. Ensure all Python modules from requirements.txt are installed.

## PREDICTION PROCESS
1. Review and run example_predict.py. 

Example (fictitious entropy values used):
```
python example_predict.py --domain_name hjlskadfjoie.com --entropy_value 3.5
Domain hjlskadfjoie.com is a DGA.

python example_predict.py --domain_name google.com --entropy_value 3.1
Domain google.com is not a DGA.
```
