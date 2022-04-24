from setuptools import find_packages, setup

setup(
    name='artemis',
    packages=find_packages(),
    version='0.1.0',
    description='Every day, threat actors utilize internet domain names to facilitate their malicious activity. This activity includes command and control (C2) of compromised infrastructure, exfiltration of sensitive data, and the delivery of malicious payloads via common internet technologies. The domain names involved in these campaigns are either specifically registered by the threat actor for a malicious purpose or are legitimate assets that have been compromised with the intent of exploiting that legitimacy to evade detection and fool unsuspecting victims. Our goal is to collect publicly available data and attempt to predict the probability that an internet domain name will be used for malicious purposes, what malicious activity the domain name facilitates, and which threat actor is most likely to carry out that activity. ',
    author='MADS Artemis Team',
    license='',
    install_requires=[
        'Click'
    ],
    entry_points={
        'console_scripts': [
            'artemis = src.scripts.artemis:cli',
        ],
    },
)
