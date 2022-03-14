import tldextract
"""
Get the parts of a domain.
The returned value is a named tuple, with three values (ext.subdomain, ext.domain, ext.suffix).
Reference: https://github.com/john-kurkowski/tldextract
"""

def get_domain_parts(domain_name):
    domain_parts = tldextract.extract(domain_name)
    return domain_parts
