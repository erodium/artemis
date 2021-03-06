threatfox_api_url = "https://threatfox-api.abuse.ch/api/v1/"

type_mapping = {
    'ip:port': 'ip-dst|port',
    'url': 'url',
    'md5_hash': 'md5',
    'sha1_hash': 'sha1',
    'sha256_hash': 'sha256',
    'sha3_384_hash': 'sha384',
    'domain': 'domain',
    'envelope_from': 'email-src',
    'body_from': 'email-dst-display-name',
}

confidence_tagging = {
    0: 'misp:confidence-level="unconfident"',
    10: 'misp:confidence-level="rarely-confident"',
    37: 'misp:confidence-level="fairly-confident"',
    63: 'misp:confidence-level="usually-confident"',
    90: 'misp:confidence-level="completely-confident"',
}

lookback_days = 2