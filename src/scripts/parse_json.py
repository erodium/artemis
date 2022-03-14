import simplejson
import re

def parse_json(data):
    """
    Reference: https://stackoverflow.com/questions/27659164/how-to-read-multiple-dictionaries-from-a-file-in-python
    """
    FLAGS = re.VERBOSE | re.MULTILINE | re.DOTALL
    WHITESPACE = re.compile(r'[ \t\n\r]*', FLAGS)
    decoder = simplejson.JSONDecoder()
    obj, end = decoder.raw_decode(data)
    end = WHITESPACE.match(data, end).end()
    return obj, data[end:]
