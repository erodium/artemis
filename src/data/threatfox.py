from datetime import datetime
import json
import requests

from config import (
    type_mapping,
    threatfox_api_url as fetch_url,
    confidence_tagging
)

class ThreatFoxHandler():
    tf_data = []

    def fetch_threatfox(self, time: int) -> dict:
        """
            Query current IOC set from ThreatFox API
        """
        post_data = f'{{ "query": "get_iocs", "days": {time} }}'
        data = requests.post(fetch_url, post_data).content.decode('utf-8')
        self.tf_data = json.loads(data)['data']
        return self.tf_data

    def convert_to_attributes(self, clusters: list) -> list:
        """
            convert IOCs to MISP-Attributes and add Galaxy-Clusters by Malware-Name
        """
        attributes = []
        att = {}
        for ioc in self.tf_data:
            att['value'] = ioc['ioc']
            att['type'] = type_mapping[ioc['ioc_type']]
            if '|' in att['type']:
                att['value'] = att['value'].replace(':', '|')
            att['Tag'] = []
            if ioc['tags']:
                # tags = [{'name': tag.strip()} for tag in ioc['tags'].split(',')]
                tags = ioc['tags']
                att['Tag'].extend(tags)
            fs = datetime.strptime(ioc['first_seen'], '%Y-%m-%d %H:%M:%S UTC')
            att['first_seen'] = datetime.timestamp(fs)
            if 'last_seen' in ioc and ioc['last_seen']:
                ls = datetime.strptime(ioc['last_seen'], '%Y-%m-%d %H:%M:%S UTC')
                att['last_seen'] = max(datetime.timestamp(fs), datetime.timestamp(ls))
            names = []
            if ioc['malware_alias']:
                names = ioc['malware_alias'].lower().split(',')
            names.append(ioc['malware_printable'].lower())
            for c in clusters:
                if c['value'].lower() in names:
                    att['Tag'].append({'name': c['tag_name']})
            if not att['Tag']:
                att['Tag'].append({'name': ioc['malware_printable']})
            # append confidence-tag
            att['Tag'].append(self.confidence_level_to_tag(ioc['confidence_level']))
            att['comment'] = ioc['threat_type']
            if ioc['reference']:
                att['comment'] += f"\n{ioc['reference']}"
            attributes.append(att.copy())
        return attributes

    def confidence_level_to_tag(level: int) -> str:
        """
            map a confidence Level 0-100 to misp:confidence Taxonomy
        """
        confidence_tag = ''
        for tag_minvalue, tag in confidence_tagging.items():
            if level >= tag_minvalue:
                confidence_tag = tag
        return {'name': confidence_tag}