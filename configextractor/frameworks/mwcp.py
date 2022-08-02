# MWCP framework

import inspect
import mwcp

from configextractor.frameworks.base import Framework
from mwcp import Parser


def convert_to_MACO(metadata: list) -> dict:
    config = {}
    for meta in metadata:
        if meta['type'] == 'alphabet':
            # BaseXX alphabet
            True
        elif meta['type'] == 'command':
            # Shell commands
            # TODO incorporate Shell commands into model
            True
        elif meta['type'] == 'credential' and meta.get('password'):
            # Credentials
            config.setdefault("passwords", []).append(meta['password'])
        elif meta['type'] == 'crypto_address':
            # Cryptocurrent Addresses
            config.setdefault('cryptocurrency', []).append({
                'address': meta['address'],
                'coin': meta.get('symbol')
            })
        elif meta['type'] == 'decoded_string':
            # Decoded strings
            config.setdefault('decoded_strings', []).append(meta['value'])
            encryption = meta['encryption_key']
            if encryption:
                config.setdefault('encryption', []).append({
                    'algorithm': encryption.get('algorithm'),
                    'public_key': encryption['key'],
                    'mode': encryption.get('mode'),
                    'iv': encryption.get('iv')
                })
        elif meta['type'] == 'email_address':
            # Email addresses
            # TODO incorporate found email addresses into model
            config.setdefault('other', {})['email_address'] = meta['value']
        elif meta['type'] == 'encryption_key':
            # Encryption
            config.setdefault('encryption', []).append({
                'algorithm': encryption.get('algorithm'),
                'public_key': encryption['key'],
                'mode': encryption.get('mode'),
                'iv': encryption.get('iv')
            })
        elif meta['type'] == 'event':
            # System Events
            # TODO incorporate System Events into model
            config.setdefault('other', {})['event'] = meta['value']
        elif meta['type'] == 'injection_process':
            # Victim Process
            config.setdefault('inject_exe', []).append(meta['value'])
        elif meta['type'] == 'interval':
            # Interval associated to malware
            config.setdefault('sleep_delay', []).append(meta['value'])
        elif meta['type'] == 'mission_id':
            # Campaign ID
            config.setdefault('campaign_id', []).append(meta['value'])
        elif meta['type'] == 'mutex':
            # Mutex
            config.setdefault('mutex', []).append(meta['value'])
        elif meta['type'] == 'path':
            # File path
            config.setdefault('paths', []).append({'path': meta['path']})
        elif meta['type'] == 'pipe':
            # Pipes
            config.setdefault('pipe', []).append({'path': meta['value']})
        elif meta['type'] == 'registry':
            # Registry
            config.setdefault('registry', []).append({'key': meta['value']})
        elif meta['type'] == 'service':
            # Windows service
            config.setdefault('service', []).append({
                'dll': meta.get('dll'),
                'name': meta.get('name'),
                'display_name': meta.get('display_name'),
                'description': meta.get('description')
            })
        elif meta['type'] == 'socket':
            # Socket
            net_protocol = meta.get('network_protocol', 'tcp')
            if net_protocol in ['tcp', 'udp']:
                config.setdefault(net_protocol, []).append({
                    'server_ip': meta['address'],
                    'server_port': meta['port'],
                    'usage': 'c2' if meta.get('c2') else 'other'
                })
        elif meta['type'] == 'url':
            # URL
            config.setdefault('http', []).append({
                'uri': meta.get('url'),
                'path': meta.get('path'),
                'query': meta.get('query'),
                'protocol': meta.get('application_protocol'),
                'username': meta.get('credential', {}).get('username'),
                'password': meta.get('credential', {}).get('password')
            })
            if meta.get('socket'):
                net_protocol = meta['socket'].get('network_protocol', 'tcp')
                if net_protocol in ['tcp', 'udp']:
                    config.setdefault(net_protocol, []).append({
                        'server_ip': meta['socket']['address'],
                        'server_port': meta['socket']['port'],
                        'usage': 'c2' if meta['socket'].get('c2') else 'other'
                    })
        elif meta['type'] == 'user_agent':
            # User Agent
            config.setdefault('http', []).append({
                'user_agent': meta['value']
            })
        elif meta['type'] == 'uuid':
            # UUID
            config['identifier'] = meta['value']
        elif meta['type'] == 'version':
            # Version of malware
            config['version'] = meta['value']
        elif meta['type'] == 'other':
            # Catch-all
            config.setdefault('other', {})[meta['key']] = meta['value']


class MWCP(Framework):
    def validate(self, parser):
        if inspect.isclass(parser):
            return issubclass(parser, Parser) and (parser.AUTHOR or parser.DESCRIPTION)

    def run(self, sample_path, parsers):
        results = dict()

        for parser, yara_matches in parsers.items():
            parser_name = MWCP.get_name(parser)
            try:
                # Just run MWCP parsers directly, using the filename to fetch the class attribute from module
                result = mwcp.run(parser, data=open(sample_path, 'rb').read()).as_dict()
                if result:
                    [self.log.error(e) for e in result.get('errors', [])]
                    if result.get('metadata'):
                        return results.update({parser.__name__: result})
            except Exception as e:
                self.log.error(f"{parser_name}: {e}")
        return results
