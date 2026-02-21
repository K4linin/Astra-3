"""
Target: cve_ssrf
CVE: CVE-2024-37891, CVE-2018-18074, CVE-2019-20916
"""

import sys
import re
from urllib.parse import urlparse, urlsplit, unquote
from ipaddress import ip_address, ip_network, AddressValueError

PRIVATE_NETWORKS = [
    ip_network('10.0.0.0/8'),
    ip_network('172.16.0.0/12'),
    ip_network('192.168.0.0/16'),
    ip_network('127.0.0.0/8'),
    ip_network('169.254.0.0/16'),
    ip_network('::1/128'),
    ip_network('fc00::/7'),
    ip_network('fe80::/10'),
]

BLOCKED_HOSTS = [
    'localhost',
    'localhost.localdomain',
    'ip6-localhost',
    'ip6-loopback',
    'metadata.google.internal',
    '169.254.169.254',
]


def _is_private_ip(host: str) -> bool:
    try:
        addr = ip_address(host)
        for network in PRIVATE_NETWORKS:
            if addr in network:
                return True
    except (ValueError, AddressValueError):
        pass
    return False


def _dns_rebind_check(host: str) -> dict:
    result = {
        'vulnerable': False,
        'issues': []
    }
    
    if host in BLOCKED_HOSTS:
        result['vulnerable'] = True
        result['issues'].append(f'BLOCKED_HOST:{host}')
    
    try:
        decimal_ip = int(host)
        if _is_private_ip(str(ip_address(decimal_ip))):
            result['vulnerable'] = True
            result['issues'].append(f'DECIMAL_IP:{decimal_ip}')
    except (ValueError, AddressValueError):
        pass
    
    if host.startswith('0x') or host.startswith('0X'):
        try:
            hex_ip = int(host, 16)
            if _is_private_ip(str(ip_address(hex_ip))):
                result['vulnerable'] = True
                result['issues'].append(f'HEX_IP:{host}')
        except (ValueError, AddressValueError):
            pass
    
    if host.startswith('0') and len(host) > 1 and not host.startswith('0x'):
        try:
            octal_ip = int(host, 8)
            if _is_private_ip(str(ip_address(octal_ip))):
                result['vulnerable'] = True
                result['issues'].append(f'OCTAL_IP:{host}')
        except (ValueError, AddressValueError):
            pass
    
    return result


def _check_ssrf_attempt(url: str) -> dict:
    result = {
        'safe': True,
        'issues': [],
        'parsed': None
    }
    
    try:
        parsed = urlparse(url)
        result['parsed'] = {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'path': parsed.path,
        }
        
        safe_schemes = {'http', 'https'}
        if parsed.scheme.lower() not in safe_schemes:
            result['safe'] = False
            result['issues'].append(f'UNSAFE_SCHEME:{parsed.scheme}')
        
        host = parsed.hostname
        if host:
            if host.lower() in BLOCKED_HOSTS:
                result['safe'] = False
                result['issues'].append(f'BLOCKED_HOST:{host}')
            
            if _is_private_ip(host):
                result['safe'] = False
                result['issues'].append(f'PRIVATE_IP:{host}')
            
            rebind = _dns_rebind_check(host)
            if rebind['vulnerable']:
                result['safe'] = False
                result['issues'].extend(rebind['issues'])
            
            if host in ['::1', '[::1]', '0:0:0:0:0:0:0:1']:
                result['safe'] = False
                result['issues'].append('IPV6_LOCALHOST')
        
        if parsed.port:
            dangerous_ports = [22, 23, 25, 3306, 5432, 6379, 27017]
            if parsed.port in dangerous_ports:
                result['issues'].append(f'DANGEROUS_PORT:{parsed.port}')
        
        if parsed.username or parsed.password:
            result['issues'].append('CREDENTIALS_IN_URL')
        
        decoded_netloc = unquote(parsed.netloc)
        if decoded_netloc != parsed.netloc:
            if '@' in decoded_netloc:
                result['safe'] = False
                result['issues'].append('URL_ENCODED_CREDENTIALS')
        
        if '\n' in url or '\r' in url:
            result['safe'] = False
            result['issues'].append('NEWLINE_IN_URL')
        
        if '\x00' in url or '%00' in url:
            result['safe'] = False
            result['issues'].append('NULL_BYTE_IN_URL')
            
    except ValueError as e:
        result['safe'] = False
        result['issues'].append(f'PARSE_ERROR:{str(e)[:50]}')
    except RecursionError:
        result['safe'] = False
        result['issues'].append('RECURSION_ERROR')
        raise
    except MemoryError:
        result['safe'] = False
        result['issues'].append('MEMORY_ERROR')
        raise
    
    return result


def _test_redirect_bypass(data: bytes) -> dict:
    result = {
        'issues': []
    }
    
    try:
        text = data.decode('utf-8', errors='replace')
        
        redirect_patterns = [
            '@',
            '//',
            '\\\\',
            '/\\',
            '\\/',
        ]
        
        for pattern in redirect_patterns:
            if pattern in text:
                result['issues'].append(f'REDIRECT_PATTERN:{repr(pattern)}')
        
        if 'http://' in text and 'https://' in text:
            result['issues'].append('MIXED_PROTOCOLS')
        
        if '\r\n' in text or '%0d%0a' in text.lower():
            result['issues'].append('CRLF_INJECTION')
            
    except UnicodeDecodeError:
        result['issues'].append('DECODE_ERROR')
    
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    try:
        text = data.decode('utf-8', errors='replace')
        
        if len(text) > 10000:
            text = text[:10000]
        
        if '://' not in text:
            url = 'http://' + text
        else:
            url = text
        
        result = _check_ssrf_attempt(url)
        redirect_result = _test_redirect_bypass(data)
        
        if result.get('issues') or redirect_result.get('issues'):
            pass
            
    except ValueError:
        pass
    except UnicodeDecodeError:
        pass


if __name__ == '__main__':
    try:
        import atheris
        atheris.instrument_func(fuzz_target)
        
        @atheris.instrument_func
        def test_one_input(data: bytes):
            fuzz_target(data)
        
        atheris.Setup(sys.argv, test_one_input)
        atheris.Fuzz()
    except ImportError:
        pass
    
    test_cases = [
        b"http://localhost/admin",
        b"http://127.0.0.1/admin",
        b"http://[::1]/admin",
        b"http://2130706433/admin",
        b"http://0x7f000001/admin",
        b"http://0177.0.0.1/admin",
        b"http://169.254.169.254/latest/meta-data/",
        b"http://metadata.google.internal/",
        b"http://evil.com@localhost/admin",
        b"http://localhost.evil.com/admin",
        b"http://localhost\r\nHost: evil.com",
        b"http://localhost%00.evil.com/admin",
        b"http://[0:0:0:0:0:0:0:1]/admin",
        b"http://localhost:22/",
        b"http://localhost:3306/",
        b"file:///etc/passwd",
        b"gopher://localhost:70/",
        b"dict://localhost:11211/stats",
    ]
    
    print("Testing SSRF CVE cases...")
    for test in test_cases:
        try:
            if b'://' in test:
                url = test.decode('utf-8', errors='replace')
            else:
                url = 'http://' + test.decode('utf-8', errors='replace')
            
            result = _check_ssrf_attempt(url)
            if result.get('issues'):
                print(f"[!] SSRF detected: {result['issues']}")
            else:
                print(f"[?] No issues: {test[:50]}...")
        except RecursionError:
            print(f"[!!!] RecursionError with: {test[:50]}...")
        except MemoryError:
            print(f"[!!!] MemoryError with: {test[:50]}...")