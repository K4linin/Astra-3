"""
Target: cve_url_parsing
CVE: CVE-2023-24329, CVE-2023-43806, CVE-2024-37891
"""

import sys
from urllib.parse import urlparse, urlsplit, parse_qs, unquote


def _parse_url_safely(data: bytes) -> dict:
    result = {
        'scheme': None,
        'netloc': None,
        'path': None,
        'query': None,
        'fragment': None,
        'issues': []
    }
    
    if len(data) == 0:
        return result
    
    try:
        text = data.decode('utf-8', errors='replace')
        
        if len(text) > 10000:
            text = text[:10000]
        
        if '://' not in text:
            url = 'http://' + text
        else:
            url = text
        
        parsed = urlparse(url)
        result['scheme'] = parsed.scheme
        result['netloc'] = parsed.netloc
        result['path'] = parsed.path
        result['query'] = parsed.query
        result['fragment'] = parsed.fragment
        
        if parsed.netloc and (' ' in parsed.netloc or '\t' in parsed.netloc):
            result['issues'].append('WHITESPACE_IN_NETLOC')
        
        if any(ord(c) < 0x20 and c not in '\t\r\n' for c in url):
            result['issues'].append('CONTROL_CHARS_IN_URL')
        
        if parsed.scheme and parsed.scheme not in ['http', 'https', 'ftp', 'file']:
            result['issues'].append(f'UNUSUAL_SCHEME:{parsed.scheme}')
        
        split_result = urlsplit(url)
        if split_result.netloc != parsed.netloc:
            result['issues'].append('NETLOC_MISMATCH')
        
        if parsed.query:
            try:
                qs_result = parse_qs(parsed.query, keep_blank_values=True)
                if len(str(qs_result)) > 100000:
                    result['issues'].append('QUERY_STRING_LARGE')
            except ValueError:
                result['issues'].append('QUERY_PARSE_ERROR')
        
        try:
            unquoted = unquote(url)
            if len(unquoted) > len(url) * 10:
                result['issues'].append('UNQUOTE_EXPANSION')
        except ValueError:
            result['issues'].append('UNQUOTE_ERROR')
            
    except UnicodeDecodeError:
        result['issues'].append('DECODE_ERROR')
    except ValueError:
        result['issues'].append('PARSE_ERROR')
    except RecursionError:
        result['issues'].append('RECURSION_ERROR')
        raise
    except MemoryError:
        result['issues'].append('MEMORY_ERROR')
        raise
    
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    try:
        result = _parse_url_safely(data)
        if result.get('issues'):
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
        b" http://evil.com",
        b"\thttp://evil.com",
        b"  http://evil.com",
        b"http://evil.com\n",
        b"http://\x00evil.com",
        b"http://\x1fevil.com",
        b"http://evil\x0d\x0a.com",
        b"javascript:alert(1)",
        b"file:///etc/passwd",
        b"data:text/html,<script>alert(1)</script>",
        b"http://test.com?q=" + b"a" * 100000,
        b"http://\x00evil.com",
        b"http://evil.com/\xe2\x80\xae",
    ]
    
    print("Testing URL parsing CVE cases...")
    for test in test_cases:
        try:
            result = _parse_url_safely(test)
            if result.get('issues'):
                print(f"[!] Issues found: {result['issues']}")
        except RecursionError:
            print(f"[!!!] RecursionError with: {test[:50]}...")
        except MemoryError:
            print(f"[!!!] MemoryError with: {test[:50]}...")