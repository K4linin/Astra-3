"""
Target: cve_path_traversal
CVE: CVE-2021-4118, CVE-2021-33558, CVE-2020-28475
"""

import sys
import os
import re
from urllib.parse import unquote, quote


def _normalize_path(path: str) -> str:
    path = path.replace('\x00', '')
    
    prev = None
    while prev != path:
        prev = path
        path = unquote(path)
    
    path = path.replace('\\', '/')
    
    while '//' in path:
        path = path.replace('//', '/')
    
    return path


def _detect_traversal_attempt(path: str) -> dict:
    result = {
        'is_traversal': False,
        'issues': [],
        'normalized': None
    }
    
    if not path:
        return result
    
    try:
        normalized = _normalize_path(path)
        result['normalized'] = normalized
        
        if '../' in normalized or '..\\' in path:
            result['is_traversal'] = True
            result['issues'].append('DOTDOT_SLASH')
        
        encoded_patterns = [
            '%2e%2e/',
            '%2e%2e%2f',
            '%2e%2e%5c',
            '..%2f',
            '..%5c',
            '%252e%252e',
            '..%c0%af',
            '..%c1%9c',
        ]
        
        for pattern in encoded_patterns:
            if pattern.lower() in path.lower():
                result['is_traversal'] = True
                result['issues'].append(f'ENCODED_TRAVERSAL:{pattern}')
        
        if '%' in path and unquote(path) != path:
            decoded = unquote(path)
            if '../' in decoded or '..\\' in decoded:
                result['is_traversal'] = True
                result['issues'].append('DOUBLE_ENCODED_TRAVERSAL')
        
        unicode_patterns = [
            '\u002e\u002e',
            '\uff0e\uff0e',
            '\u2024\u2024',
        ]
        
        for pattern in unicode_patterns:
            if pattern in path:
                result['is_traversal'] = True
                result['issues'].append('UNICODE_TRAVERSAL')
        
        if '\x00' in path or '%00' in path.lower():
            result['is_traversal'] = True
            result['issues'].append('NULL_BYTE_INJECTION')
        
        if normalized.startswith('/') or (len(normalized) > 1 and normalized[1] == ':'):
            result['issues'].append('ABSOLUTE_PATH')
        
        sensitive_paths = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/proc/self',
            '/var/log',
            '/windows/system32',
            '\\windows\\system32',
            'c:\\windows',
            'c:/windows',
        ]
        
        for sensitive in sensitive_paths:
            if sensitive.lower() in normalized.lower():
                result['is_traversal'] = True
                result['issues'].append(f'SENSITIVE_PATH:{sensitive}')
        
        if '..' in normalized:
            levels_up = normalized.count('../') + normalized.count('..\\')
            if levels_up > 3:
                result['is_traversal'] = True
                result['issues'].append(f'DEEP_TRAVERSAL:{levels_up}')
                
    except RecursionError:
        result['is_traversal'] = True
        result['issues'].append('RECURSION_ERROR')
        raise
    except MemoryError:
        result['is_traversal'] = True
        result['issues'].append('MEMORY_ERROR')
        raise
    
    return result


def _safe_path_join(base_dir: str, user_path: str) -> dict:
    result = {
        'safe': True,
        'path': None,
        'issues': []
    }
    
    try:
        base_dir = os.path.normpath(base_dir)
        
        traversal_check = _detect_traversal_attempt(user_path)
        if traversal_check['is_traversal']:
            result['safe'] = False
            result['issues'].extend(traversal_check['issues'])
            return result
        
        normalized_user = _normalize_path(user_path)
        
        full_path = os.path.join(base_dir, normalized_user)
        full_path = os.path.normpath(full_path)
        
        if not os.path.isabs(base_dir):
            base_dir = os.path.abspath(base_dir)
        
        full_path_abs = os.path.abspath(full_path)
        
        if not full_path_abs.startswith(base_dir + os.sep) and full_path_abs != base_dir:
            result['safe'] = False
            result['issues'].append('ESCAPED_BASE_DIR')
            return result
        
        result['path'] = full_path_abs
        
    except ValueError as e:
        result['safe'] = False
        result['issues'].append(f'VALUE_ERROR:{str(e)[:50]}')
    except RecursionError:
        result['safe'] = False
        result['issues'].append('RECURSION_ERROR')
        raise
    except MemoryError:
        result['safe'] = False
        result['issues'].append('MEMORY_ERROR')
        raise
    
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    try:
        text = data.decode('utf-8', errors='replace')
        
        if len(text) > 10000:
            text = text[:10000]
        
        result = _detect_traversal_attempt(text)
        join_result = _safe_path_join('/var/www/uploads', text)
        
        if result.get('issues') or join_result.get('issues'):
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
        b"../../../etc/passwd",
        b"..\\..\\..\\windows\\system32\\config\\sam",
        b"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        b"..%2f..%2f..%2fetc/passwd",
        b"%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
        b"..%c0%af..%c0%af..%c0%afetc/passwd",
        b"..%c1%9c..%c1%9c..%c1%9cetc/passwd",
        b"../../../etc/passwd%00.jpg",
        b"../../../etc/passwd\x00.jpg",
        b"\x2e\x2e/\x2e\x2e/\x2e\x2e/etc/passwd",
        b"\xef\xbc\x8e\xef\xbc\x8e/\xef\xbc\x8e\xef\xbc\x8e/\xef\xbc\x8e\xef\xbc\x8e/etc/passwd",
        b"..//..//..//etc/passwd",
        b"..\\../..\\../..\\../etc/passwd",
        b"/etc/passwd",
        b"C:\\Windows\\System32\\config\\SAM",
        b"....//....//....//etc/passwd",
        b"..../..../..../etc/passwd",
        b"safe.txt/../../../etc/passwd",
        b"safe.txt\x00/../../../etc/passwd",
    ]
    
    print("Testing Path Traversal CVE cases...")
    for test in test_cases:
        try:
            text = test.decode('utf-8', errors='replace')
            result = _detect_traversal_attempt(text)
            if result.get('is_traversal'):
                print(f"[!] Traversal detected: {result['issues']}")
            else:
                print(f"[?] No issues: {test[:50]}...")
        except RecursionError:
            print(f"[!!!] RecursionError with: {test[:50]}...")
        except MemoryError:
            print(f"[!!!] MemoryError with: {test[:50]}...")