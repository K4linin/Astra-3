"""
Target: cve_regex_dos
CVE: CVE-2021-23437, CVE-2022-29189, CVE-2020-7753
"""

import sys
import re
import time
from typing import List, Tuple, Optional

RE_DOS_PATTERNS = [
    (r'^(a+)+$', 'nested_quantifier'),
    (r'^(a|aa)+$', 'alternation_quantifier'),
    (r'^(a|a?)+$', 'optional_quantifier'),
    (r'^(a*)+$', 'star_plus'),
    (r'^(a+)+b', 'no_end_anchor'),
    (r'^([a-zA-Z0-9])+$', 'character_class_quantifier'),
    (r'^(\w+)+$', 'word_quantifier'),
    (r'^(\d+)+$', 'digit_quantifier'),
    (r'^([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$', 'email_complex'),
    (r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', 'email_standard'),
    (r'^(https?://)?([\da-z\.-]+)\.([a-z\.]{2,6})([/\w \.-]*)*/?$', 'url_pattern'),
    (r'<([a-zA-Z][a-zA-Z0-9]*)[^>]*>.*?</\1>', 'html_tag'),
    (r'<!--.*?-->', 'html_comment'),
    (r'^(\d{1,2})([-/.])(\d{1,2})\2(\d{4})$', 'date_pattern'),
    (r'^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$', 'phone_pattern'),
    (r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', 'uuid_pattern'),
]


def _estimate_regex_complexity(pattern: str) -> dict:
    result = {
        'risk': 'low',
        'issues': [],
        'features': []
    }
    
    if re.search(r'\([^)]*\+[^)]*\)\+', pattern):
        result['risk'] = 'high'
        result['issues'].append('NESTED_QUANTIFIER')
    
    if re.search(r'\([^)]*\|[^)]*\)\+', pattern):
        result['risk'] = 'high'
        result['issues'].append('ALTERNATION_WITH_QUANTIFIER')
    
    if re.search(r'\([^)]*\?[^)]*\)\+', pattern):
        result['risk'] = 'high'
        result['issues'].append('OPTIONAL_WITH_QUANTIFIER')
    
    group_count = pattern.count('(') - pattern.count('\\(')
    if group_count > 3:
        result['features'].append(f'MANY_GROUPS:{group_count}')
    
    quantifier_count = len(re.findall(r'[+*?]|\{\d', pattern))
    if quantifier_count > 5:
        result['features'].append(f'MANY_QUANTIFIERS:{quantifier_count}')
    
    if re.search(r'\\[1-9]', pattern):
        result['features'].append('BACKREFERENCE')
    
    if re.search(r'\(\?[=!]', pattern):
        result['features'].append('LOOKAHEAD_LOOKBEHIND')
    
    return result


def _test_regex_safely(pattern: str, test_input: str, timeout_ms: int = 100) -> dict:
    result = {
        'match': None,
        'time_ms': 0,
        'timeout': False,
        'error': None,
        'is_dos': False
    }
    
    try:
        compiled = re.compile(pattern)
        
        start_time = time.perf_counter()
        
        try:
            match = compiled.search(test_input)
            result['match'] = bool(match)
        except RecursionError:
            result['error'] = 'RECURSION_ERROR'
            result['is_dos'] = True
            return result
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        result['time_ms'] = elapsed_ms
        
        if elapsed_ms > timeout_ms:
            result['timeout'] = True
            result['is_dos'] = True
            
    except re.error as e:
        result['error'] = f'REGEX_ERROR:{str(e)[:50]}'
    except RecursionError:
        result['error'] = 'RECURSION_ERROR'
        result['is_dos'] = True
    except MemoryError:
        result['error'] = 'MEMORY_ERROR'
        result['is_dos'] = True
    
    return result


def _generate_evil_inputs(pattern: str, base_input: str) -> List[str]:
    evil_inputs = []
    
    evil_inputs.append(base_input * 10)
    evil_inputs.append(base_input * 100)
    evil_inputs.append(base_input + 'x')
    evil_inputs.append('x' + base_input)
    evil_inputs.append(base_input[:-1] if len(base_input) > 1 else base_input + 'x')
    
    if 'a' in base_input.lower():
        evil_inputs.append('a' * 30)
        evil_inputs.append('a' * 30 + '!')
        evil_inputs.append('a!' * 30)
    
    return evil_inputs


def _analyze_input_for_redos(data: bytes) -> dict:
    result = {
        'patterns_tested': 0,
        'vulnerable_patterns': [],
        'issues': []
    }
    
    if len(data) == 0:
        return result
    
    try:
        text = data.decode('utf-8', errors='replace')
        
        if len(text) > 5000:
            text = text[:5000]
        
        for pattern, name in RE_DOS_PATTERNS:
            try:
                test_result = _test_regex_safely(pattern, text, timeout_ms=50)
                result['patterns_tested'] += 1
                
                if test_result.get('is_dos'):
                    result['vulnerable_patterns'].append({
                        'name': name,
                        'pattern': pattern,
                        'time_ms': test_result.get('time_ms', 0),
                        'error': test_result.get('error')
                    })
            except RecursionError:
                result['issues'].append(f'RECURSION_IN:{name}')
            except MemoryError:
                result['issues'].append(f'MEMORY_IN:{name}')
        
        for char in set(text):
            if text.count(char * 5) > 3:
                result['issues'].append(f'REPEATED_CHARS:{char}')
        
        if text.count('(') > 10 or text.count('[') > 10:
            result['issues'].append('MANY_BRACKETS')
        
        if text.count('\\') > 10:
            result['issues'].append('MANY_BACKSLASHES')
            
    except UnicodeDecodeError:
        result['issues'].append('DECODE_ERROR')
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
        result = _analyze_input_for_redos(data)
        
        if result.get('vulnerable_patterns'):
            pass
            
    except UnicodeDecodeError:
        pass
    except ValueError:
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
        b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!',
        b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab',
        b'aaa' * 20 + b'!',
        b'abcabcabcabcabcabcabcabcabcabcabcabc!',
        b'a@a@a@a@a@a@a@a@a@a@a@a@a@a@a@a@a@a@a',
        b'aaa' * 30,
        b'<' + b'div' * 50 + b'>',
        b'(((' + b'a' * 100 + b')))',
        b'(?=' + b'a' * 50 + b')',
        b'(a)\\1' * 30,
        b'[a-z]' * 50,
        b'a?b?c?d?e?f?' * 30,
        b'a+' * 50 + b'b',
    ]
    
    print("Testing ReDoS CVE cases...")
    for test in test_cases:
        try:
            result = _analyze_input_for_redos(test)
            if result.get('vulnerable_patterns'):
                print(f"[!] ReDoS detected: {len(result['vulnerable_patterns'])} vulnerable patterns")
            if result.get('issues'):
                print(f"[!] Issues: {result['issues']}")
        except RecursionError:
            print(f"[!!!] RecursionError with: {test[:30]}...")
        except MemoryError:
            print(f"[!!!] MemoryError with: {test[:30]}...")
    
    print("\nTesting known dangerous patterns with evil inputs...")
    for pattern, name in RE_DOS_PATTERNS[:5]:
        evil_inputs = _generate_evil_inputs(pattern, 'test')
        for evil in evil_inputs[:3]:
            try:
                test_result = _test_regex_safely(pattern, evil, timeout_ms=100)
                if test_result.get('is_dos') or test_result.get('time_ms', 0) > 50:
                    print(f"[!] Pattern '{name}' vulnerable: {test_result['time_ms']:.2f}ms")
                    break
            except Exception as e:
                print(f"[!] Pattern '{name}' error: {e}")