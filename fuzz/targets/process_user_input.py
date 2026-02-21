"""
Target: process_user_input
Фаззинг обработки пользовательского ввода: SQL/XSS injection, валидация
"""

import re
import sys
from typing import Any, Dict


class InputValidationError(Exception):
    pass


def sanitize_string(value: str, max_length: int = 10000) -> str:
    if len(value) > max_length:
        value = value[:max_length]
    
    value = value.replace('\x00', '')
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    
    return value


def validate_email(email: str) -> bool:
    if len(email) > 254:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_username(username: str) -> bool:
    if len(username) < 3 or len(username) > 64:
        return False
    pattern = r'^[a-zA-Z0-9_]+$'
    return bool(re.match(pattern, username))


def detect_sql_injection(value: str) -> bool:
    sql_patterns = [
        r"('|\")\s*(OR|AND)\s*('|\")",
        r";\s*(DROP|DELETE|UPDATE|INSERT)",
        r"UNION\s+SELECT",
        r"--\s*$",
        r"/\*.*\*/",
        r"xp_cmdshell",
        r"CONCAT\s*\(",
        r"CHAR\s*\(",
    ]
    
    value_upper = value.upper()
    for pattern in sql_patterns:
        if re.search(pattern, value_upper, re.IGNORECASE):
            return True
    return False


def detect_xss(value: str) -> bool:
    xss_patterns = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"expression\s*\(",
        r"vbscript:",
    ]
    
    value_lower = value.lower()
    for pattern in xss_patterns:
        if re.search(pattern, value_lower, re.IGNORECASE):
            return True
    return False


def escape_html(value: str) -> str:
    replacements = {
        '&': '&',
        '<': '<',
        '>': '>',
        '"': '"',
        "'": '&#x27;',
    }
    
    for char, replacement in replacements.items():
        value = value.replace(char, replacement)
    
    return value


def process_input_field(name: str, value: str, field_type: str = 'text') -> Dict[str, Any]:
    result = {
        'name': sanitize_string(name, 100),
        'original_value': value,
        'sanitized': False,
        'warnings': []
    }
    
    sanitized = sanitize_string(value)
    if sanitized != value:
        result['sanitized'] = True
        result['warnings'].append('Value was sanitized')
    
    result['value'] = sanitized
    
    if detect_sql_injection(sanitized):
        result['warnings'].append('Potential SQL injection detected')
    
    if detect_xss(sanitized):
        result['warnings'].append('Potential XSS detected')
        result['value'] = escape_html(sanitized)
    
    if field_type == 'email':
        if not validate_email(sanitized):
            raise InputValidationError(f"Invalid email format: {sanitized[:50]}")
    elif field_type == 'username':
        if not validate_username(sanitized):
            raise InputValidationError(f"Invalid username: {sanitized[:50]}")
    
    return result


def process_form(data: Dict[str, Any]) -> Dict[str, Any]:
    result = {
        'fields': {},
        'valid': True,
        'errors': []
    }
    
    for field_name, field_value in data.items():
        try:
            if isinstance(field_value, str):
                field_result = process_input_field(field_name, field_value, field_type='text')
                result['fields'][field_name] = field_result
            elif isinstance(field_value, dict):
                result['fields'][field_name] = process_form(field_value)
            elif isinstance(field_value, list):
                result['fields'][field_name] = [
                    process_input_field(f"{field_name}[{i}]", str(v))
                    for i, v in enumerate(field_value[:100])
                ]
        except InputValidationError as e:
            result['valid'] = False
            result['errors'].append(str(e))
    
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    try:
        text = data.decode('utf-8', errors='replace')
    except:
        return
    
    try:
        _ = sanitize_string(text)
    except:
        pass
    
    try:
        _ = detect_sql_injection(text)
        _ = detect_xss(text)
    except:
        pass
    
    try:
        _ = process_input_field('test_field', text)
    except InputValidationError:
        pass
    except RecursionError:
        pass
    except MemoryError:
        pass
    
    try:
        import json
        if text.strip().startswith('{'):
            form_data = json.loads(text)
            _ = process_form(form_data)
    except json.JSONDecodeError:
        pass
    except InputValidationError:
        pass
    except RecursionError:
        pass
    except MemoryError:
        pass


if __name__ == '__main__':
    try:
        import atheris
        
        @atheris.instrument_func
        def test_one_input(data: bytes):
            fuzz_target(data)
            
        atheris.Setup(sys.argv, test_one_input)
        atheris.Fuzz()
    except ImportError:
        print("atheris not installed")
        test_cases = [
            b"normal text",
            b"<script>alert('xss')</script>",
            b"' OR '1'='1",
            b"user@example.com",
            b"A" * 100000,
            b"\x00\x01\x02<script>",
        ]
        
        for test in test_cases:
            try:
                fuzz_target(test)
                print(f"OK: {test[:50]}...")
            except Exception as e:
                print(f"FAIL: {test[:50]}... -> {e}")