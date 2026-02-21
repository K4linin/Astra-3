"""
Target: validate_schema
Фаззинг валидации JSON Schema
"""

import json
import re
import sys
from typing import Any, Dict


class SchemaValidationError(Exception):
    pass


def validate_type(value: Any, expected_type: str) -> bool:
    type_map = {
        'string': str,
        'number': (int, float),
        'integer': int,
        'boolean': bool,
        'array': list,
        'object': dict,
        'null': type(None)
    }
    
    expected = type_map.get(expected_type)
    if expected is None:
        return True
    
    return isinstance(value, expected)


def validate_string(value: str, constraints: Dict[str, Any]) -> bool:
    if not isinstance(value, str):
        return False
    
    if 'minLength' in constraints:
        if len(value) < constraints['minLength']:
            return False
    
    if 'maxLength' in constraints:
        if len(value) > constraints['maxLength']:
            return False
    
    if 'pattern' in constraints:
        try:
            if not re.search(constraints['pattern'], value):
                return False
        except re.error:
            pass
    
    if 'enum' in constraints:
        if value not in constraints['enum']:
            return False
    
    return True


def validate_number(value: Any, constraints: Dict[str, Any]) -> bool:
    if not isinstance(value, (int, float)):
        return False
    
    if 'minimum' in constraints:
        if value < constraints['minimum']:
            return False
    
    if 'maximum' in constraints:
        if value > constraints['maximum']:
            return False
    
    if 'multipleOf' in constraints:
        if value % constraints['multipleOf'] != 0:
            return False
    
    return True


def validate_array(value: list, constraints: Dict[str, Any]) -> bool:
    if not isinstance(value, list):
        return False
    
    if 'minItems' in constraints:
        if len(value) < constraints['minItems']:
            return False
    
    if 'maxItems' in constraints:
        if len(value) > constraints['maxItems']:
            return False
    
    if constraints.get('uniqueItems'):
        try:
            if len(value) != len(set(json.dumps(item) for item in value)):
                return False
        except:
            pass
    
    return True


def validate_object(value: dict, schema: Dict[str, Any]) -> bool:
    if not isinstance(value, dict):
        return False
    
    properties = schema.get('properties', {})
    required = schema.get('required', [])
    
    for prop in required:
        if prop not in value:
            return False
    
    for prop, prop_schema in properties.items():
        if prop in value:
            if not validate_value(value[prop], prop_schema):
                return False
    
    if not schema.get('additionalProperties', True):
        for prop in value:
            if prop not in properties:
                return False
    
    return True


def validate_value(value: Any, schema: Dict[str, Any]) -> bool:
    if not isinstance(schema, dict):
        return True
    
    if 'type' in schema:
        schema_type = schema['type']
        
        if isinstance(schema_type, list):
            if not any(validate_type(value, t) for t in schema_type):
                return False
        else:
            if not validate_type(value, schema_type):
                return False
    
    if isinstance(value, str):
        if not validate_string(value, schema):
            return False
    elif isinstance(value, (int, float)):
        if not validate_number(value, schema):
            return False
    elif isinstance(value, list):
        if not validate_array(value, schema):
            return False
        if 'items' in schema:
            for item in value:
                if not validate_value(item, schema['items']):
                    return False
    elif isinstance(value, dict):
        if not validate_object(value, schema):
            return False
    
    if 'oneOf' in schema:
        matches = sum(validate_value(value, s) for s in schema['oneOf'])
        if matches != 1:
            return False
    
    if 'anyOf' in schema:
        if not any(validate_value(value, s) for s in schema['anyOf']):
            return False
    
    if 'allOf' in schema:
        if not all(validate_value(value, s) for s in schema['allOf']):
            return False
    
    if 'not' in schema:
        if validate_value(value, schema['not']):
            return False
    
    return True


def parse_and_validate(data: bytes) -> Dict[str, Any]:
    result = {'valid': False, 'errors': []}
    
    try:
        text = data.decode('utf-8', errors='replace')
        parsed = json.loads(text)
        
        if isinstance(parsed, dict) and '_schema' in parsed:
            schema = parsed['_schema']
            value = parsed.get('value', {})
            
            try:
                result['valid'] = validate_value(value, schema)
            except RecursionError:
                result['errors'].append('Recursion limit exceeded')
            except Exception as e:
                result['errors'].append(str(e))
        else:
            result['valid'] = True
            
    except json.JSONDecodeError as e:
        result['errors'].append(f'JSON error: {e}')
    except Exception as e:
        result['errors'].append(str(e))
    
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    try:
        _ = parse_and_validate(data)
    except RecursionError:
        pass
    except MemoryError:
        pass


if __name__ == '__main__':
    try:
        import atheris
        atheris.Setup(sys.argv, lambda d: fuzz_target(d))
        atheris.Fuzz()
    except ImportError:
        print("atheris not installed")