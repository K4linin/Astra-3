"""
Target: cve_deserialization
CVE: CVE-2022-48549, CVE-2020-29651, CVE-2013-1753
"""

import sys
import pickle
import marshal
import struct
from io import BytesIO


def _test_pickle_safely(data: bytes) -> dict:
    result = {
        'parse_success': False,
        'issues': []
    }
    
    if len(data) == 0:
        return result
    
    if len(data) > 50000:
        data = data[:50000]
    
    try:
        if len(data) >= 2:
            protocol_marker = data[0]
            result['pickle_protocol'] = protocol_marker
            
            if b'R' in data or b'c' in data:
                result['issues'].append('DANGEROUS_OPCODE_DETECTED')
        
        try:
            import RestrictedUnpickler
            
            class SafeUnpickler(RestrictedUnpickler):
                def find_class(self, module, name):
                    blocked = {'os', 'subprocess', 'sys', 'builtins', 'eval', 'exec'}
                    if module in blocked or name in blocked:
                        raise pickle.UnpicklingError(f"Blocked: {module}.{name}")
                    return super().find_class(module, name)
            
            obj = SafeUnpickler.loads(data)
            result['parse_success'] = True
            result['object_type'] = type(obj).__name__
            
        except ImportError:
            result['issues'].append('RESTRICTED_UNPICKLER_UNAVAILABLE')
            
    except pickle.UnpicklingError as e:
        result['issues'].append(f'UNPICKLING_ERROR:{str(e)[:50]}')
    except pickle.PickleError as e:
        result['issues'].append(f'PICKLE_ERROR:{str(e)[:50]}')
    except ValueError:
        result['issues'].append('VALUE_ERROR')
    except EOFError:
        result['issues'].append('EOF_ERROR')
    except struct.error:
        result['issues'].append('STRUCT_ERROR')
    except RecursionError:
        result['issues'].append('RECURSION_ERROR')
        raise
    except MemoryError:
        result['issues'].append('MEMORY_ERROR')
        raise
    
    return result


def _test_marshal_safely(data: bytes) -> dict:
    result = {
        'parse_success': False,
        'issues': []
    }
    
    if len(data) == 0:
        return result
    
    if len(data) > 100000:
        data = data[:100000]
    
    try:
        if len(data) >= 4:
            version_marker = data[0]
            result['marshal_version'] = version_marker
        
        obj = marshal.loads(data)
        result['parse_success'] = True
        result['object_type'] = type(obj).__name__
        
    except ValueError:
        result['issues'].append('VALUE_ERROR')
    except EOFError:
        result['issues'].append('EOF_ERROR')
    except TypeError:
        result['issues'].append('TYPE_ERROR')
    except RecursionError:
        result['issues'].append('RECURSION_ERROR')
        raise
    except MemoryError:
        result['issues'].append('MEMORY_ERROR')
        raise
    
    return result


def _test_xml_parsing(data: bytes) -> dict:
    result = {
        'parse_success': False,
        'issues': []
    }
    
    if len(data) == 0:
        return result
    
    try:
        text = data.decode('utf-8', errors='replace')
        
        if len(text) > 50000:
            text = text[:50000]
        
        entity_patterns = [
            '<!ENTITY',
            '<!DOCTYPE',
            'SYSTEM',
            'PUBLIC',
        ]
        
        for pattern in entity_patterns:
            if pattern.lower() in text.lower():
                result['issues'].append(f'DTD_ENTITY_DETECTED:{pattern}')
        
        entity_count = text.count('&')
        if entity_count > 100:
            result['issues'].append(f'HIGH_ENTITY_COUNT:{entity_count}')
        
        import xml.etree.ElementTree as ET
        
        try:
            try:
                from defusedxml.ElementTree import fromstring as safe_fromstring
                root = safe_fromstring(text)
                result['parse_success'] = True
                result['root_tag'] = root.tag
            except ImportError:
                root = ET.fromstring(text)
                result['parse_success'] = True
                result['root_tag'] = root.tag if hasattr(root, 'tag') else str(type(root))
        except ET.ParseError as e:
            result['issues'].append(f'XML_PARSE_ERROR:{str(e)[:50]}')
                
    except UnicodeDecodeError:
        result['issues'].append('DECODE_ERROR')
    except ValueError:
        result['issues'].append('VALUE_ERROR')
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
        if len(data) >= 2:
            if data[0] in [0x80, ord('('), ord('.'), ord('S'), ord('I'), ord('L')]:
                _test_pickle_safely(data)
            elif data[0] in [0, 1, 2, 3, 4] and len(data) > 4:
                _test_marshal_safely(data)
            elif data[0:1] == b'<' or data[0:5] == b'<?xml':
                _test_xml_parsing(data)
            else:
                _test_pickle_safely(data)
                _test_marshal_safely(data)
                _test_xml_parsing(data)
                
    except ValueError:
        pass
    except UnicodeDecodeError:
        pass
    except EOFError:
        pass
    except struct.error:
        pass
    except TypeError:
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
        b'(' + b'a' * 10000,
        b'\x00\x00\x00\x00' + b'x' * 1000,
        b'\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x05hello\x94.',
        b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><lolz>&lol2;</lolz>',
        b'c__builtin__\neval\n(S\'print(1)\'\ntR.',
        b'\x80\x04\x95\xff\xff\xff\xff',
    ]
    
    print("Testing deserialization CVE cases...")
    for test in test_cases:
        try:
            fuzz_target(test)
            print(f"[OK] Test passed: {test[:30]}...")
        except RecursionError:
            print(f"[!!!] RecursionError with: {test[:30]}...")
        except MemoryError:
            print(f"[!!!] MemoryError with: {test[:30]}...")