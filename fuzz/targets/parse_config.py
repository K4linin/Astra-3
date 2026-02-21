"""
Target: parse_config
Фаззинг парсинга JSON, YAML, INI конфигураций
"""

import json
import sys
from typing import Any, Dict

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class ConfigParseError(Exception):
    pass


def parse_json_config(data: bytes) -> Dict[str, Any]:
    try:
        text = data.decode('utf-8')
        config = json.loads(text)
        
        if not isinstance(config, dict):
            raise ConfigParseError("Config must be a dictionary")
            
        return config
    except UnicodeDecodeError as e:
        raise ConfigParseError(f"Invalid UTF-8: {e}")
    except json.JSONDecodeError as e:
        raise ConfigParseError(f"Invalid JSON: {e}")


def parse_yaml_config(data: bytes) -> Dict[str, Any]:
    if not HAS_YAML:
        return {}
        
    try:
        text = data.decode('utf-8')
        config = yaml.safe_load(text)
        
        if config is None:
            return {}
        if not isinstance(config, dict):
            raise ConfigParseError("Config must be a dictionary")
            
        return config
    except UnicodeDecodeError as e:
        raise ConfigParseError(f"Invalid UTF-8: {e}")
    except yaml.YAMLError as e:
        raise ConfigParseError(f"Invalid YAML: {e}")


def parse_ini_config(data: bytes) -> Dict[str, Any]:
    try:
        text = data.decode('utf-8')
        config = {}
        current_section = 'default'
        
        for line in text.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#') or line.startswith(';'):
                continue
                
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                if current_section not in config:
                    config[current_section] = {}
                continue
                
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if current_section not in config:
                    config[current_section] = {}
                    
                config[current_section][key] = value
                
        return config
    except Exception as e:
        raise ConfigParseError(f"Invalid INI: {e}")


def validate_config(config: Dict[str, Any]) -> bool:
    if not isinstance(config, dict):
        return False
        
    dangerous_keys = ['__class__', '__import__', 'eval', 'exec']
    for key in dangerous_keys:
        if key in str(config):
            return False
            
    return True


def process_config(config: Dict[str, Any]) -> Dict[str, Any]:
    if not validate_config(config):
        raise ConfigParseError("Invalid config: failed validation")
    
    result = {}
    
    for key, value in config.items():
        if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
            var_name = value[2:-1]
            result[key] = f"<ENV:{var_name}>"
        elif isinstance(value, dict):
            result[key] = process_config(value)
        elif isinstance(value, list):
            result[key] = [
                process_config(v) if isinstance(v, dict) else v
                for v in value
            ]
        else:
            result[key] = value
            
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
        
    try:
        config = parse_json_config(data)
        if config:
            _ = process_config(config)
    except ConfigParseError:
        pass
    except RecursionError:
        pass
    except MemoryError:
        pass
    
    if HAS_YAML:
        try:
            config = parse_yaml_config(data)
            if config:
                _ = process_config(config)
        except ConfigParseError:
            pass
        except RecursionError:
            pass
        except MemoryError:
            pass
    
    try:
        config = parse_ini_config(data)
        if config:
            _ = process_config(config)
    except ConfigParseError:
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
            b'{"key": "value"}',
            b'{"nested": {"deep": {"value": 123}}}',
            b'[section]\nkey=value',
            b'invalid{{{json',
            b'\x00\x01\x02\x03',
            b'A' * 100000,
        ]
        
        for test in test_cases:
            try:
                fuzz_target(test)
                print(f"OK: {test[:50]}...")
            except Exception as e:
                print(f"FAIL: {test[:50]}... -> {e}")