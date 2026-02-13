"""
Target: parse_config
Фаззинг-обертка для парсинга конфигурационных файлов

Тестирует:
- Парсинг JSON, YAML, INI конфигураций
- Обработка некорректных данных
- Граничные случаи
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
    """Ошибка парсинга конфигурации"""
    pass


def parse_json_config(data: bytes) -> Dict[str, Any]:
    """
    Парсинг JSON конфигурации
    
    Args:
        data: Сырые байты конфигурации
        
    Returns:
        Распарсенный словарь конфигурации
        
    Raises:
        ConfigParseError: При ошибке парсинга
    """
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
    """
    Парсинг YAML конфигурации
    
    Args:
        data: Сырые байты конфигурации
        
    Returns:
        Распарсенный словарь конфигурации
    """
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
    """
    Парсинг INI конфигурации
    
    Args:
        data: Сырые байты конфигурации
        
    Returns:
        Распарсенный словарь конфигурации
    """
    try:
        text = data.decode('utf-8')
        config = {}
        current_section = 'default'
        
        for line in text.split('\n'):
            line = line.strip()
            
            # Пропускаем комментарии и пустые строки
            if not line or line.startswith('#') or line.startswith(';'):
                continue
                
            # Секция
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                if current_section not in config:
                    config[current_section] = {}
                continue
                
            # Ключ=значение
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
    """
    Валидация конфигурации
    
    Проверяет обязательные поля и типы данных
    """
    if not isinstance(config, dict):
        return False
        
    # Проверяем на опасные значения
    dangerous_keys = ['__class__', '__import__', 'eval', 'exec']
    for key in dangerous_keys:
        if key in str(config):
            return False
            
    return True


def process_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Обработка конфигурации
    
    Выполняет подстановку переменных и валидацию
    """
    if not validate_config(config):
        raise ConfigParseError("Invalid config: failed validation")
    
    result = {}
    
    for key, value in config.items():
        # Подстановка переменных окружения
        if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
            var_name = value[2:-1]
            # Безопасная подстановка - возвращаем placeholder
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
    """
    Главная фаззинг-функция для парсинга конфигурации
    
    Эта функция вызывается фаззером с произвольными данными.
    Должна обрабатывать все исключения и падать только на реальных багах.
    """
    if len(data) == 0:
        return
        
    # Пробуем разные форматы парсинга
    
    # 1. JSON
    try:
        config = parse_json_config(data)
        if config:
            _ = process_config(config)
    except ConfigParseError:
        pass  # Ожидаемая ошибка парсинга
    except RecursionError:
        pass  # Защита от бесконечной рекурсии
    except MemoryError:
        pass  # Защита от OOM
    
    # 2. YAML
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
    
    # 3. INI
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


# Для прямого запуска с atheris
if __name__ == '__main__':
    try:
        import atheris
        
        @atheris.instrument_func
        def test_one_input(data: bytes):
            fuzz_target(data)
            
        atheris.Setup(sys.argv, test_one_input)
        atheris.Fuzz()
    except ImportError:
        print("atheris not installed. Install with: pip install atheris")
        # Тестовый запуск с примерами
        test_cases = [
            b'{"key": "value"}',
            b'{"nested": {"deep": {"value": 123}}}',
            b'[section]\nkey=value',
            b'invalid{{{json',
            b'\x00\x01\x02\x03',  # Binary data
            b'A' * 100000,  # Large input
        ]
        
        for test in test_cases:
            try:
                fuzz_target(test)
                print(f"✓ {test[:50]}...")
            except Exception as e:
                print(f"✗ {test[:50]}... -> {e}")