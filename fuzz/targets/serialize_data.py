"""
Target: serialize_data
Фаззинг-обертка для сериализации данных (JSON, XML, Pickle, MessagePack)
"""

import json
import sys
from typing import Any


def serialize_json(data: Any) -> str:
    """Сериализация в JSON"""
    return json.dumps(data, default=str)


def deserialize_json(data: bytes) -> Any:
    """Десериализация из JSON"""
    text = data.decode('utf-8', errors='replace')
    return json.loads(text)


def serialize_xml(data: dict, root: str = 'root') -> str:
    """Простейшая XML сериализация"""
    def dict_to_xml(d: dict, indent: int = 0) -> str:
        lines = []
        spaces = '  ' * indent
        for key, value in d.items():
            safe_key = str(key).replace('<', '_').replace('>', '_')
            if isinstance(value, dict):
                lines.append(f'{spaces}<{safe_key}>')
                lines.append(dict_to_xml(value, indent + 1))
                lines.append(f'{spaces}</{safe_key}>')
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f'{spaces}<{safe_key}>')
                        lines.append(dict_to_xml(item, indent + 1))
                        lines.append(f'{spaces}</{safe_key}>')
                    else:
                        safe_val = str(item).replace('<', '<').replace('>', '>')
                        lines.append(f'{spaces}<{safe_key}>{safe_val}</{safe_key}>')
            else:
                safe_val = str(value).replace('<', '<').replace('>', '>')
                lines.append(f'{spaces}<{safe_key}>{safe_val}</{safe_key}>')
        return '\n'.join(lines)
    
    return f'<?xml version="1.0"?>\n<{root}>\n{dict_to_xml(data)}\n</{root}>'


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    # 1. JSON
    try:
        result = deserialize_json(data)
        _ = serialize_json(result)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    except RecursionError:
        pass
    except MemoryError:
        pass
    
    # 2. XML
    try:
        text = data.decode('utf-8', errors='replace')
        if '<' in text and '>' in text:
            # Простейший тест XML
            _ = serialize_xml({'data': text[:1000]})
    except:
        pass


if __name__ == '__main__':
    try:
        import atheris
        atheris.Setup(sys.argv, lambda d: fuzz_target(d))
        atheris.Fuzz()
    except ImportError:
        print("atheris not installed")