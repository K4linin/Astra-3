"""
Target: format_output
Фаззинг-обертка для форматирования вывода
"""

import re
import sys
from typing import Any, Dict, List, Optional


def format_string(template: str, values: Dict[str, Any]) -> str:
    """Форматирование строки с плейсхолдерами"""
    result = template
    
    for key, value in values.items():
        placeholder = '{' + str(key) + '}'
        result = result.replace(placeholder, str(value)[:1000])
    
    return result


def format_table(data: List[List[Any]], headers: List[str] = None) -> str:
    """Форматирование данных в таблицу"""
    if not data:
        return ''
    
    # Ограничиваем размер
    data = [row[:20] for row in data[:100]]
    
    if headers:
        data = [headers] + data
    
    # Вычисляем ширину колонок
    col_widths = []
    for col_idx in range(len(data[0])):
        max_width = max(len(str(row[col_idx])[:50]) for row in data)
        col_widths.append(min(max_width, 50))
    
    # Формируем строки
    lines = []
    for row in data:
        cells = [
            str(val)[:col_widths[i]].ljust(col_widths[i])
            for i, val in enumerate(row)
        ]
        lines.append(' | '.join(cells))
    
    return '\n'.join(lines)


def format_xml(data: Dict[str, Any], root: str = 'root') -> str:
    """Форматирование в XML"""
    def to_xml(obj: Any, name: str, indent: int = 0) -> str:
        spaces = '  ' * indent
        safe_name = re.sub(r'[^\w]', '_', str(name))[:50]
        
        if obj is None:
            return f'{spaces}<{safe_name}/>'
        elif isinstance(obj, dict):
            children = '\n'.join(
                to_xml(v, k, indent + 1) for k, v in obj.items()
            )
            return f'{spaces}<{safe_name}>\n{children}\n{spaces}</{safe_name}>'
        elif isinstance(obj, list):
            children = '\n'.join(
                to_xml(item, 'item', indent + 1) for item in obj
            )
            return f'{spaces}<{safe_name}>\n{children}\n{spaces}</{safe_name}>'
        else:
            safe_val = str(obj)[:1000].replace('<', '<').replace('>', '>')
            return f'{spaces}<{safe_name}>{safe_val}</{safe_name}>'
    
    return f'<?xml version="1.0"?>\n{to_xml(data, root)}'


def format_csv(data: List[List[Any]], delimiter: str = ',') -> str:
    """Форматирование в CSV"""
    def escape_cell(value: Any) -> str:
        s = str(value)[:1000]
        if delimiter in s or '"' in s or '\n' in s:
            return '"' + s.replace('"', '""') + '"'
        return s
    
    lines = []
    for row in data[:1000]:
        cells = [escape_cell(cell) for cell in row[:100]]
        lines.append(delimiter.join(cells))
    
    return '\n'.join(lines)


def parse_format_string(data: bytes) -> Dict[str, Any]:
    """Парсинг и форматирование данных"""
    result = {'type': None, 'output': ''}
    
    try:
        text = data.decode('utf-8', errors='replace')
        
        # Пробуем JSON
        if text.strip().startswith('{') or text.strip().startswith('['):
            import json
            parsed = json.loads(text)
            
            if isinstance(parsed, dict):
                result['type'] = 'dict'
                result['output'] = format_xml(parsed)
            elif isinstance(parsed, list):
                if all(isinstance(row, list) for row in parsed):
                    result['type'] = 'table'
                    result['output'] = format_table(parsed)
                else:
                    result['type'] = 'list'
                    result['output'] = format_csv([[item] for item in parsed])
        
        # Пробуем как шаблон
        elif '{' in text and '}' in text:
            result['type'] = 'template'
            result['output'] = format_string(text, {'value': 'test', 'name': 'sample'})
        
    except Exception:
        pass
    
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    try:
        _ = parse_format_string(data)
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