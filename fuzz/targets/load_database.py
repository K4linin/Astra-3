"""
Target: load_database
Фаззинг-обертка для операций с базой данных
"""

import json
import re
import sys
from typing import Any, Dict, List, Optional


class DatabaseError(Exception):
    pass


def parse_sql_value(value: str) -> Any:
    """Парсинг SQL значения"""
    value = value.strip()
    
    if value.upper() == 'NULL':
        return None
    if value.upper() in ('TRUE', 'FALSE'):
        return value.upper() == 'TRUE'
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1].replace('""', '"')
    if '.' in value:
        try:
            return float(value)
        except ValueError:
            pass
    try:
        return int(value)
    except ValueError:
        pass
    return value


def parse_insert_statement(sql: str) -> Optional[Dict[str, Any]]:
    """Парсинг INSERT statement"""
    pattern = r"INSERT\s+INTO\s+(\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)"
    match = re.search(pattern, sql, re.IGNORECASE)
    
    if not match:
        return None
    
    table = match.group(1)
    columns = [c.strip() for c in match.group(2).split(',')]
    values = [parse_sql_value(v.strip()) for v in match.group(3).split(',')]
    
    return {
        'table': table,
        'columns': columns,
        'values': dict(zip(columns, values))
    }


def parse_select_statement(sql: str) -> Optional[Dict[str, Any]]:
    """Парсинг SELECT statement"""
    pattern = r"SELECT\s+(.+?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+))?"
    match = re.search(pattern, sql, re.IGNORECASE)
    
    if not match:
        return None
    
    columns = [c.strip() for c in match.group(1).split(',')]
    table = match.group(2)
    where = match.group(3) if match.group(3) else None
    
    return {
        'table': table,
        'columns': columns,
        'where': where
    }


def simulate_query(data: bytes) -> Dict[str, Any]:
    """Симуляция выполнения запроса"""
    result = {'success': False, 'type': None, 'data': None}
    
    try:
        sql = data.decode('utf-8', errors='replace').strip()
        
        if sql.upper().startswith('SELECT'):
            parsed = parse_select_statement(sql)
            result['type'] = 'SELECT'
        elif sql.upper().startswith('INSERT'):
            parsed = parse_insert_statement(sql)
            result['type'] = 'INSERT'
        else:
            return result
        
        if parsed:
            result['success'] = True
            result['data'] = parsed
            
    except Exception:
        pass
    
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    try:
        _ = simulate_query(data)
    except DatabaseError:
        pass
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