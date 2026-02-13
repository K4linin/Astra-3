"""
Target: execute_command
Фаззинг-обертка для выполнения команд (безопасная симуляция)
"""

import re
import sys
from typing import Any, Dict, List, Optional


class CommandError(Exception):
    pass


# Разрешенные команды (белый список)
ALLOWED_COMMANDS = {
    'echo', 'ls', 'cat', 'pwd', 'date', 'whoami', 'id', 'uname',
    'head', 'tail', 'wc', 'sort', 'uniq', 'grep', 'find', 'xargs'
}

# Опасные паттерны
DANGEROUS_PATTERNS = [
    r'rm\s+-rf',
    r'sudo\s+',
    r'chmod\s+777',
    r'>(>|>>)',  # Redirection
    r'\|\s*\|',   # Double pipe
    r';\s*rm',
    r'\$\([^)]+\)',  # Command substitution
    r'`[^`]+`',      # Backtick substitution
    r'\$\{[^}]+\}',  # Variable expansion
    r'eval\s+',
    r'exec\s+',
]


def tokenize_command(cmd: str) -> List[str]:
    """Токенизация командной строки"""
    tokens = []
    current = ''
    in_quote = None
    escape = False
    
    for char in cmd[:10000]:  # Limit length
        if escape:
            current += char
            escape = False
        elif char == '\\':
            escape = True
        elif in_quote:
            if char == in_quote:
                in_quote = None
            else:
                current += char
        elif char in ('"', "'"):
            in_quote = char
        elif char in (' ', '\t', '\n'):
            if current:
                tokens.append(current)
                current = ''
        else:
            current += char
    
    if current:
        tokens.append(current)
    
    return tokens


def is_safe_command(cmd: str) -> bool:
    """Проверка безопасности команды"""
    cmd_lower = cmd.lower()
    
    # Проверка опасных паттернов
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd_lower):
            return False
    
    return True


def parse_command(cmd: str) -> Optional[Dict[str, Any]]:
    """Парсинг команды"""
    tokens = tokenize_command(cmd)
    
    if not tokens:
        return None
    
    command = tokens[0]
    args = tokens[1:]
    
    return {
        'command': command,
        'args': args,
        'allowed': command in ALLOWED_COMMANDS,
        'safe': is_safe_command(cmd)
    }


def simulate_command(data: bytes) -> Dict[str, Any]:
    """Безопасная симуляция выполнения команды"""
    result = {
        'success': False,
        'output': '',
        'error': '',
        'parsed': None
    }
    
    try:
        cmd = data.decode('utf-8', errors='replace')
        parsed = parse_command(cmd)
        
        if not parsed:
            return result
        
        result['parsed'] = parsed
        
        if not parsed['safe']:
            result['error'] = 'Command contains dangerous patterns'
            return result
        
        if not parsed['allowed']:
            result['error'] = f"Command '{parsed['command']}' is not allowed"
            return result
        
        # Симуляция выполнения
        result['success'] = True
        result['output'] = f"[SIMULATED] {parsed['command']} executed"
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    try:
        _ = simulate_command(data)
    except CommandError:
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