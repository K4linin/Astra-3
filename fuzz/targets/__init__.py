"""
Fuzzing Targets Package

Этот пакет содержит фаззинг-обертки для различных функций:
- parse_config: Парсинг конфигурационных файлов
- process_user_input: Обработка пользовательского ввода
- handle_network_packet: Обработка сетевых пакетов
- serialize_data: Сериализация данных
- load_database: Загрузка данных из БД
- compress_image: Сжатие изображений
- execute_command: Выполнение команд
- format_output: Форматирование вывода
- validate_schema: Валидация схем
- calculate_checksum: Вычисление контрольных сумм
"""

import sys
from typing import Callable, Dict, List

# Реестр доступных targets
TARGETS: Dict[str, Callable] = {}

def register_target(name: str):
    """Декоратор для регистрации фаззинг-таргета"""
    def decorator(func: Callable) -> Callable:
        TARGETS[name] = func
        return func
    return decorator

def get_target(name: str) -> Callable:
    """Получение таргета по имени"""
    if name not in TARGETS:
        raise ValueError(f"Unknown target: {name}. Available: {list(TARGETS.keys())}")
    return TARGETS[name]

def list_targets() -> List[str]:
    """Список доступных таргетов"""
    return list(TARGETS.keys())

# Импортируем все targets
from . import (
    parse_config,
    process_user_input,
    handle_network_packet,
    serialize_data,
    load_database,
    compress_image,
    execute_command,
    format_output,
    validate_schema,
    calculate_checksum
)