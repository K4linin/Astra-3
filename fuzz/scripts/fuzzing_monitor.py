#!/usr/bin/env python3
"""
Fuzzing Monitor - Главный скрипт мониторинга фаззинг-тестирования

Этот скрипт управляет запуском фаззинга с поддержкой:
- Graceful shutdown по таймауту или отсутствию крашей
- Мониторинг ресурсов (CPU, память)
- Кроссплатформенность (Windows/Linux/macOS)
- Интеграция с Hypothesis (Windows) и Atheris (Linux/macOS)
"""

import argparse
import gc
import hashlib
import importlib.util
import json
import os
import platform
import random
import shutil
import signal
import string
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Кроссплатформенный импорт psutil
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available, resource monitoring disabled")

# Кроссплатформенный импорт colorama
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Заглушки для colorama
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""

# Проверка доступности фаззинг-фреймворков
HYPOTHESIS_AVAILABLE = False
ATHERIS_AVAILABLE = False

try:
    import hypothesis
    from hypothesis import given, settings, strategies as st
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    pass

try:
    import atheris
    ATHERIS_AVAILABLE = True
except ImportError:
    pass


class FuzzingConfig:
    """Конфигурация фаззинг-тестирования"""
    
    def __init__(
        self,
        target: str,
        duration_minutes: int = 60,
        crash_timeout_hours: int = 2,
        corpus_dir: str = "fuzz/corpus",
        crashes_dir: str = "fuzz/crashes",
        logs_dir: str = "fuzz/logs",
        verbosity: str = "normal",
        max_corpus_size: int = 10000,
        max_input_size: int = 100000
    ):
        self.target = target
        self.duration_minutes = duration_minutes
        self.crash_timeout_hours = crash_timeout_hours
        self.corpus_dir = Path(corpus_dir) / target
        self.crashes_dir = Path(crashes_dir) / target
        self.logs_dir = Path(logs_dir) / target
        self.verbosity = verbosity
        self.max_corpus_size = max_corpus_size
        self.max_input_size = max_input_size
        
        # Таймауты в секундах
        self.duration_seconds = duration_minutes * 60
        self.crash_timeout_seconds = crash_timeout_hours * 3600
        
        # Создаём директории
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)


class CrashInfo:
    """Информация о краше"""
    
    def __init__(
        self,
        crash_type: str,
        input_data: bytes,
        stack_trace: str,
        timestamp: datetime = None,
        target: str = ""
    ):
        self.crash_type = crash_type
        self.input_data = input_data
        self.stack_trace = stack_trace
        self.timestamp = timestamp or datetime.utcnow()
        self.target = target
        
        # Генерируем уникальный ID краша
        self.crash_id = hashlib.sha256(input_data).hexdigest()[:16]
        
        # Классификация severity
        self.severity = self._classify_severity()
        self.is_false_positive = self._check_false_positive()
    
    def _classify_severity(self) -> str:
        """Классификация severity краша"""
        critical_patterns = ['SEGFAULT', 'Buffer Overflow', 'Use-After-Free', 'Heap Corruption']
        high_patterns = ['NULL Pointer', 'Assertion', 'Integer Overflow', 'Stack Overflow']
        medium_patterns = ['Parse Error', 'Division by Zero', 'IndexError', 'KeyError']
        
        crash_upper = self.crash_type.upper()
        stack_upper = self.stack_trace.upper()
        
        for pattern in critical_patterns:
            if pattern.upper() in crash_upper or pattern.upper() in stack_upper:
                return 'critical'
        
        for pattern in high_patterns:
            if pattern.upper() in crash_upper or pattern.upper() in stack_upper:
                return 'high'
        
        for pattern in medium_patterns:
            if pattern.upper() in crash_upper or pattern.upper() in stack_upper:
                return 'medium'
        
        return 'low'
    
    def _check_false_positive(self) -> bool:
        """Проверка на ложное срабатывание"""
        fp_patterns = [
            'MemoryError',           # OOM
            'TimeoutError',          # Timeout
            'KeyboardInterrupt',     # User interrupt
            'PermissionError',       # Permission denied
            'ConnectionError',       # Network error
            'OSError'                # System error
        ]
        
        for pattern in fp_patterns:
            if pattern in self.crash_type or pattern in self.stack_trace:
                return True
        
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь"""
        return {
            'crash_id': self.crash_id,
            'crash_type': self.crash_type,
            'severity': self.severity,
            'is_false_positive': self.is_false_positive,
            'target': self.target,
            'timestamp': self.timestamp.isoformat(),
            'input_size': len(self.input_data),
            'input_hex': self.input_data[:100].hex(),
            'stack_trace': self.stack_trace[:2000]
        }


class FuzzingStats:
    """Статистика фаззинг-тестирования"""
    
    def __init__(self):
        self.start_time: datetime = datetime.utcnow()
        self.end_time: Optional[datetime] = None
        self.total_executions: int = 0
        self.total_crashes: int = 0
        self.unique_crashes: int = 0
        self.false_positives: int = 0
        self.corpus_size: int = 0
        self.last_crash_time: Optional[datetime] = None
        self.executions_per_second: float = 0.0
        self.peak_memory_mb: float = 0.0
        self.peak_cpu_percent: float = 0.0
        self.crashes: List[CrashInfo] = []
    
    def update_execution_rate(self):
        """Обновление скорости выполнения"""
        elapsed = (datetime.utcnow() - self.start_time).total_seconds()
        if elapsed > 0:
            self.executions_per_second = self.total_executions / elapsed
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь"""
        return {
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': (self.end_time or datetime.utcnow() - self.start_time).total_seconds(),
            'total_executions': self.total_executions,
            'total_crashes': self.total_crashes,
            'unique_crashes': self.unique_crashes,
            'false_positives': self.false_positives,
            'corpus_size': self.corpus_size,
            'executions_per_second': round(self.executions_per_second, 2),
            'peak_memory_mb': round(self.peak_memory_mb, 2),
            'peak_cpu_percent': round(self.peak_cpu_percent, 2),
            'crashes': [c.to_dict() for c in self.crashes]
        }


class FuzzingMonitor:
    """Главный класс мониторинга фаззинга"""
    
    def __init__(self, config: FuzzingConfig):
        self.config = config
        self.stats = FuzzingStats()
        self.running = True
        self.stop_reason = ""
        self.target_module = None
        self.fuzz_function: Optional[Callable] = None
        
        # Для отслеживания уникальных крашей
        self._crash_ids: set = set()
        
        # Lock для потокобезопасности
        self._lock = threading.Lock()
        
        # Регистрируем обработчики сигналов
        self._register_signal_handlers()
    
    def _register_signal_handlers(self):
        """Регистрация обработчиков сигналов для graceful shutdown"""
        def signal_handler(signum, frame):
            self.running = False
            self.stop_reason = f"Received signal {signum}"
            print(f"\n{Fore.YELLOW}[!] Graceful shutdown initiated...{Style.RESET_ALL}")
        
        # SIGINT (Ctrl+C)
        signal.signal(signal.SIGINT, signal_handler)
        
        # SIGTERM (kill command)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)
    
    def _load_target(self) -> bool:
        """Загрузка target модуля"""
        target_path = Path(f"fuzz/targets/{self.config.target}.py")
        
        if not target_path.exists():
            print(f"{Fore.RED}[ERROR] Target file not found: {target_path}{Style.RESET_ALL}")
            return False
        
        try:
            spec = importlib.util.spec_from_file_location(
                f"fuzz.targets.{self.config.target}",
                target_path
            )
            self.target_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.target_module)
            
            if hasattr(self.target_module, 'fuzz_target'):
                self.fuzz_function = self.target_module.fuzz_target
                return True
            else:
                print(f"{Fore.RED}[ERROR] Target module has no 'fuzz_target' function{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to load target: {e}{Style.RESET_ALL}")
            return False
    
    def _load_corpus(self) -> List[bytes]:
        """Загрузка corpus данных"""
        corpus = []
        
        if self.config.corpus_dir.exists():
            for file_path in self.config.corpus_dir.iterdir():
                if file_path.is_file() and file_path.stat().st_size <= self.config.max_input_size:
                    try:
                        with open(file_path, 'rb') as f:
                            corpus.append(f.read())
                    except:
                        pass
        
        self.stats.corpus_size = len(corpus)
        return corpus
    
    def _save_corpus_entry(self, data: bytes):
        """Сохранение новой corpus записи"""
        if len(data) == 0:
            return
        
        # Генерируем уникальное имя файла
        file_hash = hashlib.sha256(data).hexdigest()[:16]
        file_path = self.config.corpus_dir / f"corpus_{file_hash}"
        
        if not file_path.exists():
            try:
                with open(file_path, 'wb') as f:
                    f.write(data)
                self.stats.corpus_size += 1
            except:
                pass
    
    def _save_crash(self, crash: CrashInfo):
        """Сохранение информации о краше"""
        # Сохраняем input файл
        crash_file = self.config.crashes_dir / f"crash_{crash.crash_id}.crash"
        input_file = self.config.crashes_dir / f"crash_{crash.crash_id}.input"
        
        try:
            # Сохраняем метаданные краша
            with open(crash_file, 'w') as f:
                json.dump(crash.to_dict(), f, indent=2)
            
            # Сохраняем input данные
            with open(input_file, 'wb') as f:
                f.write(crash.input_data)
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to save crash: {e}{Style.RESET_ALL}")
    
    def _generate_random_input(self, size: int = None) -> bytes:
        """Генерация случайного input"""
        if size is None:
            size = random.randint(1, min(4096, self.config.max_input_size))
        
        # Различные стратегии генерации
        strategy = random.choice(['random', 'structured', 'edge_cases'])
        
        if strategy == 'random':
            return bytes([random.randint(0, 255) for _ in range(size)])
        
        elif strategy == 'structured':
            # Структурированные данные (JSON-like, XML-like, etc.)
            chars = string.printable.encode()
            return bytes([random.choice(chars) for _ in range(size)])
        
        else:
            # Edge cases
            edge_cases = [
                b'\x00' * size,                    # Null bytes
                b'\xff' * size,                    # Max bytes
                b'A' * size,                       # Repeated char
                bytes(range(256)) * (size // 256 + 1),  # All byte values
                b'{"key": "value"}' * (size // 16 + 1), # JSON-like
                b'<tag>content</tag>' * (size // 18 + 1), # XML-like
            ]
            return random.choice(edge_cases)[:size]
    
    def _mutate_input(self, data: bytes) -> bytes:
        """Мутация input данных"""
        if not data:
            return self._generate_random_input()
        
        data = bytearray(data)
        
        # Применяем случайные мутации
        num_mutations = random.randint(1, min(10, len(data)))
        
        for _ in range(num_mutations):
            if not data:
                break
            
            mutation_type = random.choice(['flip', 'insert', 'delete', 'replace', 'duplicate'])
            
            if mutation_type == 'flip' and data:
                pos = random.randint(0, len(data) - 1)
                data[pos] ^= random.randint(1, 255)
            
            elif mutation_type == 'insert' and len(data) < self.config.max_input_size:
                pos = random.randint(0, len(data))
                data.insert(pos, random.randint(0, 255))
            
            elif mutation_type == 'delete' and len(data) > 1:
                pos = random.randint(0, len(data) - 1)
                data.pop(pos)
            
            elif mutation_type == 'replace' and data:
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.randint(0, 255)
            
            elif mutation_type == 'duplicate' and len(data) < self.config.max_input_size // 2:
                if data:
                    pos = random.randint(0, len(data) - 1)
                    chunk_size = min(random.randint(1, 10), len(data) - pos)
                    chunk = data[pos:pos + chunk_size]
                    insert_pos = random.randint(0, len(data))
                    for i, byte in enumerate(chunk):
                        if len(data) < self.config.max_input_size:
                            data.insert(insert_pos + i, byte)
        
        return bytes(data)
    
    def _run_single_test(self, data: bytes) -> Optional[CrashInfo]:
        """Запуск одного теста"""
        try:
            self.fuzz_function(data)
            return None
            
        except (KeyboardInterrupt, SystemExit):
            raise
        
        except RecursionError:
            # Игнорируем ошибки рекурсии (expected)
            return None
        
        except MemoryError:
            # Игнорируем ошибки памяти (expected)
            gc.collect()
            return None
        
        except Exception as e:
            # Найден краш!
            crash = CrashInfo(
                crash_type=type(e).__name__,
                input_data=data,
                stack_trace=traceback.format_exc(),
                target=self.config.target
            )
            return crash
    
    def _update_resource_stats(self):
        """Обновление статистики ресурсов"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            process = psutil.Process()
            
            # Memory usage
            memory_mb = process.memory_info().rss / 1024 / 1024
            if memory_mb > self.stats.peak_memory_mb:
                self.stats.peak_memory_mb = memory_mb
            
            # CPU usage
            cpu_percent = process.cpu_percent(interval=0.1)
            if cpu_percent > self.stats.peak_cpu_percent:
                self.stats.peak_cpu_percent = cpu_percent
                
        except:
            pass
    
    def _check_stop_conditions(self) -> bool:
        """Проверка условий остановки"""
        elapsed = (datetime.utcnow() - self.stats.start_time).total_seconds()
        
        # 1. Превышен общий таймаут
        if elapsed >= self.config.duration_seconds:
            self.stop_reason = f"Duration timeout ({self.config.duration_minutes} minutes)"
            return True
        
        # 2. Нет крашей в течение crash_timeout
        if self.stats.last_crash_time:
            time_since_crash = (datetime.utcnow() - self.stats.last_crash_time).total_seconds()
            if time_since_crash >= self.config.crash_timeout_seconds:
                self.stop_reason = f"No crashes for {self.config.crash_timeout_hours} hours"
                return True
        
        # 3. Corpus достиг максимального размера
        if self.stats.corpus_size >= self.config.max_corpus_size:
            self.stop_reason = f"Corpus max size reached ({self.config.max_corpus_size})"
            return True
        
        return False
    
    def _print_status(self):
        """Вывод статуса"""
        elapsed = (datetime.utcnow() - self.stats.start_time).total_seconds()
        elapsed_str = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
        
        self.stats.update_execution_rate()
        
        print(f"\r{Fore.CYAN}[{elapsed_str}]{Style.RESET_ALL} "
              f"Execs: {Fore.GREEN}{self.stats.total_executions:,}{Style.RESET_ALL} | "
              f"EPS: {Fore.YELLOW}{self.stats.executions_per_second:.0f}{Style.RESET_ALL} | "
              f"Corpus: {Fore.BLUE}{self.stats.corpus_size}{Style.RESET_ALL} | "
              f"Crashes: {Fore.RED}{self.stats.total_crashes}{Style.RESET_ALL} "
              f"({self.stats.unique_crashes} unique)", end='')
    
    def run(self) -> FuzzingStats:
        """Запуск фаззинг-тестирования"""
        print(f"\n{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Fuzzing Monitor v1.0{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}\n")
        
        # Вывод информации о системе
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"Python: {platform.python_version()}")
        print(f"Hypothesis available: {HYPOTHESIS_AVAILABLE}")
        print(f"Atheris available: {ATHERIS_AVAILABLE}")
        print()
        
        # Вывод конфигурации
        print(f"{Fore.CYAN}Configuration:{Style.RESET_ALL}")
        print(f"  Target: {Fore.YELLOW}{self.config.target}{Style.RESET_ALL}")
        print(f"  Duration: {self.config.duration_minutes} minutes")
        print(f"  Crash timeout: {self.config.crash_timeout_hours} hours")
        print(f"  Corpus dir: {self.config.corpus_dir}")
        print(f"  Crashes dir: {self.config.crashes_dir}")
        print(f"  Verbosity: {self.config.verbosity}")
        print()
        
        # Загрузка target
        print(f"{Fore.CYAN}Loading target...{Style.RESET_ALL}")
        if not self._load_target():
            return self.stats
        print(f"{Fore.GREEN}✓ Target loaded successfully{Style.RESET_ALL}\n")
        
        # Загрузка corpus
        corpus = self._load_corpus()
        print(f"{Fore.CYAN}Loaded {len(corpus)} corpus entries{Style.RESET_ALL}\n")
        
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Starting fuzzing...{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}\n")
        
        # Основной цикл фаззинга
        iteration = 0
        while self.running:
            # Проверка условий остановки
            if self._check_stop_conditions():
                break
            
            # Генерация или мутация input
            if corpus and random.random() < 0.7:
                # Мутация существующего corpus
                base = random.choice(corpus)
                data = self._mutate_input(base)
            else:
                # Генерация нового input
                data = self._generate_random_input()
            
            # Запуск теста
            crash = self._run_single_test(data)
            self.stats.total_executions += 1
            
            # Обработка краша
            if crash:
                self.stats.total_crashes += 1
                self.stats.last_crash_time = datetime.utcnow()
                
                # Проверка на уникальность
                if crash.crash_id not in self._crash_ids:
                    self._crash_ids.add(crash.crash_id)
                    self.stats.unique_crashes += 1
                    
                    # Добавляем в corpus (для воспроизведения)
                    self._save_corpus_entry(data)
                    
                    # Сохраняем краш
                    self._save_crash(crash)
                    self.stats.crashes.append(crash)
                    
                    # Вывод информации о краше
                    if crash.is_false_positive:
                        self.stats.false_positives += 1
                        print(f"\n{Fore.YELLOW}[FP] {crash.crash_type} (ID: {crash.crash_id}){Style.RESET_ALL}")
                    else:
                        severity_color = {
                            'critical': Fore.RED,
                            'high': Fore.RED,
                            'medium': Fore.YELLOW,
                            'low': Fore.GREEN
                        }.get(crash.severity, Fore.WHITE)
                        
                        print(f"\n{severity_color}[{crash.severity.upper()}] {crash.crash_type} "
                              f"(ID: {crash.crash_id}){Style.RESET_ALL}")
            
            # Периодическое обновление
            if iteration % 100 == 0:
                self._update_resource_stats()
                
                if self.config.verbosity != 'quiet':
                    self._print_status()
            
            # Добавляем в corpus интересные input
            if iteration % 1000 == 0 and len(data) > 0:
                self._save_corpus_entry(data)
            
            iteration += 1
        
        # Финализация статистики
        self.stats.end_time = datetime.utcnow()
        self.stats.update_execution_rate()
        
        # Вывод итогов
        print(f"\n\n{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Fuzzing Complete{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}\n")
        
        if self.stop_reason:
            print(f"Stop reason: {Fore.YELLOW}{self.stop_reason}{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}Statistics:{Style.RESET_ALL}")
        print(f"  Total executions: {Fore.GREEN}{self.stats.total_executions:,}{Style.RESET_ALL}")
        print(f"  Executions/sec: {Fore.GREEN}{self.stats.executions_per_second:.2f}{Style.RESET_ALL}")
        print(f"  Corpus size: {Fore.BLUE}{self.stats.corpus_size}{Style.RESET_ALL}")
        print(f"  Total crashes: {Fore.RED}{self.stats.total_crashes}{Style.RESET_ALL}")
        print(f"  Unique crashes: {Fore.RED}{self.stats.unique_crashes}{Style.RESET_ALL}")
        print(f"  False positives: {Fore.YELLOW}{self.stats.false_positives}{Style.RESET_ALL}")
        print(f"  Peak memory: {Fore.YELLOW}{self.stats.peak_memory_mb:.2f} MB{Style.RESET_ALL}")
        print(f"  Peak CPU: {Fore.YELLOW}{self.stats.peak_cpu_percent:.1f}%{Style.RESET_ALL}")
        
        # Сохранение статистики в файл
        stats_file = self.config.logs_dir / f"stats_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(stats_file, 'w') as f:
                json.dump(self.stats.to_dict(), f, indent=2)
            print(f"\n{Fore.GREEN}✓ Statistics saved to {stats_file}{Style.RESET_ALL}")
        except:
            pass
        
        return self.stats


def run_with_hypothesis(config: FuzzingConfig, monitor: FuzzingMonitor):
    """Запуск фаззинга с Hypothesis (кроссплатформенный)"""
    from hypothesis import given, settings, strategies as st
    from hypothesis.database import InMemoryExampleDatabase
    from hypothesis import Phase
    
    print(f"{Fore.CYAN}Using Hypothesis fuzzing engine{Style.RESET_ALL}\n")
    
    crashes_found = []
    start_time = time.time()
    
    @given(st.binary(min_size=0, max_size=config.max_input_size))
    @settings(
        max_examples=10_000_000,
        database=InMemoryExampleDatabase(),
        deadline=None,
        phases=[Phase.generate]
    )
    def hypothesis_test(data: bytes):
        # Проверка таймаута ПЕРЕД каждым тестом
        elapsed = time.time() - start_time
        if elapsed >= config.duration_seconds:
            raise StopIteration
        
        if not monitor.running:
            raise StopIteration
        
        monitor.stats.total_executions += 1
        
        crash = monitor._run_single_test(data)
        
        if crash:
            monitor.stats.total_crashes += 1
            monitor.stats.last_crash_time = datetime.utcnow()
            
            if crash.crash_id not in monitor._crash_ids:
                monitor._crash_ids.add(crash.crash_id)
                monitor.stats.unique_crashes += 1
                monitor._save_crash(crash)
                monitor.stats.crashes.append(crash)
                
                severity_color = {
                    'critical': Fore.RED,
                    'high': Fore.RED,
                    'medium': Fore.YELLOW,
                    'low': Fore.GREEN
                }.get(crash.severity, Fore.WHITE)
                
                print(f"\n{severity_color}[{crash.severity.upper()}] {crash.crash_type} "
                      f"(ID: {crash.crash_id}){Style.RESET_ALL}")
        
        # Проверка условий остановки
        if monitor._check_stop_conditions():
            raise StopIteration
        
        # Обновление статуса
        if monitor.stats.total_executions % 100 == 0:
            monitor._update_resource_stats()
            monitor._print_status()
    
    try:
        hypothesis_test()
    except StopIteration:
        pass
    
    # Финализация
    monitor.stats.end_time = datetime.utcnow()
    monitor.stats.update_execution_rate()
    
    elapsed = time.time() - start_time
    print(f"\n\n{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Fuzzing Complete{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}\n")
    
    print(f"{Fore.CYAN}Statistics:{Style.RESET_ALL}")
    print(f"  Duration: {Fore.GREEN}{int(elapsed // 60)}m {int(elapsed % 60)}s{Style.RESET_ALL}")
    print(f"  Total executions: {Fore.GREEN}{monitor.stats.total_executions:,}{Style.RESET_ALL}")
    print(f"  Executions/sec: {Fore.GREEN}{monitor.stats.executions_per_second:.2f}{Style.RESET_ALL}")
    print(f"  Total crashes: {Fore.RED}{monitor.stats.total_crashes}{Style.RESET_ALL}")
    print(f"  Unique crashes: {Fore.RED}{monitor.stats.unique_crashes}{Style.RESET_ALL}")
    
    return crashes_found


def main():
    parser = argparse.ArgumentParser(
        description='Fuzzing Monitor - Cross-platform fuzzing orchestrator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fuzzing_monitor.py --target parse_config --duration 30
  python fuzzing_monitor.py --target process_user_input --duration 60 --crash-timeout 4
  python fuzzing_monitor.py --target all --duration 120 --verbosity verbose
        """
    )
    
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target name (e.g., parse_config, process_user_input)'
    )
    
    parser.add_argument(
        '--duration', '-d',
        type=int,
        default=60,
        help='Duration in minutes (default: 60)'
    )
    
    parser.add_argument(
        '--crash-timeout',
        type=int,
        default=2,
        help='Stop if no crashes for N hours (default: 2)'
    )
    
    parser.add_argument(
        '--corpus-dir',
        default='fuzz/corpus',
        help='Corpus directory (default: fuzz/corpus)'
    )
    
    parser.add_argument(
        '--crashes-dir',
        default='fuzz/crashes',
        help='Crashes directory (default: fuzz/crashes)'
    )
    
    parser.add_argument(
        '--logs-dir',
        default='fuzz/logs',
        help='Logs directory (default: fuzz/logs)'
    )
    
    parser.add_argument(
        '--verbosity', '-v',
        choices=['quiet', 'normal', 'verbose', 'debug'],
        default='normal',
        help='Verbosity level (default: normal)'
    )
    
    parser.add_argument(
        '--engine',
        choices=['auto', 'atheris', 'hypothesis', 'builtin'],
        default='auto',
        help='Fuzzing engine (default: auto)'
    )
    
    parser.add_argument(
        '--artifact-prefix',
        default='',
        help='Prefix for artifact files (for CI integration)'
    )
    
    args = parser.parse_args()
    
    # Создаём конфигурацию
    config = FuzzingConfig(
        target=args.target,
        duration_minutes=args.duration,
        crash_timeout_hours=args.crash_timeout,
        corpus_dir=args.corpus_dir,
        crashes_dir=args.crashes_dir,
        logs_dir=args.logs_dir,
        verbosity=args.verbosity
    )
    
    # Создаём монитор
    monitor = FuzzingMonitor(config)
    
    # Выбираем движок
    engine = args.engine
    
    if engine == 'auto':
        if platform.system() == 'Linux' and ATHERIS_AVAILABLE:
            engine = 'atheris'
        elif HYPOTHESIS_AVAILABLE:
            engine = 'hypothesis'
        else:
            engine = 'builtin'
    
    print(f"{Fore.CYAN}Selected fuzzing engine: {engine}{Style.RESET_ALL}")
    
    # Запуск
    if engine == 'hypothesis' and HYPOTHESIS_AVAILABLE:
        # Загружаем target перед запуском Hypothesis
        if not monitor._load_target():
            print(f"{Fore.RED}[ERROR] Failed to load target{Style.RESET_ALL}")
            sys.exit(1)
        run_with_hypothesis(config, monitor)
    else:
        # Встроенный движок
        monitor.run()
    
    # Возвращаем код возврата
    if monitor.stats.unique_crashes > 0:
        sys.exit(1)  # Есть краши
    else:
        sys.exit(0)  # Успех


if __name__ == '__main__':
    main()