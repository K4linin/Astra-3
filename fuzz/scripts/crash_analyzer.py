#!/usr/bin/env python3
"""
 =============================================================================
 Crash Analyzer - Анализ и кластеризация крашей
 =============================================================================
 
 Описание:
   Этот скрипт реализует анализ и валидацию крашей:
   - Разделение на легитимные баги и ложные срабатывания
   - Кластеризация по схожести
   - Формирование crash summary
   - Минимизация входных данных
   
 Использование:
   python crash_analyzer.py --target <target> --crashes-dir <dir> [options]
   
 Параметры:
   --target         Цель фаззинга
   --crashes-dir    Директория с крашами
   --reports-dir    Директория для отчетов
   --corpus-dir     Директория с corpus
   --minimize       Минимизировать входные данные
   --cluster        Кластеризовать краши
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


class CrashSeverity(Enum):
    """Уровни серьезности крашей"""
    CRITICAL = "critical"    # Удаленное выполнение кода, обход безопасности
    HIGH = "high"           # Падение приложения, утечка памяти
    MEDIUM = "medium"       # Ошибки парсинга, некорректная обработка
    LOW = "low"             # Мелкие проблемы, cosmetic issues
    INFO = "info"           # Информационные события


class CrashType(Enum):
    """Типы крашей"""
    # Легитимные баги
    SEGFAULT = "segfault"
    ASSERTION_FAILURE = "assertion_failure"
    NULL_POINTER = "null_pointer"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    MEMORY_LEAK = "memory_leak"
    INTEGER_OVERFLOW = "integer_overflow"
    STACK_OVERFLOW = "stack_overflow"
    DIVISION_BY_ZERO = "division_by_zero"
    PARSE_ERROR = "parse_error"
    VALIDATION_ERROR = "validation_error"
    
    # Ложные срабатывания (инфраструктурные)
    OOM_KILLER = "oom_killer"
    TIMEOUT = "timeout"
    DISK_FULL = "disk_full"
    NETWORK_ERROR = "network_error"
    PERMISSION_DENIED = "permission_denied"
    RESOURCE_LIMIT = "resource_limit"
    UNKNOWN = "unknown"


@dataclass
class Crash:
    """Представление краша"""
    crash_id: str
    target: str
    input_file: Optional[Path] = None
    input_data: bytes = b''
    crash_type: CrashType = CrashType.UNKNOWN
    severity: CrashSeverity = CrashSeverity.MEDIUM
    stack_trace: str = ""
    error_message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    is_false_positive: bool = False
    is_legitimate_bug: bool = True
    cluster_id: Optional[str] = None
    similarity_hash: str = ""
    minimized_input: bytes = b''
    reproducer_command: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            'crash_id': self.crash_id,
            'target': self.target,
            'input_file': str(self.input_file) if self.input_file else None,
            'input_size': len(self.input_data),
            'crash_type': self.crash_type.value,
            'severity': self.severity.value,
            'stack_trace': self.stack_trace,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat(),
            'is_false_positive': self.is_false_positive,
            'is_legitimate_bug': self.is_legitimate_bug,
            'cluster_id': self.cluster_id,
            'similarity_hash': self.similarity_hash,
            'minimized_size': len(self.minimized_input),
            'reproducer_command': self.reproducer_command,
            'tags': self.tags,
            'metadata': self.metadata
        }


@dataclass
class CrashCluster:
    """Кластер схожих крашей"""
    cluster_id: str
    crashes: List[Crash] = field(default_factory=list)
    representative: Optional[Crash] = None
    common_stack_frames: List[str] = field(default_factory=list)
    similarity_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'cluster_id': self.cluster_id,
            'crash_count': len(self.crashes),
            'crash_ids': [c.crash_id for c in self.crashes],
            'representative_id': self.representative.crash_id if self.representative else None,
            'common_stack_frames': self.common_stack_frames,
            'similarity_score': self.similarity_score
        }


class CrashAnalyzer:
    """
    Анализатор крашей
    
    Функциональность:
    - Загрузка крашей из директории
    - Классификация по типам
    - Валидация (отделение ложных срабатываний)
    - Кластеризация по схожести
    - Минимизация входных данных
    - Генерация отчетов
    """
    
    # Паттерны для классификации крашей
    CRASH_PATTERNS = {
        # Легитимные баги
        CrashType.SEGFAULT: [
            r'SEGFAULT',
            r'Segmentation fault',
            r'signal 11',
            r'SIGSEGV',
            r'access violation',
            r'core dumped'
        ],
        CrashType.ASSERTION_FAILURE: [
            r'Assertion.*failed',
            r'assert\(.+\)',
            r'ASSERTION FAILED',
            r'Check failed:',
            r'FATAL.*assert'
        ],
        CrashType.NULL_POINTER: [
            r'null pointer',
            r'nullptr',
            r'NULL dereference',
            r'dereferencing null',
            r'0x0.*access'
        ],
        CrashType.BUFFER_OVERFLOW: [
            r'buffer overflow',
            r'stack smashing',
            r'heap overflow',
            r'out of bounds',
            r'array index.*out of range'
        ],
        CrashType.USE_AFTER_FREE: [
            r'use after free',
            r'double free',
            r'invalid free',
            r'freed.*used',
            r'heap-use-after-free'
        ],
        CrashType.INTEGER_OVERFLOW: [
            r'integer overflow',
            r'arithmetic overflow',
            r'numeric overflow',
            r'Value too large'
        ],
        CrashType.STACK_OVERFLOW: [
            r'stack overflow',
            r'RecursionError',
            r'maximum recursion depth',
            r'stack depth exceeded'
        ],
        CrashType.DIVISION_BY_ZERO: [
            r'division by zero',
            r'divide by zero',
            r'ZeroDivisionError',
            r'floating point exception'
        ],
        CrashType.PARSE_ERROR: [
            r'ParseError',
            r'SyntaxError',
            r'unexpected token',
            r'invalid.*format',
            r'malformed.*input',
            r'unable to parse'
        ],
        CrashType.VALIDATION_ERROR: [
            r'ValidationError',
            r'invalid.*schema',
            r'validation failed',
            r'invalid input',
            r'schema violation'
        ],
        
        # Ложные срабатывания
        CrashType.OOM_KILLER: [
            r'OOM killer',
            r'out of memory',
            r'Cannot allocate memory',
            r'memory allocation failed',
            r'killed by OS'
        ],
        CrashType.TIMEOUT: [
            r'Timeout',
            r'timed out',
            r'TimeoutError',
            r'execution time exceeded'
        ],
        CrashType.RESOURCE_LIMIT: [
            r'Resource temporarily unavailable',
            r'Too many open files',
            r'resource limit',
            r'ulimit'
        ],
        CrashType.NETWORK_ERROR: [
            r'NetworkError',
            r'Connection refused',
            r'Network is unreachable',
            r'Socket error'
        ],
        CrashType.PERMISSION_DENIED: [
            r'Permission denied',
            r'Access denied',
            r'Unauthorized',
            r'EACCES'
        ]
    }
    
    # Серьезность по типу краша
    SEVERITY_MAP = {
        CrashType.SEGFAULT: CrashSeverity.CRITICAL,
        CrashType.BUFFER_OVERFLOW: CrashSeverity.CRITICAL,
        CrashType.USE_AFTER_FREE: CrashSeverity.CRITICAL,
        CrashType.DOUBLE_FREE: CrashSeverity.HIGH,
        CrashType.NULL_POINTER: CrashSeverity.HIGH,
        CrashType.ASSERTION_FAILURE: CrashSeverity.HIGH,
        CrashType.INTEGER_OVERFLOW: CrashSeverity.HIGH,
        CrashType.STACK_OVERFLOW: CrashSeverity.MEDIUM,
        CrashType.DIVISION_BY_ZERO: CrashSeverity.MEDIUM,
        CrashType.PARSE_ERROR: CrashSeverity.MEDIUM,
        CrashType.VALIDATION_ERROR: CrashSeverity.LOW,
        # Ложные срабатывания
        CrashType.OOM_KILLER: CrashSeverity.INFO,
        CrashType.TIMEOUT: CrashSeverity.INFO,
        CrashType.RESOURCE_LIMIT: CrashSeverity.INFO,
        CrashType.NETWORK_ERROR: CrashSeverity.INFO,
        CrashType.PERMISSION_DENIED: CrashSeverity.INFO,
        CrashType.UNKNOWN: CrashSeverity.MEDIUM
    }
    
    # Ложные срабатывания
    FALSE_POSITIVE_TYPES = {
        CrashType.OOM_KILLER,
        CrashType.TIMEOUT,
        CrashType.RESOURCE_LIMIT,
        CrashType.NETWORK_ERROR,
        CrashType.PERMISSION_DENIED,
        CrashType.DISK_FULL
    }
    
    def __init__(self, 
                 target: str,
                 crashes_dir: Path,
                 reports_dir: Path,
                 corpus_dir: Optional[Path] = None,
                 minimize: bool = True,
                 cluster: bool = True):
        self.target = target
        self.crashes_dir = Path(crashes_dir)
        self.reports_dir = Path(reports_dir)
        self.corpus_dir = Path(corpus_dir) if corpus_dir else None
        self.minimize = minimize
        self.cluster = cluster
        
        self.crashes: List[Crash] = []
        self.clusters: List[CrashCluster] = []
        self.stats = {
            'total_crashes': 0,
            'legitimate_bugs': 0,
            'false_positives': 0,
            'unique_clusters': 0,
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int)
        }
    
    def log(self, message: str) -> None:
        """Логирование"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} [CrashAnalyzer] [{self.target}] {message}")
    
    def _classify_crash(self, crash: Crash) -> Tuple[CrashType, CrashSeverity]:
        """Классификация типа и серьезности краша"""
        combined_text = f"{crash.stack_trace}\n{crash.error_message}".lower()
        
        for crash_type, patterns in self.CRASH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    severity = self.SEVERITY_MAP.get(crash_type, CrashSeverity.MEDIUM)
                    return crash_type, severity
        
        return CrashType.UNKNOWN, CrashSeverity.MEDIUM
    
    def _is_false_positive(self, crash: Crash) -> bool:
        """Определение является ли краш ложным срабатыванием"""
        # Проверяем тип краша
        if crash.crash_type in self.FALSE_POSITIVE_TYPES:
            return True
        
        # Проверяем размер входных данных (слишком большой может вызвать OOM)
        if len(crash.input_data) > 100 * 1024 * 1024:  # > 100MB
            return True
        
        # Проверяем паттерны в stack trace
        false_positive_patterns = [
            r'test.*framework',
            r'pytest',
            r'unittest',
            r'mock',
            r'fixture'
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, crash.stack_trace, re.IGNORECASE):
                # Это может быть проблема тестовой инфраструктуры
                crash.tags.append('potentially-infrastructure')
                break
        
        return False
    
    def _compute_similarity_hash(self, crash: Crash) -> str:
        """Вычисление хэша схожести для кластеризации"""
        # Извлекаем ключевые части stack trace
        stack_frames = crash.stack_trace.split('\n')
        
        # Фильтруем и нормализуем frames
        normalized_frames = []
        for frame in stack_frames:
            # Удаляем адреса и номера строк
            normalized = re.sub(r'0x[0-9a-f]+', '', frame)
            normalized = re.sub(r':\d+', '', normalized)
            normalized = re.sub(r'line \d+', '', normalized)
            normalized = normalized.strip()
            if normalized:
                normalized_frames.append(normalized)
        
        # Берем топ-5 фреймов
        top_frames = normalized_frames[:5]
        
        # Создаем хэш
        combined = '|'.join(top_frames)
        return hashlib.md5(combined.encode()).hexdigest()[:16]
    
    def _minimize_input(self, crash: Crash) -> bytes:
        """Минимизация входных данных для воспроизведения краша"""
        if not crash.input_data:
            return b''
        
        # Простая стратегия: берем префикс данных
        # В реальной реализации использовали бы delta-debugging
        
        data = crash.input_data
        
        # Пробуем уменьшить до 1KB
        if len(data) > 1024:
            # Проверяем краш с первыми 1KB
            truncated = data[:1024]
            # В реальной реализации здесь была бы проверка воспроизведения
            return truncated
        
        return data
    
    def load_crashes(self) -> None:
        """Загрузка крашей из директории"""
        self.log(f"Loading crashes from {self.crashes_dir}")
        
        if not self.crashes_dir.exists():
            self.log(f"Crashes directory does not exist: {self.crashes_dir}")
            return
        
        # Ищем файлы крашей
        for crash_file in self.crashes_dir.glob('**/*.crash'):
            try:
                self._load_crash_file(crash_file)
            except Exception as e:
                self.log(f"Failed to load crash {crash_file}: {e}")
        
        # Также ищем crash logs от фаззера
        for log_file in self.crashes_dir.glob('**/*.log'):
            if 'crash' in log_file.name.lower():
                try:
                    self._load_log_file(log_file)
                except Exception as e:
                    self.log(f"Failed to load log {log_file}: {e}")
        
        self.log(f"Loaded {len(self.crashes)} crashes")
    
    def _load_crash_file(self, crash_file: Path) -> None:
        """Загрузка отдельного файла краша"""
        # Читаем данные краша
        with open(crash_file, 'rb') as f:
            content = f.read()
        
        # Пробуем распарсить как JSON
        crash_data = {}
        try:
            text = content.decode('utf-8')
            if text.strip().startswith('{'):
                crash_data = json.loads(text)
        except:
            pass
        
        # Создаем Crash объект
        crash_id = crash_data.get('crash_id') or hashlib.md5(content).hexdigest()[:12]
        
        # Ищем соответствующий input файл
        input_file = None
        input_data = b''
        
        possible_input_names = [
            crash_file.with_suffix('.input'),
            crash_file.with_suffix('.bin'),
            crash_file.with_suffix('.txt'),
            crash_file.parent / f"{crash_file.stem}_input"
        ]
        
        for possible in possible_input_names:
            if possible.exists():
                input_file = possible
                with open(possible, 'rb') as f:
                    input_data = f.read()
                break
        
        crash = Crash(
            crash_id=crash_id,
            target=self.target,
            input_file=input_file,
            input_data=input_data,
            stack_trace=crash_data.get('stack_trace', ''),
            error_message=crash_data.get('error_message', ''),
            timestamp=datetime.fromtimestamp(crash_file.stat().st_mtime)
        )
        
        # Классифицируем
        crash.crash_type, crash.severity = self._classify_crash(crash)
        
        # Проверяем false positive
        crash.is_false_positive = self._is_false_positive(crash)
        crash.is_legitimate_bug = not crash.is_false_positive
        
        # Вычисляем similarity hash
        crash.similarity_hash = self._compute_similarity_hash(crash)
        
        self.crashes.append(crash)
    
    def _load_log_file(self, log_file: Path) -> None:
        """Загрузка краша из лог-файла"""
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Ищем stack traces и ошибки
        stack_trace = ""
        error_message = ""
        
        # Паттерн для Python traceback
        if 'Traceback' in content:
            match = re.search(r'Traceback.*?(?=\n\n|\Z)', content, re.DOTALL)
            if match:
                stack_trace = match.group(0)
        
        # Паттерн для ошибок
        error_patterns = [
            r'Error: .+',
            r'Exception: .+',
            r'FATAL: .+',
            r'CRITICAL: .+'
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, content)
            if match:
                error_message = match.group(0)
                break
        
        if stack_trace or error_message:
            crash_id = hashlib.md5(content.encode()).hexdigest()[:12]
            
            crash = Crash(
                crash_id=crash_id,
                target=self.target,
                input_file=log_file,
                stack_trace=stack_trace,
                error_message=error_message,
                timestamp=datetime.fromtimestamp(log_file.stat().st_mtime)
            )
            
            crash.crash_type, crash.severity = self._classify_crash(crash)
            crash.is_false_positive = self._is_false_positive(crash)
            crash.is_legitimate_bug = not crash.is_false_positive
            crash.similarity_hash = self._compute_similarity_hash(crash)
            
            self.crashes.append(crash)
    
    def analyze(self) -> None:
        """Анализ загруженных крашей"""
        self.log("Analyzing crashes...")
        
        # Минимизация
        if self.minimize:
            for crash in self.crashes:
                crash.minimized_input = self._minimize_input(crash)
        
        # Кластеризация
        if self.cluster:
            self._cluster_crashes()
        
        # Сбор статистики
        self._collect_stats()
        
        self.log(f"Analysis complete: {self.stats['legitimate_bugs']} legitimate bugs, "
                f"{self.stats['false_positives']} false positives")
    
    def _cluster_crashes(self) -> None:
        """Кластеризация крашей по схожести"""
        # Группируем по similarity hash
        hash_groups: Dict[str, List[Crash]] = defaultdict(list)
        
        for crash in self.crashes:
            hash_groups[crash.similarity_hash].append(crash)
        
        # Создаем кластеры
        for idx, (hash_val, crashes) in enumerate(hash_groups.items()):
            cluster = CrashCluster(
                cluster_id=f"cluster_{idx:03d}",
                crashes=crashes,
                similarity_score=1.0  # Все краши в группе имеют одинаковый hash
            )
            
            # Выбираем представителя (первый краш или самый маленький)
            cluster.representative = min(crashes, key=lambda c: len(c.input_data))
            
            # Находим общие stack frames
            if crashes:
                all_frames = [set(c.stack_trace.split('\n')) for c in crashes]
                cluster.common_stack_frames = list(
                    set.intersection(*all_frames) if all_frames else []
                )
            
            # Присваиваем cluster_id крашам
            for crash in crashes:
                crash.cluster_id = cluster.cluster_id
            
            self.clusters.append(cluster)
        
        self.log(f"Created {len(self.clusters)} crash clusters")
    
    def _collect_stats(self) -> None:
        """Сбор статистики"""
        self.stats['total_crashes'] = len(self.crashes)
        
        for crash in self.crashes:
            if crash.is_false_positive:
                self.stats['false_positives'] += 1
            else:
                self.stats['legitimate_bugs'] += 1
            
            self.stats['by_severity'][crash.severity.value] += 1
            self.stats['by_type'][crash.crash_type.value] += 1
        
        self.stats['unique_clusters'] = len(self.clusters)
    
    def generate_report(self) -> Dict[str, Any]:
        """Генерация отчета"""
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'statistics': dict(self.stats),
            'crashes': [c.to_dict() for c in self.crashes],
            'clusters': [c.to_dict() for c in self.clusters],
            'summary': {
                'total': len(self.crashes),
                'legitimate_bugs': self.stats['legitimate_bugs'],
                'false_positives': self.stats['false_positives'],
                'unique_clusters': len(self.clusters),
                'severity_breakdown': dict(self.stats['by_severity']),
                'type_breakdown': dict(self.stats['by_type'])
            }
        }
        
        return report
    
    def save_report(self, format: str = 'json') -> Path:
        """Сохранение отчета в файл"""
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        report = self.generate_report()
        
        if format == 'json':
            output_file = self.reports_dir / f"{self.target}_crash_analysis.json"
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        else:
            output_file = self.reports_dir / f"{self.target}_crash_analysis.txt"
            with open(output_file, 'w') as f:
                f.write(self._format_text_report(report))
        
        self.log(f"Report saved to {output_file}")
        return output_file
    
    def _format_text_report(self, report: Dict) -> str:
        """Форматирование текстового отчета"""
        lines = [
            "=" * 70,
            f"CRASH ANALYSIS REPORT - {report['target']}",
            f"Generated: {report['timestamp']}",
            "=" * 70,
            "",
            "SUMMARY",
            "-" * 40,
            f"Total crashes: {report['summary']['total']}",
            f"Legitimate bugs: {report['summary']['legitimate_bugs']}",
            f"False positives: {report['summary']['false_positives']}",
            f"Unique clusters: {report['summary']['unique_clusters']}",
            "",
            "BY SEVERITY",
            "-" * 40
        ]
        
        for severity, count in report['summary']['severity_breakdown'].items():
            lines.append(f"  {severity}: {count}")
        
        lines.extend([
            "",
            "BY TYPE",
            "-" * 40
        ])
        
        for crash_type, count in report['summary']['type_breakdown'].items():
            lines.append(f"  {crash_type}: {count}")
        
        if report['clusters']:
            lines.extend([
                "",
                "CLUSTERS",
                "-" * 40
            ])
            
            for cluster in report['clusters']:
                lines.append(f"  [{cluster['cluster_id']}] {cluster['crash_count']} crashes")
                if cluster.get('representative_id'):
                    lines.append(f"    Representative: {cluster['representative_id']}")
        
        lines.extend(["", "=" * 70])
        
        return '\n'.join(lines)


def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(
        description='Crash Analyzer - анализ и кластеризация крашей',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--target', '-t', required=True, help='Target name')
    parser.add_argument('--crashes-dir', required=True, help='Crashes directory')
    parser.add_argument('--reports-dir', default='fuzz/reports', help='Reports directory')
    parser.add_argument('--corpus-dir', help='Corpus directory')
    parser.add_argument('--minimize', action='store_true', default=True, help='Minimize inputs')
    parser.add_argument('--cluster', action='store_true', default=True, help='Cluster crashes')
    parser.add_argument('--format', choices=['json', 'text'], default='json', help='Output format')
    
    args = parser.parse_args()
    
    # Создаем анализатор
    analyzer = CrashAnalyzer(
        target=args.target,
        crashes_dir=Path(args.crashes_dir),
        reports_dir=Path(args.reports_dir),
        corpus_dir=Path(args.corpus_dir) if args.corpus_dir else None,
        minimize=args.minimize,
        cluster=args.cluster
    )
    
    # Загружаем и анализируем краши
    analyzer.load_crashes()
    analyzer.analyze()
    
    # Сохраняем отчет
    output_file = analyzer.save_report(format=args.format)
    
    # Выводим сводку
    print("\n" + "=" * 60)
    print("CRASH ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Target: {args.target}")
    print(f"Total crashes: {analyzer.stats['total_crashes']}")
    print(f"Legitimate bugs: {analyzer.stats['legitimate_bugs']}")
    print(f"False positives: {analyzer.stats['false_positives']}")
    print(f"Unique clusters: {analyzer.stats['unique_clusters']}")
    print(f"Report: {output_file}")
    print("=" * 60)


if __name__ == '__main__':
    main()