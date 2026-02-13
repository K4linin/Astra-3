# 🧪 Fuzzing Testing Suite

Комплексная система фаззинг-тестирования для GitHub Actions с поддержкой 15+ триггеров, автоматической кластеризацией крашей и интеграцией с баг-трекером.

## 📋 Содержание

- [Возможности](#возможности)
- [Архитектура](#архитектура)
- [Установка](#установка)
- [Использование](#использование)
- [Конфигурация](#конфигурация)
- [Fuzzing Targets](#fuzzing-targets)
- [GitHub Actions](#github-actions)
- [Отчеты](#отчеты)

---

## ✨ Возможности

### 15+ Триггеров для CI/CD

| # | Триггер | Описание |
|---|---------|----------|
| 1 | `push` | Push в любую ветку |
| 2 | `pull_request` | Открытие PR |
| 3 | `pull_request:synchronize` | Новый коммит в PR |
| 4 | `pull_request:closed` | Закрытие/merge PR |
| 5 | `merge_group` | Merge queue |
| 6 | `release` | Публикация релиза |
| 7 | `create:tag` | Создание тега |
| 8 | `delete` | Удаление ветки/тега |
| 9 | `schedule:daily` | Nightly build (2:00 UTC) |
| 10 | `schedule:weekend` | Выходные (3:00 UTC) |
| 11 | `workflow_dispatch` | Ручной запуск |
| 12 | `workflow_call` | Вызов из другого workflow |
| 13 | `workflow_run` | После другого workflow |
| 14 | `issues` | События с issues |
| 15 | `issue_comment` | Комментарии к issues |

### Shift Left подход

- ✅ Запуск фаззинга на самых ранних этапах CI/CD
- ✅ Инкрементальный анализ изменений
- ✅ Перезапуск только затронутых targets

### Автоматизация

- 🔄 Автоматическое определение зависимостей
- 🔄 Кластеризация крашей по схожести
- 🔄 Создание GitHub Issues для багов
- 🔄 Graceful shutdown по условиям

---

## 🏗️ Архитектура

```
Astra-3/
├── .github/
│   └── workflows/
│       └── fuzzing-main.yml      # Главный workflow
├── fuzz/
│   ├── config/
│   │   └── dependency_map.json   # Карта зависимостей
│   ├── corpus/                   # Corpus данные
│   ├── crashes/                  # Найденные краши
│   ├── logs/                     # Логи выполнения
│   ├── reports/                  # HTML/MD/JSON отчеты
│   ├── scripts/
│   │   ├── fuzzing_monitor.py    # Мониторинг фаззинга
│   │   ├── crash_analyzer.py     # Анализ крашей
│   │   ├── generate_report.py    # Генерация отчетов
│   │   └── bug_reporter.py       # Создание баг-репортов
│   └── targets/
│       ├── __init__.py
│       ├── parse_config.py       # Target 1
│       ├── process_user_input.py # Target 2
│       ├── handle_network_packet.py # Target 3
│       ├── serialize_data.py     # Target 4
│       ├── load_database.py      # Target 5
│       ├── compress_image.py     # Target 6
│       ├── execute_command.py    # Target 7
│       ├── format_output.py      # Target 8
│       ├── validate_schema.py    # Target 9
│       └── calculate_checksum.py # Target 10
└── requirements-fuzz.txt         # Зависимости
```

---

## 🚀 Установка

### Локальная установка

```bash
# Клонирование
git clone https://github.com/your-org/Astra-3.git
cd Astra-3

# Создание виртуального окружения
python -m venv venv
source venv/bin/activate  # Linux/Mac
# или
venv\Scripts\activate     # Windows

# Установка зависимостей
pip install -r requirements-fuzz.txt
```

### Установка atheris (Linux/macOS)

```bash
# Требуется Clang
sudo apt-get install clang  # Ubuntu/Debian
brew install llvm           # macOS

pip install atheris
```

---

## 💻 Использование

### Запуск локально

```bash
# Запуск мониторинга фаззинга
python fuzz/scripts/fuzzing_monitor.py \
    --target parse_config \
    --duration 30 \
    --crash-timeout 2 \
    --verbosity verbose

# Анализ крашей
python fuzz/scripts/crash_analyzer.py \
    --target parse_config \
    --crashes-dir fuzz/crashes/parse_config \
    --reports-dir fuzz/reports

# Генерация отчетов
python fuzz/scripts/generate_report.py \
    --target parse_config \
    --format html markdown json

# Создание баг-репортов (dry-run)
python fuzz/scripts/bug_reporter.py \
    --crashes-dir fuzz/crashes \
    --repo owner/repo \
    --dry-run
```

### Ручной запуск отдельного target

```bash
# Запуск фаззинга с atheris
python -m fuzz.targets.parse_config -runs=1000

# С corpus
python -m fuzz.targets.parse_config \
    -runs=10000 \
    fuzz/corpus/parse_config/
```

---

## ⚙️ Конфигурация

### Параметры fuzzing_monitor.py

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `--target` | (обязательный) | Имя target'а |
| `--duration` | 60 | Длительность в минутах |
| `--crash-timeout` | 2 | Таймаут без крашей (часы) |
| `--corpus-dir` | fuzz/corpus | Директория corpus |
| `--crashes-dir` | fuzz/crashes | Директория крашей |
| `--verbosity` | normal | Уровень логирования |

### Параметры GitHub Actions

```yaml
# Ручной запуск с параметрами
workflow_dispatch:
  inputs:
    fuzzing_duration:
      type: choice
      options: ['15', '30', '60', '120', '240']
    targets:
      type: string
      default: 'all'
    crash_timeout:
      type: choice
      options: ['1', '2', '4', '8']
```

### Условия остановки

Фаззинг автоматически остановится если:

1. ⏱️ Превышен общий таймаут (`duration` минут)
2. ⏳ Нет новых крашей в течение `crash-timeout` часов
3. 📦 Превышен максимальный размер corpus (10,000 файлов)
4. 🛑 Получен сигнал завершения (SIGINT/SIGTERM)

---

## 🎯 Fuzzing Targets

### Список targets (10 функций)

| Target | Описание | Тестирует |
|--------|----------|-----------|
| `parse_config` | Парсинг конфигураций | JSON, YAML, INI |
| `process_user_input` | Обработка ввода | Валидация, SQL/XSS |
| `handle_network_packet` | Сетевые пакеты | Ethernet, IP, TCP, UDP |
| `serialize_data` | Сериализация | JSON, XML |
| `load_database` | Операции БД | SQL parsing |
| `compress_image` | Сжатие данных | PNG, JPEG, RLE, zlib |
| `execute_command` | Выполнение команд | CLI parsing, security |
| `format_output` | Форматирование | XML, CSV, таблицы |
| `validate_schema` | Валидация схем | JSON Schema |
| `calculate_checksum` | Контрольные суммы | CRC32, MD5, SHA, Fletcher |

### Добавление нового target

1. Создайте файл `fuzz/targets/new_target.py`:

```python
"""
Target: new_target
Описание вашего target'а
"""

def fuzz_target(data: bytes) -> None:
    """
    Главная фаззинг-функция
    
    Должна обрабатывать все исключения и падать
    только на реальных багах.
    """
    if len(data) == 0:
        return
    
    try:
        # Ваш код фаззинга
        pass
    except ExpectedError:
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
```

2. Обновите `fuzz/config/dependency_map.json`:

```json
{
  "new_target": [
    "src/new_module/",
    "fuzz/targets/new_target.py"
  ]
}
```

---

## 🔄 GitHub Actions

### Workflow Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    fuzzing-main.yml                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐     ┌──────────────┐                     │
│  │   analyze    │────▶│   prepare    │                     │
│  │              │     │              │                     │
│  │ • Diff check │     │ • Create dirs│                     │
│  │ • Deps map   │     │ • Cache corp │                     │
│  └──────────────┘     └──────────────┘                     │
│         │                    │                              │
│         ▼                    ▼                              │
│  ┌─────────────────────────────────────────┐               │
│  │              fuzz (matrix)               │               │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐   │               │
│  │  │target 1 │ │target 2 │ │target N │   │               │
│  │  └─────────┘ └─────────┘ └─────────┘   │               │
│  │         fail-fast: false                │               │
│  └─────────────────────────────────────────┘               │
│                        │                                    │
│                        ▼                                    │
│  ┌──────────────┐     ┌──────────────┐                     │
│  │  aggregate   │────▶│  bug-reports │                     │
│  │              │     │              │                     │
│  │ • Stats      │     │ • Issues     │                     │
│  │ • Summary    │     │ • Duplicates │                     │
│  └──────────────┘     └──────────────┘                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Artifacts

| Artifact | Содержание | Retention |
|----------|------------|-----------|
| `crashes-<target>-<run_id>` | Crash файлы, логи | 30 дней |
| `corpus-<target>-<run_id>` | Corpus данные | 30 дней |
| `report-<target>-<run_id>` | HTML/MD отчеты | 30 дней |
| `aggregate-results` | Сводные данные | 30 дней |

---

## 📊 Отчеты

### Форматы отчетов

1. **HTML** - Интерактивный отчет с графиками
2. **Markdown** - Для GitHub PR comments
3. **JSON** - Для интеграции с CI системами
4. **JUnit XML** - Для совместимости с тестовыми фреймворками

### Crash Analysis

```json
{
  "target": "parse_config",
  "crash_type": "ParseError",
  "severity": "medium",
  "is_false_positive": false,
  "cluster_id": "cluster_001",
  "stack_trace": "...",
  "input_size": 128
}
```

### Классификация крашей

| Severity | Типы |
|----------|------|
| 🔴 Critical | SEGFAULT, Buffer Overflow, Use-After-Free |
| 🟠 High | NULL Pointer, Assertion Failure, Integer Overflow |
| 🟡 Medium | Parse Error, Stack Overflow, Division by Zero |
| 🟢 Low | Validation Error |
| ⚪ Info | Timeout, OOM, Resource Limit |

---

## 🔒 Валидация крашей

### Легитимные баги

- SEGFAULT
- Buffer Overflow
- Use-After-Free
- NULL Pointer Dereference
- Assertion Failures

### Ложные срабатывания

- OOM Killer
- Timeout
- Resource Limits
- Network Errors
- Permission Denied

---

## 📈 Мониторинг

### Metrics

- Total executions
- Executions per second
- Corpus size
- Coverage edges/blocks
- Crash count by type/severity

### Graceful Shutdown

Мониторинг автоматически завершит работу при:

1. Превышении общего таймаута
2. Отсутствии крашей N часов
3. Получении сигнала прерывания
4. Превышении лимита памяти

---

## 🐛 Bug Reports

### Автоматическое создание Issues

При обнаружении крашей автоматически создаются GitHub Issues с:

- 📋 Подробным описанием
- 📝 Stack trace
- 🏷️ Labels (severity, type)
- 🔗 Ссылкой на run/commit
- 📎 Input файлом

### Дедупликация

Система проверяет существующие issues по Crash ID и не создаёт дубликаты.

---

## 📝 License

MIT License

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your changes
4. Run fuzzing tests
5. Submit a pull request

---

## 📞 Support

- 📧 Email: support@example.com
- 📚 Documentation: https://docs.example.com
- 🐛 Issues: https://github.com/your-org/Astra-3/issues