# 📁 Описание файлов проекта

## Структура проекта

```
Astra-3/
├── .github/workflows/
│   └── fuzzing-main.yml          
├── fuzz/
│   ├── config/
│   │   └── dependency_map.json   
│   ├── scripts/
│   │   ├── fuzzing_monitor.py    
│   │   ├── crash_analyzer.py     
│   │   ├── generate_report.py    
│   │   └── bug_reporter.py       
│   └── targets/
│       ├── __init__.py           
│       ├── parse_config.py       
│       ├── process_user_input.py 
│       ├── handle_network_packet.py
│       ├── serialize_data.py     
│       ├── load_database.py      
│       ├── compress_image.py     
│       ├── execute_command.py    
│       ├── format_output.py      
│       ├── validate_schema.py    
│       └── calculate_checksum.py 
├── requirements-fuzz.txt         
├── README.md                     
├── QUICKSTART.md                 
└── FILES.md                      
```

---

## 📄 Описание каждого файла

### 🔧 Конфигурация

| Файл | Назначение |
|------|------------|
| `requirements-fuzz.txt` | Python зависимости (hypothesis, pytest, pyyaml, etc.) |
| `fuzz/config/dependency_map.json` | Связывает файлы проекта с fuzzing targets |

---

### 🚀 GitHub Actions

| Файл | Назначение |
|------|------------|
| `.github/workflows/fuzzing-main.yml` | CI/CD pipeline с 15+ триггерами |

**Что делает:**
1. Анализирует изменившиеся файлы
2. Определяет какие targets запускать
3. Запускает фаззинг параллельно (5 jobs одновременно)
4. Собирает краши и создаёт отчёты
5. Автоматически создаёт GitHub Issues для багов
6. Загружает артефакты (corpus, crashes, logs)

---

### 🎮 Основные скрипты (fuzz/scripts/)

#### `fuzzing_monitor.py` ⭐ Главный файл

**Назначение:** Оркестратор фаззинг-тестирования

**Что делает:**
1. Загружает target модуль
2. Генерирует случайные данные (мутации, edge cases)
3. Запускает fuzz_target() для каждого input
4. Ловит краши и сохраняет их
5. Мониторит ресурсы (CPU, память)
6. Останавливается по timeout или отсутствию крашей
7. Выводит статистику

**Запуск:**
```bash
python fuzz/scripts/fuzzing_monitor.py --target parse_config --duration 5
```

---

#### `crash_analyzer.py`

**Назначение:** Анализ и кластеризация найденных крашей

**Что делает:**
1. Загружает crash файлы из директории
2. Классифицирует по типу (TypeError, ValueError, etc.)
3. Определяет severity (critical, high, medium, low)
4. Проверяет на false positive (OOM, timeout)
5. Кластеризует похожие краши по stack trace
6. Генерирует crash summary

**Запуск:**
```bash
python fuzz/scripts/crash_analyzer.py --target parse_config --crashes-dir fuzz/crashes
```

---

#### `generate_report.py`

**Назначение:** Генерация отчётов в разных форматах

**Что делает:**
1. Загружает статистику из логов
2. Загружает информацию о крашах
3. Генерирует HTML отчёт с графиками
4. Генерирует Markdown для GitHub PR comments
5. Генерирует JSON для интеграции с CI

**Форматы:**
- `report.html` - Интерактивный HTML
- `report.md` - Markdown summary
- `report.json` - Машинно-читаемый формат

---

#### `bug_reporter.py`

**Назначение:** Автоматическое создание GitHub Issues

**Что делает:**
1. Анализирует краши
2. Группирует по типу (не создаёт дубликаты)
3. Формирует описание бага
4. Создаёт GitHub Issue через API
5. Добавляет labels (bug, severity, fuzzing)
6. Прикрепляет input файл для воспроизведения

---

### 🎯 Fuzzing Targets (fuzz/targets/)

Каждый target тестирует определённую функциональность:

#### `parse_config.py`
**Тестирует:** Парсинг конфигурационных файлов
- JSON
- YAML
- INI
- ENV files

**Типичные баги:** Невалидный JSON, глубокая вложенность, спецсимволы

---

#### `process_user_input.py`
**Тестирует:** Обработку пользовательского ввода
- Валидация форм
- SQL инъекции
- XSS атаки
- Path traversal

**Типичные баги:** Обход валидации, инъекции

---

#### `handle_network_packet.py`
**Тестирует:** Парсинг сетевых пакетов
- Ethernet frames
- IP packets
- TCP/UDP segments
- HTTP requests

**Типичные баги:** Malformed packets, buffer overflow

---

#### `serialize_data.py`
**Тестирует:** Сериализацию/десериализацию
- JSON encode/decode
- XML parsing
- Pickle (безопасность)

**Типичные баги:** Рекурсивные структуры, memory exhaustion

---

#### `load_database.py`
**Тестирует:** Операции с базой данных
- SQL parsing
- INSERT/SELECT statements
- Query validation

**Типичные баги:** SQL инъекции, malformed queries

---

#### `compress_image.py`
**Тестирует:** Сжатие изображений
- PNG parsing
- JPEG parsing
- RLE compression
- Zlib compression

**Типичные баги:** Buffer overflow в декодерах, integer overflow

---

#### `execute_command.py`
**Тестирует:** Выполнение команд (безопасная симуляция)
- CLI parsing
- Command injection
- Shell escaping

**Типичные баги:** Command injection, privilege escalation

---

#### `format_output.py`
**Тестирует:** Форматирование вывода
- XML generation
- CSV formatting
- Table formatting
- Template rendering

**Типичные баги:** XSS в HTML, injection в CSV

---

#### `validate_schema.py`
**Тестирует:** Валидацию JSON Schema
- Type validation
- Pattern matching
- Recursive schemas
- OneOf/AnyOf/AllOf

**Типичные баги:** ReDoS, бесконечная рекурсия

---

#### `calculate_checksum.py`
**Тестирует:** Вычисление контрольных сумм
- CRC32
- MD5, SHA1, SHA256
- Adler-32
- Fletcher checksum

**Типичные баги:** Integer overflow, infinite loops

---

#### `__init__.py`
**Назначение:** Инициализация Python пакета

**Что делает:**
- Экспортирует все targets
- Определяет список доступных targets
- Вспомогательные функции

---

### 📚 Документация

| Файл | Назначение |
|------|------------|
| `README.md` | Полная документация проекта |
| `QUICKSTART.md` | Быстрый старт и FAQ |
| `FILES.md` | Этот файл - описание всех файлов |

---

## 📂 Директории (создаются автоматически)

| Директория | Назначение |
|------------|------------|
| `fuzz/corpus/<target>/` | Corpus - входные данные для фаззинга |
| `fuzz/crashes/<target>/` | Найденные краши (.crash + .input файлы) |
| `fuzz/logs/<target>/` | Логи выполнения и статистика |
| `fuzz/reports/` | Сгенерированные отчёты (HTML/MD/JSON) |

---

## 🔄 Поток данных

```
1. fuzzing_monitor.py
   ↓ генерирует данные
2. fuzz/targets/<target>.py::fuzz_target()
   ↓ ловит краши
3. fuzz/crashes/<target>/crash_*.crash
   ↓ анализирует
4. crash_analyzer.py
   ↓ кластеризует
5. generate_report.py
   ↓ создаёт отчёт
6. fuzz/reports/<target>_report.html
   ↓ создаёт Issues
7. bug_reporter.py
   ↓
8. GitHub Issues
```

---

## ⚡ Минимальный набор для старта

Для использования в своём проекте достаточно:

```
fuzz/
├── config/dependency_map.json
├── scripts/fuzzing_monitor.py
└── targets/<ваш_target>.py

requirements-fuzz.txt
```

Всё остальное - опционально!