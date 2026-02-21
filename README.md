Установка

pip install -r requirements-fuzz.txt


Для Linux нужен atheris
pip install atheris

Запуск

python fuzz/scripts/fuzzing_monitor.py --target <имя_target> --duration <минуты>

Запуск на 30 минут

python fuzz/scripts/fuzzing_monitor.py --target parse_config --duration 30

Доступные targets

Основные:
- `parse_config` - парсинг конфигов (JSON, YAML, INI)
- `process_user_input` - обработка пользовательского ввода
- `handle_network_packet` - сетевые пакеты (Ethernet, IP, TCP, UDP)
- `serialize_data` - сериализация (JSON, XML)
- `load_database` - SQL операции
- `compress_image` - сжатие (PNG, JPEG, zlib)
- `execute_command` - парсинг команд
- `format_output` - форматирование вывода
- `validate_schema` - JSON Schema валидация
- `calculate_checksum` - контрольные суммы (CRC32, MD5, SHA)
- `img2pdf_convert` - конвертация изображений в PDF

CVE targets (поиск уязвимостей):
- `cve_url_parsing` - URL injection, SSRF
- `cve_ssrf` - Server-Side Request Forgery
- `cve_path_traversal` - обход пути
- `cve_deserialization` - небезопасная десериализация
- `cve_regex_dos` - ReDoS атаки

Результаты

Результаты сохраняются в:
- `fuzz/crashes/<target>/` - найденные краши
- `fuzz/corpus/<target>/` - corpus данные
- `fuzz/logs/<target>/` - логи и статистика

