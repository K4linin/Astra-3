# 🚀 Быстрый старт: Как тестировать свой проект

## ❓ Частые вопросы

### 1. Откуда взялись 700+ ошибок?

**Это НЕ ошибки в вашем коде!** Это нормально для фаззинга:

- Фаззер генерирует **случайные бинарные данные** (мусор)
- Он отправляет их в функции парсинга (JSON, YAML, SQL и т.д.)
- Большинство данных невалидны → вызывают TypeError, ValueError и т.д.
- Фаззинг помечает их как "краши" - но это **ожидаемые исключения**

**Реальные баги** - это:
- SEGFAULT (segmentation fault)
- Buffer Overflow
- Use-After-Free
- Бесконечные циклы
- Крах Python интерпретатора

В нашем тесте все 700+ это TypeError - **это нормально**, значит код правильно обрабатывает невалидный ввод.

---

## 2. Как тестировать СВОЙ проект

### Шаг 1: Создайте свой target

Допустим, у вас есть функция в `src/my_module.py`:

```python
# src/my_module.py
def process_payment(card_number: str, amount: float):
    """Ваша функция обработки платежей"""
    if not card_number.isdigit():
        raise ValueError("Invalid card number")
    if amount < 0:
        raise ValueError("Negative amount")
    # ... логика обработки
    return {"status": "success", "transaction_id": "tx_123"}
```

### Шаг 2: Создайте fuzzing wrapper

Создайте файл `fuzz/targets/process_payment.py`:

```python
"""
Target: process_payment
Фаззинг функции обработки платежей
"""

import sys

# Импортируйте ваш модуль
# Добавьте путь к вашему проекту если нужно
# sys.path.insert(0, '/path/to/your/project')
# from src.my_module import process_payment

def process_payment_local(card_number: str, amount_str: str):
    """Локальная копия функции для примера"""
    if not card_number or not card_number.isdigit():
        raise ValueError("Invalid card number")
    
    try:
        amount = float(amount_str)
    except ValueError:
        raise ValueError("Invalid amount")
    
    if amount < 0:
        raise ValueError("Negative amount")
    
    return {"status": "success"}


def fuzz_target(data: bytes) -> None:
    """
    Главная фаззинг-функция
    
    Принимает случайные байты и тестирует функцию.
    ВАЖНО: Ловите ожидаемые исключения!
    """
    if len(data) < 2:
        return
    
    try:
        # Разделяем данные на две части: номер карты и сумма
        parts = data.split(b'|', 1)
        
        if len(parts) == 2:
            card_number = parts[0].decode('utf-8', errors='replace')
            amount_str = parts[1].decode('utf-8', errors='replace')
        else:
            # Если разделителя нет - используем первые 16 байт как номер
            card_number = data[:16].decode('utf-8', errors='replace')
            amount_str = data[16:].decode('utf-8', errors='replace')
        
        # Вызываем тестируемую функцию
        result = process_payment_local(card_number, amount_str)
        
    except ValueError:
        # Ожидаемая ошибка валидации - НЕ КРАШ
        pass
    except UnicodeDecodeError:
        # Ожидаемая ошибка декодирования - НЕ КРАШ
        pass
    
    # Если функция упала с другой ошибкой (например, IndexError, AttributeError)
    # и мы её не поймали - это КРАШ (баг!)


if __name__ == '__main__':
    try:
        import atheris
        atheris.Setup(sys.argv, lambda d: fuzz_target(d))
        atheris.Fuzz()
    except ImportError:
        print("atheris not installed - use fuzzing_monitor.py")
```

### Шаг 3: Запустите фаззинг

```bash
python fuzz/scripts/fuzzing_monitor.py \
    --target process_payment \
    --duration 5 \
    --verbosity normal
```

### Шаг 4: Анализируйте результаты

```
fuzz/crashes/process_payment/   <- Найденные краши
fuzz/corpus/process_payment/    <- Corpus (интересные input)
fuzz/logs/process_payment/      <- Логи и статистика
```

---

## 3. Типы багов которые находит фаззинг

### ✅ РЕАЛЬНЫЕ БАГИ (нужно исправить)

| Тип | Описание | Severity |
|-----|----------|----------|
| `IndexError` | Выход за границы массива | Medium |
| `AttributeError` | Обращение к несуществующему атрибуту | Medium |
| `ZeroDivisionError` | Деление на ноль | Medium |
| `RecursionError` | Бесконечная рекурсия | High |
| `MemoryError` | Утечка памяти | High |

### ⚠️ ОЖИДАЕМЫЕ ИСКЛЮЧЕНИЯ (не баги)

| Тип | Почему не баг |
|-----|---------------|
| `ValueError` | Валидация входных данных |
| `TypeError` | Проверка типов |
| `JSONDecodeError` | Невалидный JSON |
| `UnicodeDecodeError` | Невалидная кодировка |

### 🔴 КРИТИЧЕСКИЕ БАГИ

| Тип | Описание | Что делать |
|-----|----------|------------|
| SEGFAULT | Ошибка памяти | Срочно исправить! |
| Buffer Overflow | Переполнение буфера | Security issue! |
| Hang | Бесконечный цикл | Установить timeout |

---

## 4. Пример: Тестирование реального API

Допустим, у вас есть FastAPI приложение:

```python
# fuzz/targets/test_api.py

import sys
import json

def fuzz_target(data: bytes) -> None:
    """Фаззинг API endpoint"""
    
    try:
        # Пробуем распарсить как JSON
        payload = json.loads(data.decode('utf-8', errors='replace'))
    except json.JSONDecodeError:
        return  # Не JSON - пропускаем
    
    # Тестируем endpoint
    try:
        # Импортируйте ваше приложение
        # from app.main import app
        # from fastapi.testclient import TestClient
        # client = TestClient(app)
        
        # response = client.post("/api/users", json=payload)
        # assert response.status_code in [200, 400, 422]
        
        pass
        
    except Exception as e:
        # Если API упал с 500 - это баг!
        if "500" in str(e) or "Internal Server Error" in str(e):
            raise  # Пробрасываем как краш
        pass
```

---

## 5. Интеграция с вашим проектом

### Вариант A: Копирование файлов

```bash
# Скопируйте fuzz/ директорию в ваш проект
cp -r fuzz/ /path/to/your/project/

# Скопируйте workflow
cp -r .github/ /path/to/your/project/

# Установите зависимости
pip install -r requirements-fuzz.txt
```

### Вариант B: Как submodule

```bash
cd /path/to/your/project
git submodule add https://github.com/your-org/fuzzing-suite.git fuzz
```

### Вариант C: Только скрипты

```bash
# Скопируйте только нужное
mkdir -p fuzz/{scripts,targets,corpus,crashes,logs,config}
cp fuzz/scripts/*.py fuzz/scripts/
cp fuzz/config/dependency_map.json fuzz/config/
```

---

## 6. Best Practices

### ✅ ДЕЛАЙТЕ:

1. **Ловите ожидаемые исключения** в fuzz_target
2. **Ограничивайте размер данных** (data[:10000])
3. **Устанавливайте timeout** на операции
4. **Сохраняйте воспроизводимые краши** в corpus
5. **Запускайте регулярно** в CI/CD

### ❌ НЕ ДЕЛАЙТЕ:

1. Не игнорируйте все исключения (except Exception: pass)
2. Не тестируйте внешние API без mock
3. Не запускайте бесконечно без таймаута
4. Не забывайте про очистку ресурсов

---

## 7. Быстрая проверка

```bash
# Запуск на 1 минуту для проверки
python fuzz/scripts/fuzzing_monitor.py \
    --target parse_config \
    --duration 1 \
    --verbosity verbose

# Проверка результатов
ls fuzz/crashes/parse_config/
cat fuzz/logs/parse_config/stats_*.json
```

---

## 📞 Нужна помощь?

- Смотрите примеры в `fuzz/targets/*.py`
- Читайте README.md
- Проверяйте логи в `fuzz/logs/`