# 🚀 Команда для сборки приложения

Это инструкция для компиляции скрипта `main.py` в один исполняемый (`.exe`) файл для Windows с помощью Nuitka.

## Полная команда для терминала:

Скопируйте и выполните эту команду в вашей консоли.

```bash
python -m nuitka --standalone --onefile --windows-console-mode=disable --disable-cache=ccache --enable-plugin=pyqt5 --output-dir=build --output-file=UserManagementApp main.py
```

### Пояснение опций:

* `--standalone:` Включить все необходимые библиотеки в сборку.

* `--onefile:` Создать один исполняемый файл.

* `--windows-console-mode=disable:` Отключить появление консольного окна при запуске.

* `--enable-plugin=pyqt5:` Подключить плагин для корректной работы с библиотекой PyQt5.

* `--output-dir=build:` Папка, куда будет помещен результат.

* `--output-file=UserManagementApp:` Имя конечного файла.


---

# 🔐 Рекомендации по улучшению приложения

Ниже собраны практики для повышения **безопасности**, улучшения **UX/UI**, обработки **ошибок** и оптимизации **производительности** твоего приложения.

---

## 1. 🛡 Безопасность: хранение и шифрование данных

### 🔑 Хранение паролей

Текущий код держит пароли в **plaintext** в памяти — это небезопасно.
Лучшие практики: использовать **environment variables**, `keyring`, а в БД хранить только **хэши**.

```python
import bcrypt

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Пример в create_postgres_user:
hashed_pwd = hash_password(password)
cursor.execute(
    sql.SQL('CREATE USER {} WITH PASSWORD %s').format(sql.Identifier(login)),
    (hashed_pwd.decode(),)
)
```

👉 Для AD: используй `use_ssl=True` в `ldap3`.

### 🌍 Хранение credentials в переменных окружения

Не хардкодь пароли в коде, используй `.env` или системные переменные:

```python
import os
ad_admin_password = os.getenv('AD_ADMIN_PASSWORD')
if not ad_admin_password:
    raise ValueError("Установите AD_ADMIN_PASSWORD в переменных окружения")
```

Установи их через `.env` (с `python-dotenv`) или в настройках ОС.

### 🔒 Минимальные права (least privilege)

Создавай роли PostgreSQL с минимальными привилегиями:

```python
cursor.execute(
    "SELECT rolname FROM pg_roles WHERE rolname = %s AND rolsuper = false;",
    (self.pg_admin_user,)
)
if not cursor.fetchone():
    raise PermissionError("Недостаточно прав для админа")
```

### 📡 SSL для PostgreSQL

Подключайся с шифрованием:

```python
connection = psycopg2.connect(..., sslmode='require')
```

---

## 2. 🎨 Улучшение интерфейса (PyQt5)

### 📊 Model-View для таблиц

Заменяй `QListWidget` на `QTableView` с `QSqlTableModel`:

```python
from PyQt5.QtSql import QSqlDatabase, QSqlTableModel

self.db = QSqlDatabase.addDatabase("QPSQL")
self.db.setHostName(self.pg_host)
self.db.setDatabaseName(self.current_db)
self.db.setUserName(self.pg_admin_user)
self.db.setPassword(self.pg_admin_password)

self.pg_model = QSqlTableModel(self, self.db)
self.pg_model.setTable("pg_roles")
self.pg_model.select()
self.postgres_users_list.setModel(self.pg_model)  # заменяет QListWidget
```

### ✅ Валидация форм

Используй `QValidator`:

```python
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtCore import QRegExp

login_validator = QRegExpValidator(QRegExp(r"^[a-zA-Z0-9_]+$"), self)
self.login_input.setValidator(login_validator)
```

### 🎭 Стилизация

Включи современный вид:

```python
app.setStyle('Fusion')
```

### 🌐 Многоязычность

Для поддержки i18n используй `QTranslator`.

---

## 3. 📝 Обработка ошибок и логирование

### 📂 Ротация логов

```python
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler("logs/app.log", maxBytes=10*1024*1024, backupCount=5)
logging.basicConfig(level=logging.DEBUG, handlers=[handler, logging.StreamHandler()])
```

### ⚠️ Глобальный обработчик ошибок

```python
def exception_hook(exctype, value, tb):
    logging.error("Необработанная ошибка", exc_info=(exctype, value, tb))
    QMessageBox.critical(None, "Ошибка", str(value))

sys.excepthook = exception_hook
```

---

## 4. ⚡ Производительность и расширения

### 🚦 Асинхронная загрузка

Используй `QThread`, чтобы UI не зависал:

```python
from PyQt5.QtCore import QThread, pyqtSignal

class LoadUsersThread(QThread):
    finished = pyqtSignal(list)
    def run(self):
        users_list = load_ad_users_in_ou()
        self.finished.emit(users_list)
```

### 👥 Роли в AD

Ограничь права пользователей:

```python
if not self.check_ad_group_membership(login, 'Admins'):
    raise PermissionError("Нет прав на создание")
```

### 📤 Экспорт/импорт CSV

```python
import pandas as pd
df = pd.DataFrame(users_data)
df.to_csv('users.csv', index=False)
```

### 🧪 Unit-тесты

Добавь `pytest` для проверки `validate_password` и подключений.

---

# 🚀 Следующие шаги

Определи, с чего начать:

* 🔐 Безопасность
* 🎨 Интерфейс
* 📝 Логирование
* ⚡ Оптимизация

---
