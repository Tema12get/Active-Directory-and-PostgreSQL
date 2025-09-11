## 🚀 Команда для сборки приложения

Это инструкция для компиляции скрипта `main.py` в один исполняемый (`.exe`) файл для Windows с помощью Nuitka.

### Полная команда для терминала:

Скопируйте и выполните эту команду в вашей консоли.

```bash
python -m nuitka --standalone --onefile --windows-console-mode=disable --disable-cache=ccache --enable-plugin=pyqt5 --output-dir=build --output-file=UserManagementApp main.py
```

Пояснение опций:
--standalone: Включить все необходимые библиотеки в сборку.

--onefile: Создать один исполняемый файл.

--windows-console-mode=disable: Отключить появление консольного окна при запуске.

--enable-plugin=pyqt5: Подключить плагин для корректной работы с библиотекой PyQt5.

--output-dir=build: Папка, куда будет помещен результат.

--output-file=UserManagementApp: Имя конечного файла.
