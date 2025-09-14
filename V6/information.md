# 🚀 Команда для сборки приложения

Это инструкция для компиляции скрипта `main.py` в один исполняемый (`.exe`) файл для Windows с помощью Nuitka.

## Полная команда для терминала:

Скопируйте и выполните эту команду в вашей консоли.

```bash
python -m nuitka --standalone --windows-console-mode=disable --disable-cache=ccache --enable-plugin=pyqt5 --include-data-dir=images=images --windows-icon-from-ico=images/main_icon.ico --output-dir=build --output-filename=UserManagementApp.exe main.py
```

### Пояснение опций:

* `--standalone:` Создаёт автономный дистрибутив со всеми зависимостями.
* 
* `--windows-console-mode=disable:` Скрывает консольное окно при запуске.
* 
* `--disable-cache=ccache:` Отключает кэш компилятора для чистой сборки.
* 
* `--enable-plugin=pyqt5:` Обеспечивает поддержку PyQt5.
* 
* `--include-data-dir=images=images:` Копирует папку images в дистрибутив.
* 
* `--windows-icon-from-ico=images/main_icon.ico:` Встраивает main_icon.ico как иконку .exe.
* 
* `--output-dir=build:` Сохраняет результаты в папку build.
* 
* `--output-filename=UserManagementApp.exe:` Задаёт имя .exe файла.

## Важно при сборке

Переменная окружения `NUITKA_CACHE_DIR:` Вы используете `set NUITKA_CACHE_DIR=C:\PP\NCached` перед командой, чтобы перенаправить кэш Nuitka (например, для скачивания компилятора GCC) в `C:\PP\NCached.` Это не часть команды Nuitka, но влияет на то, где хранятся кэшированные файлы.

