import json
import os
import sys
import logging
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QColor, QIcon
from PyQt5.QtWidgets import QApplication, QWidget

# Путь к файлу конфигурации
data_dir = os.path.join(os.path.dirname(sys.executable), "date")
os.makedirs(data_dir, exist_ok=True)
CONFIG_FILE = os.path.join(data_dir, "config.json")

def save_theme(theme: str):
    """Сохраняет выбранную тему в config.json."""
    try:
        config = {'theme': theme}
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        logging.info(f"Тема сохранена: {theme}")
    except Exception as e:
        logging.error(f"Ошибка сохранения темы: {e}")

def load_theme() -> str:
    """Загружает тему из config.json или возвращает 'light' при первом запуске."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get('theme', 'light')
        return 'light'  # По умолчанию светлая тема
    except Exception as e:
        logging.error(f"Ошибка загрузки темы: {e}")
        return 'light'

def apply_theme(widget: QWidget, theme: str):
    """Применяет указанную тему к виджету и обновляет глобальную палитру."""
    if theme == "dark":
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        QApplication.instance().setPalette(palette)
        # Стили и иконка для кнопки темы (если она есть)
        if hasattr(widget, 'theme_button'):
            widget.theme_button.setIcon(QIcon('images/light_theme_icon.png'))  # Светлая иконка для тёмной темы
            widget.theme_button.setStyleSheet("""
                QPushButton {
                    border: none;
                    border-radius: 5px;
                    background-color: rgba(240, 240, 240, 0.2);
                }
                QPushButton:hover {
                    background-color: rgba(220, 220, 220, 0.3);
                }
                QPushButton::menu-indicator {
                    image: none;
                }
            """)
    else:  # light theme
        QApplication.instance().setPalette(QApplication.style().standardPalette())
        if hasattr(widget, 'theme_button'):
            widget.theme_button.setIcon(QIcon('images/dark_theme_icon.png'))  # Тёмная иконка для светлой темы
            widget.theme_button.setStyleSheet("""
                QPushButton {
                    border: none;
                    border-radius: 5px;
                    background-color: rgba(53, 53, 53, 0.2);
                }
                QPushButton:hover {
                    background-color: rgba(80, 80, 80, 0.3);
                }
                QPushButton::menu-indicator {
                    image: none;
                }
            """)
    logging.info(f"Тема {theme} применена к виджету {widget.__class__.__name__}")