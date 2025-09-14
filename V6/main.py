import logging
import os
import sys
import traceback
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication
from login_window import LoginWindow

# Настройка логирования для записи в файл
data_dir = os.path.join(os.path.dirname(sys.executable), "date")
os.makedirs(data_dir, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(data_dir, "app.log")),
        logging.StreamHandler()
    ]
)

if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        app.setWindowIcon(QIcon('images/main_icon.png'))
        login_window = LoginWindow()
        login_window.show()
        sys.exit(app.exec_())
    except Exception as e:
        logging.error("Критическая ошибка при запуске приложения", exc_info=e)
        traceback.print_exc()