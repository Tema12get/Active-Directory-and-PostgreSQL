import logging
import ldap3
import psycopg2
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QGroupBox, QLabel, QLineEdit, QPushButton, QCheckBox, QMessageBox
)
from theme_manager import load_theme, apply_theme
from user_management_window import UserManagementWindow

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Окно входа")
        self.setGeometry(200, 200, 400, 300)
        self._build_ui()
        # Применение темы при инициализации
        theme = load_theme()
        apply_theme(self, theme)

    def _build_ui(self):
        main_layout = QVBoxLayout()

        ad_group = QGroupBox("Active Directory")
        ad_layout = QGridLayout()

        ad_layout.addWidget(QLabel("Домен:"), 0, 0)
        self.ad_domain_input = QLineEdit()
        ad_layout.addWidget(self.ad_domain_input, 0, 1)

        ad_layout.addWidget(QLabel("Администратор:"), 1, 0)
        self.ad_admin_input = QLineEdit()
        ad_layout.addWidget(self.ad_admin_input, 1, 1)

        ad_layout.addWidget(QLabel("Пароль:"), 2, 0)
        self.ad_password_input = QLineEdit()
        self.ad_password_input.setEchoMode(QLineEdit.Password)
        ad_layout.addWidget(self.ad_password_input, 2, 1)

        self.ad_ssl_checkbox = QCheckBox("Использовать SSL для подключения к AD")
        self.ad_ssl_checkbox.setChecked(True)
        ad_layout.addWidget(self.ad_ssl_checkbox, 3, 0, 1, 2)

        ad_group.setLayout(ad_layout)

        postgres_group = QGroupBox("PostgreSQL")
        postgres_layout = QGridLayout()

        postgres_layout.addWidget(QLabel("Сервер:"), 0, 0)
        self.postgres_host_input = QLineEdit()
        self.postgres_host_input.setPlaceholderText("например: localhost или 192.168.1.10")
        postgres_layout.addWidget(self.postgres_host_input, 0, 1)

        postgres_layout.addWidget(QLabel("Администратор:"), 1, 0)
        self.postgres_admin_input = QLineEdit()
        postgres_layout.addWidget(self.postgres_admin_input, 1, 1)

        postgres_layout.addWidget(QLabel("Пароль:"), 2, 0)
        self.postgres_password_input = QLineEdit()
        self.postgres_password_input.setEchoMode(QLineEdit.Password)
        postgres_layout.addWidget(self.postgres_password_input, 2, 1)

        postgres_group.setLayout(postgres_layout)

        self.continue_button = QPushButton("Продолжить")
        self.continue_button.clicked.connect(self.on_continue)

        main_layout.addWidget(ad_group)
        main_layout.addWidget(postgres_group)
        main_layout.addWidget(self.continue_button)
        self.setLayout(main_layout)

    def on_continue(self):
        logging.info("Начало обработки кнопки 'Продолжить'")
        ad_domain = self.ad_domain_input.text().strip()
        ad_admin_user = self.ad_admin_input.text().strip() + "@" + ad_domain
        ad_admin_password = self.ad_password_input.text().strip()
        postgres_host = self.postgres_host_input.text().strip()
        postgres_admin_user = self.postgres_admin_input.text().strip()
        postgres_admin_password = self.postgres_password_input.text().strip()
        ad_use_ssl = self.ad_ssl_checkbox.isChecked()

        logging.info(f"Параметры: домен={ad_domain}, пользователь={ad_admin_user}, хост PostgreSQL={postgres_host}, "
                     f"пользователь PostgreSQL={postgres_admin_user}, SSL={ad_use_ssl}")

        if not all([ad_domain, ad_admin_user, ad_admin_password, postgres_host, postgres_admin_user,
                    postgres_admin_password]):
            logging.warning("Не все поля заполнены")
            QMessageBox.warning(self, "Ошибка", "Заполните все поля")
            return

        try:
            logging.info("Попытка подключения к Active Directory")
            server = ldap3.Server(ad_domain, use_ssl=ad_use_ssl, get_info=ldap3.NONE)
            connection = ldap3.Connection(server, user=ad_admin_user, password=ad_admin_password, auto_bind=True)
            connection.unbind()
            logging.info("Успешное подключение к Active Directory")
        except Exception as error:
            logging.error("Ошибка подключения к Active Directory", exc_info=error)
            QMessageBox.critical(self, "Ошибка AD", f"Не удалось подключиться к Active Directory:\n{error}")
            return

        try:
            logging.info("Попытка подключения к PostgreSQL")
            test_connection = psycopg2.connect(
                host=postgres_host,
                user=postgres_admin_user,
                password=postgres_admin_password,
                dbname="postgres",
                connect_timeout=5
            )
            test_connection.close()
            logging.info("Успешное подключение к PostgreSQL")
        except Exception as error:
            logging.error("Ошибка подключения к PostgreSQL", exc_info=error)
            QMessageBox.critical(self, "Ошибка PostgreSQL", f"Не удалось подключиться к PostgreSQL:\n{error}")
            return

        logging.info("Открытие главного окна")
        self.open_main_window(ad_domain, ad_admin_user, ad_admin_password,
                              postgres_host, postgres_admin_user, postgres_admin_password, ad_use_ssl)

    def open_main_window(self, ad_domain: str, ad_admin_user: str, ad_admin_password: str,
                         postgres_host: str, postgres_admin_user: str, postgres_admin_password: str, ad_use_ssl: bool):
        try:
            logging.info("Создание экземпляра UserManagementWindow")
            self.main_window = UserManagementWindow(ad_domain, ad_admin_user, ad_admin_password,
                                                    postgres_host, postgres_admin_user, postgres_admin_password,
                                                    ad_use_ssl)
            logging.info("Вызов метода show() для UserManagementWindow")
            self.main_window.show()
            logging.info("Закрытие LoginWindow")
            self.close()
        except Exception as error:
            logging.error("Ошибка при открытии главного окна", exc_info=error)
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть главное окно:\n{error}")