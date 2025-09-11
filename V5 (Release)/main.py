import sys
import re
import logging
import ldap3
import psycopg2
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QGridLayout, QGroupBox, QListWidget, QCheckBox, QHBoxLayout, QMessageBox, QComboBox, QListWidgetItem
)
from PyQt5.QtCore import Qt
from ldap3.core.exceptions import LDAPException
from psycopg2 import sql
from typing import List
import os

# Настройка логирования для записи в файл
log_dir = os.path.join(os.path.dirname(sys.executable), "logs")
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, "app.log")),
        logging.StreamHandler()
    ]
)

def validate_password(password: str) -> tuple[bool, str]:
    """
    Проверяет пароль на соответствие политике безопасности.
    Политика: минимум 8 символов, хотя бы одна заглавная буква, строчная буква и цифра.

    Args:
        password (str): Проверяемый пароль.

    Returns:
        tuple[bool, str]: Кортеж (валидность пароля, сообщение об ошибке).
    """
    if len(password) < 8:
        return False, "Пароль должен содержать минимум 8 символов"
    if not re.search(r"[A-Z]", password):
        return False, "Пароль должен содержать минимум одну заглавную букву"
    if not re.search(r"[a-z]", password):
        return False, "Пароль должен содержать минимум одну строчную букву"
    if not re.search(r"[0-9]", password):
        return False, "Пароль должен содержать минимум одну цифру"
    return True, ""

# --- Класс главного окна для управления пользователями ---
class UserManagementWindow(QWidget):
    """
    Главное окно приложения для управления пользователями в Active Directory и PostgreSQL.
    Предоставляет интерфейс для создания, изменения и удаления пользователей, а также
    отображения организационных единиц (OU) и пользователей PostgreSQL.
    """
    def __init__(self, ad_domain: str, ad_admin_user: str, ad_admin_password: str,
                 pg_host: str, pg_admin_user: str, pg_admin_password: str, ad_use_ssl: bool = True):
        """
        Инициализирует главное окно с параметрами подключения к AD и PostgreSQL.

        Args:
            ad_domain (str): Домен Active Directory (например, example.com).
            ad_admin_user (str): Имя администратора AD (в формате user@domain).
            ad_admin_password (str): Пароль администратора AD.
            pg_host (str): Хост PostgreSQL сервера.
            pg_admin_user (str): Имя администратора PostgreSQL.
            pg_admin_password (str): Пароль администратора PostgreSQL.
            ad_use_ssl (bool): Флаг использования SSL для подключения к AD (по умолчанию True).
        """
        super().__init__()
        self.setWindowTitle("Управление пользователями")
        self.setGeometry(100, 100, 880, 520)

        # Сохранение параметров подключения
        self.ad_domain = ad_domain
        self.ad_admin_user = ad_admin_user
        self.ad_admin_password = ad_admin_password
        self.pg_host = pg_host
        self.pg_admin_user = pg_admin_user
        self.pg_admin_password = pg_admin_password
        self.ad_use_ssl = ad_use_ssl
        self.current_db = None

        # Формирование BaseDN из домена AD
        self.ad_base_dn = ",".join([f"DC={part}" for part in self.ad_domain.split(".")])

        self._build_ui()
        try:
            self.load_ad_organizational_units()
            self.load_postgres_databases()
            self.load_postgres_users()
        except Exception as error:
            logging.error("Ошибка начальной загрузки данных", exc_info=error)

    def connect_to_ad(self, use_ssl: bool = None) -> ldap3.Connection:
        if use_ssl is None:
            use_ssl = self.ad_use_ssl
        try:
            server = ldap3.Server(self.ad_domain, use_ssl=use_ssl, get_info=ldap3.ALL)
            connection = ldap3.Connection(server, user=self.ad_admin_user, password=self.ad_admin_password, auto_bind=True)
            return connection
        except Exception as error:
            QMessageBox.critical(self, "Ошибка AD", f"Не удалось подключиться к Active Directory:\n{error}")
            return None

    def connect_to_postgres(self, dbname: str = "postgres") -> psycopg2.extensions.connection:
        try:
            connection = psycopg2.connect(
                host=self.pg_host,
                user=self.pg_admin_user,
                password=self.pg_admin_password,
                dbname=dbname,
                connect_timeout=5
            )
            return connection
        except Exception as error:
            logging.error("Ошибка подключения к PostgreSQL", exc_info=error)
            QMessageBox.critical(self, "Ошибка PostgreSQL", f"Не удалось подключиться к PostgreSQL:\n{error}")
            return None

    def _build_ui(self):
        main_layout = QVBoxLayout()

        # --- Группа Active Directory ---
        ad_group = QGroupBox("Active Directory")
        ad_layout = QVBoxLayout()

        ad_info_group = QGroupBox(self.ad_domain)
        ad_info_layout = QHBoxLayout()

        credentials_group = QGroupBox("Учётные данные")
        credentials_layout = QGridLayout()

        credentials_layout.addWidget(QLabel("Подразделение (OU):"), 0, 0)
        self.ou_selector = QComboBox()
        self.ou_selector.currentIndexChanged.connect(self.load_ad_users_in_ou)
        credentials_layout.addWidget(self.ou_selector, 0, 1)

        credentials_layout.addWidget(QLabel("Отображаемое имя (CN):"), 1, 0)
        self.display_name_input = QLineEdit()
        credentials_layout.addWidget(self.display_name_input, 1, 1)

        credentials_layout.addWidget(QLabel("Логин:"), 2, 0)
        self.login_input = QLineEdit()
        credentials_layout.addWidget(self.login_input, 2, 1)

        credentials_layout.addWidget(QLabel("Пароль:"), 3, 0)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        credentials_layout.addWidget(self.password_input, 3, 1)

        credentials_layout.addWidget(QLabel("Подтверждение:"), 4, 0)
        self.password_confirm_input = QLineEdit()
        self.password_confirm_input.setEchoMode(QLineEdit.Password)
        credentials_layout.addWidget(self.password_confirm_input, 4, 1)

        credentials_group.setLayout(credentials_layout)
        ad_info_layout.addWidget(credentials_group, 1)

        ad_accounts_group = QGroupBox("Учётные записи")
        ad_accounts_layout = QVBoxLayout()
        ad_accounts_layout.addWidget(QLabel("Пользователи (OU):"))
        self.ad_users_list = QListWidget()
        self.ad_users_list.itemSelectionChanged.connect(self.on_ad_user_selected)
        ad_accounts_layout.addWidget(self.ad_users_list)
        ad_accounts_group.setLayout(ad_accounts_layout)
        ad_info_layout.addWidget(ad_accounts_group, 1)

        ad_info_group.setLayout(ad_info_layout)
        ad_layout.addWidget(ad_info_group)

        ad_options_group = QGroupBox("Параметры учётной записи")
        ad_options_layout = QHBoxLayout()
        self.require_password_change = QCheckBox("Требовать смену пароля")
        self.prevent_password_change = QCheckBox("Запретить смену пароля")
        self.password_never_expires = QCheckBox("Срок действия пароля не ограничен")
        ad_options_layout.addWidget(self.require_password_change)
        ad_options_layout.addWidget(self.prevent_password_change)
        ad_options_layout.addWidget(self.password_never_expires)
        ad_options_group.setLayout(ad_options_layout)
        ad_layout.addWidget(ad_options_group)

        ad_group.setLayout(ad_layout)
        main_layout.addWidget(ad_group)

        postgres_group = QGroupBox("PostgreSQL")
        postgres_layout = QVBoxLayout()

        db_selection_group = QGroupBox("База данных")
        db_selection_layout = QHBoxLayout()
        self.database_selector = QComboBox()
        self.database_selector.currentIndexChanged.connect(self.on_database_changed)
        db_selection_layout.addWidget(self.database_selector, 1)
        db_selection_group.setLayout(db_selection_layout)

        postgres_users_group = QGroupBox("Пользователи PostgreSQL")
        postgres_users_layout = QVBoxLayout()
        self.postgres_users_list = QListWidget()
        self.postgres_users_list.itemSelectionChanged.connect(self.on_postgres_user_selected)
        postgres_users_layout.addWidget(self.postgres_users_list)
        postgres_users_group.setLayout(postgres_users_layout)

        postgres_layout.addWidget(db_selection_group)
        postgres_layout.addWidget(postgres_users_group)
        postgres_group.setLayout(postgres_layout)
        main_layout.addWidget(postgres_group)

        action_buttons_layout = QHBoxLayout()
        self.create_button = QPushButton("Создать")
        self.create_button.clicked.connect(self.on_create_clicked)
        action_buttons_layout.addWidget(self.create_button)

        self.modify_button = QPushButton("Изменить пароль")
        self.modify_button.clicked.connect(self.on_modify_clicked)
        action_buttons_layout.addWidget(self.modify_button)

        self.delete_button = QPushButton("Удалить")
        self.delete_button.clicked.connect(self.on_delete_clicked)
        action_buttons_layout.addWidget(self.delete_button)

        main_layout.addLayout(action_buttons_layout)

        self.status_bar = QLabel("Готово к работе")
        self.status_bar.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_bar)

        self.setLayout(main_layout)

    def load_postgres_databases(self):
        try:
            connection = self.connect_to_postgres("postgres")
            if not connection:
                return
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
                    databases = [row[0] for row in cursor.fetchall()]
            self.database_selector.clear()
            self.database_selector.addItems(databases)
            if databases:
                self.current_db = databases[0]
            self.status_bar.setText(f"Доступные базы: {len(databases)}")
        except Exception as error:
            logging.error("Ошибка при загрузке баз PostgreSQL", exc_info=error)
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить базы данных:\n{error}")
            self.status_bar.setText("Ошибка загрузки баз")

    def on_database_changed(self):
        self.current_db = self.database_selector.currentText()
        logging.info("Выбрана база данных: %s", self.current_db)
        self.load_postgres_users()

    def load_postgres_users(self):
        try:
            self.status_bar.setText("Загрузка пользователей PostgreSQL...")
            QApplication.processEvents()
            with self.connect_to_postgres(self.current_db) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT rolname FROM pg_roles WHERE rolcanlogin = true;")
                    users = [row[0] for row in cursor.fetchall()]
            self.postgres_users_list.clear()
            for user in users:
                item = QListWidgetItem(user)
                item.setData(Qt.UserRole, {'login': user})
                self.postgres_users_list.addItem(item)
            self.status_bar.setText(f"Пользователей PostgreSQL: {self.postgres_users_list.count()}")
            logging.info("Загружено %d пользователей PostgreSQL из базы %s", len(users), self.current_db)
        except Exception as error:
            logging.error("Ошибка при загрузке пользователей PostgreSQL", exc_info=error)
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить пользователей PostgreSQL:\n{error}")
            self.status_bar.setText("Ошибка загрузки пользователей PostgreSQL")

    def on_postgres_user_selected(self):
        selected_items = self.postgres_users_list.selectedItems()
        if not selected_items:
            return
        user_data = selected_items[0].data(Qt.UserRole) or {}
        self.login_input.setText(user_data.get('login', ''))

    def load_ad_organizational_units(self):
        try:
            self.status_bar.setText("Загрузка подразделений (OU)...")
            QApplication.processEvents()
            connection = self.connect_to_ad()
            connection.search(
                search_base=self.ad_base_dn,
                search_filter='(objectClass=organizationalUnit)',
                search_scope=ldap3.SUBTREE,
                attributes=['distinguishedName', 'name']
            )
            self.ou_selector.clear()
            for entry in connection.entries:
                name = str(entry.name) if 'name' in entry else str(entry.entry_dn)
                distinguished_name = str(entry.distinguishedName) if 'distinguishedName' in entry else str(entry.entry_dn)
                self.ou_selector.addItem(name, distinguished_name)
            self.status_bar.setText(f"Загружено {len(connection.entries)} OU")
            logging.info("Загружено %d OU из Active Directory", len(connection.entries))
            connection.unbind()
            QApplication.processEvents()
            self.load_ad_users_in_ou()
        except LDAPException as error:
            logging.error("Ошибка LDAP при загрузке OU", exc_info=error)
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить подразделения из AD:\n{error}")
            self.status_bar.setText("Ошибка загрузки OU")
        except Exception as error:
            logging.error("Неожиданная ошибка при загрузке OU", exc_info=error)
            QMessageBox.critical(self, "Ошибка", f"Ошибка при загрузке OU:\n{error}")
            self.status_bar.setText("Ошибка загрузки OU")

    def load_ad_users_in_ou(self):
        try:
            ou_distinguished_name = self.ou_selector.currentData()
            if not ou_distinguished_name:
                return
            self.status_bar.setText("Загрузка пользователей OU...")
            QApplication.processEvents()
            connection = self.connect_to_ad()
            filter_query = '(&(objectCategory=person)(objectClass=user))'
            connection.search(
                search_base=ou_distinguished_name,
                search_filter=filter_query,
                search_scope=ldap3.SUBTREE,
                attributes=['sAMAccountName', 'cn', 'displayName']
            )
            self.ad_users_list.clear()
            for entry in connection.entries:
                login = str(entry.sAMAccountName) if 'sAMAccountName' in entry else ''
                common_name = str(entry.cn) if 'cn' in entry else ''
                display_name = str(entry.displayName) if 'displayName' in entry else common_name
                text = f"{login} — {display_name}"
                item = QListWidgetItem(text)
                item.setData(Qt.UserRole, {'login': login, 'cn': common_name, 'displayName': display_name})
                self.ad_users_list.addItem(item)
            self.status_bar.setText(f"Пользователей: {self.ad_users_list.count()}")
            logging.info("Загружено %d пользователей из OU %s", len(connection.entries), ou_distinguished_name)
            connection.unbind()
        except LDAPException as error:
            logging.error("Ошибка LDAP при загрузке пользователей OU", exc_info=error)
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить пользователей OU:\n{error}")
            self.status_bar.setText("Ошибка загрузки пользователей")
        except Exception as error:
            logging.error("Неожиданная ошибка при загрузке пользователей OU", exc_info=error)
            QMessageBox.critical(self, "Ошибка", f"Ошибка при загрузке пользователей OU:\n{error}")
            self.status_bar.setText("Ошибка загрузки пользователей")

    def on_ad_user_selected(self):
        selected_items = self.ad_users_list.selectedItems()
        if not selected_items:
            return
        user_data = selected_items[0].data(Qt.UserRole) or {}
        self.login_input.setText(user_data.get('login', ''))
        self.display_name_input.setText(user_data.get('displayName', user_data.get('cn', '')))

    def on_create_clicked(self):
        try:
            self.create_user()
        except Exception as error:
            logging.error("Ошибка создания пользователя", exc_info=error)
            QMessageBox.critical(self, "Ошибка", str(error))

    def on_modify_clicked(self):
        try:
            self.modify_password()
        except Exception as error:
            logging.error("Ошибка изменения пароля", exc_info=error)
            QMessageBox.critical(self, "Ошибка", str(error))

    def on_delete_clicked(self):
        try:
            self.delete_user()
        except Exception as error:
            logging.error("Ошибка удаления пользователя", exc_info=error)
            QMessageBox.critical(self, "Ошибка", str(error))

    def create_user(self):
        login = self.login_input.text().strip()
        display_name = self.display_name_input.text().strip()
        password = self.password_input.text()
        confirm_password = self.password_confirm_input.text()
        ou_distinguished_name = self.ou_selector.currentData()

        if not all([login, display_name, password, confirm_password, ou_distinguished_name]):
            raise ValueError("Заполните логин, отображаемое имя, пароль и выберите OU")
        if password != confirm_password:
            raise ValueError("Пароли не совпадают")
        is_valid, error_message = validate_password(password)
        if not is_valid:
            raise ValueError(error_message)

        ad_user_exists = self.check_ad_user_exists(login)
        postgres_user_exists = self.check_postgres_user_exists(login, self.pg_host)

        if ad_user_exists or postgres_user_exists:
            choice = QMessageBox.question(
                self, "Пользователь уже существует",
                "Пользователь найден в AD или PostgreSQL.\nУдалить его?",
                QMessageBox.Yes | QMessageBox.No
            )
            if choice == QMessageBox.Yes:
                self.delete_user()
            return

        self.create_ad_user(display_name, login, password, ou_distinguished_name)

        try:
            self.create_postgres_user(login, password, self.pg_host, roles=[])
        except Exception as error:
            logging.error("Ошибка создания пользователя в PostgreSQL после создания в AD", exc_info=error)
            QMessageBox.warning(self, "Предупреждение", f"Пользователь создан в AD, но не в PostgreSQL:\n{error}")
            self.status_bar.setText(f"Пользователь {login} создан в AD, ошибка в PostgreSQL")
            return

        QMessageBox.information(self, "Успех", "Пользователь создан в AD и PostgreSQL")
        self.status_bar.setText(f"Пользователь {login} создан")
        logging.info("Пользователь создан: %s", login)
        self.load_ad_users_in_ou()
        self.load_postgres_users()

    def modify_password(self):
        login = self.login_input.text().strip()
        password = self.password_input.text()
        confirm_password = self.password_confirm_input.text()

        if not all([login, password, confirm_password]):
            raise ValueError("Заполните логин и новый пароль")
        if password != confirm_password:
            raise ValueError("Пароли не совпадают")
        is_valid, error_message = validate_password(password)
        if not is_valid:
            raise ValueError(error_message)

        if self.check_ad_user_exists(login):
            self.update_ad_password(login, password)

        if self.check_postgres_user_exists(login, self.pg_host):
            self.update_postgres_password(login, password, self.pg_host)

        QMessageBox.information(self, "Успех", "Пароль изменён в AD и PostgreSQL (если существовал)")
        self.status_bar.setText(f"Пароль для {login} изменён")
        logging.info("Пароль изменён для пользователя: %s", login)
        self.load_postgres_users()

    def delete_user(self):
        login = self.login_input.text().strip()
        if not login:
            raise ValueError("Введите логин для удаления")

        if self.check_ad_user_exists(login):
            self.remove_ad_user(login)

        if self.check_postgres_user_exists(login, self.pg_host):
            self.remove_postgres_user(login, self.pg_host)

        QMessageBox.information(self, "Успех", "Пользователь удалён из AD и PostgreSQL (если существовал)")
        self.status_bar.setText(f"Пользователь {login} удалён")
        logging.info("Пользователь удалён: %s", login)
        self.load_ad_users_in_ou()
        self.load_postgres_users()

    def check_ad_user_exists(self, login: str) -> bool:
        try:
            connection = self.connect_to_ad()
            connection.search(
                search_base=self.ad_base_dn,
                search_filter=f"(sAMAccountName={login})",
                search_scope=ldap3.SUBTREE,
                attributes=['distinguishedName']
            )
            exists = len(connection.entries) > 0
            connection.unbind()
            return exists
        except LDAPException as error:
            raise error

    def create_ad_user(self, display_name: str, login: str, password: str, ou_distinguished_name: str):
        connection = self.connect_to_ad()
        user_dn = f"CN={display_name},{ou_distinguished_name}"
        UAC_NORMAL = 0x0200
        UAC_PWD_NO_EXPIRE = 0x10000
        UAC_PASSWD_CANT_CHANGE = 0x0040
        uac = UAC_NORMAL
        if self.password_never_expires.isChecked():
            uac |= UAC_PWD_NO_EXPIRE
        if self.prevent_password_change.isChecked():
            uac |= UAC_PASSWD_CANT_CHANGE

        attributes = {
            'cn': display_name,
            'displayName': display_name,
            'sAMAccountName': login,
            'userPrincipalName': f"{login}@{self.ad_domain}",
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        }

        if not connection.add(user_dn, attributes=attributes):
            error = connection.result
            connection.unbind()
            raise RuntimeError(f"Ошибка добавления в AD: {error}")

        if not self.ad_use_ssl:
            logging.warning("Установка пароля в AD без SSL может не поддерживаться. Попытка продолжить.")

        try:
            if not connection.extend.microsoft.modify_password(user_dn, password):
                error = connection.result
                try:
                    connection.delete(user_dn)
                    logging.info("Созданный пользователь %s удалён из AD из-за ошибки установки пароля", user_dn)
                except Exception as delete_error:
                    logging.error("Ошибка при удалении пользователя после неудачной установки пароля",
                                  exc_info=delete_error)
                connection.unbind()
                raise RuntimeError(f"Ошибка установки пароля в AD: {error}")
        except Exception as password_error:
            try:
                connection.delete(user_dn)
                logging.info("Созданный пользователь %s удалён из AD из-за ошибки установки пароля", user_dn)
            except Exception as delete_error:
                logging.error("Ошибка при удалении пользователя после неудачной установки пароля",
                              exc_info=delete_error)
            connection.unbind()
            raise RuntimeError(f"Ошибка установки пароля в AD: {password_error}")

        try:
            if self.require_password_change.isChecked():
                if not connection.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [0])]}):

                    error = connection.result
                    connection.unbind()
                    raise RuntimeError(f"Ошибка установки pwdLastSet=0 в AD: {error}")
        except Exception as pwdlastset_error:
            try:
                connection.delete(user_dn)
                logging.info("Созданный пользователь %s удалён из AD из-за ошибки установки pwdLastSet", user_dn)
            except Exception as delete_error:
                logging.error("Ошибка при удалении пользователя после неудачной установки pwdLastSet",
                              exc_info=delete_error)
            connection.unbind()
            raise RuntimeError(f"Ошибка установки pwdLastSet в AD: {pwdlastset_error}")

        try:
            if not connection.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [uac])]}):

                error = connection.result
                connection.unbind()
                raise RuntimeError(f"Ошибка установки UAC в AD: {error}")
        except Exception as uac_error:
            try:
                connection.delete(user_dn)
                logging.info("Созданный пользователь %s удалён из AD из-за ошибки установки UAC", user_dn)
            except Exception as delete_error:
                logging.error("Ошибка при удалении пользователя после неудачной установки UAC", exc_info=delete_error)
            connection.unbind()
            raise RuntimeError(f"Ошибка установки UAC в AD: {uac_error}")

        connection.unbind()
        logging.info("Пользователь AD создан: %s", user_dn)

    def update_ad_password(self, login: str, password: str):
        connection = self.connect_to_ad()
        connection.search(self.ad_base_dn, f"(sAMAccountName={login})", ldap3.SUBTREE, attributes=['distinguishedName'])
        if not connection.entries:
            connection.unbind()
            raise RuntimeError("Пользователь не найден в AD")
        user_dn = connection.entries[0].entry_dn
        if not self.ad_use_ssl:
            logging.warning("Изменение пароля в AD без SSL может не поддерживаться. Рекомендуется использовать SSL.")
        if not connection.extend.microsoft.modify_password(user_dn, password):
            error = connection.result
            connection.unbind()
            raise RuntimeError(f"Ошибка изменения пароля в AD: {error}")
        connection.unbind()
        logging.info("Пароль AD обновлён для %s", login)

    def remove_ad_user(self, login: str):
        connection = self.connect_to_ad()
        connection.search(self.ad_base_dn, f"(sAMAccountName={login})", ldap3.SUBTREE, attributes=['distinguishedName'])
        if not connection.entries:
            connection.unbind()
            logging.info("Пользователь AD не найден для удаления: %s", login)
            return
        user_dn = connection.entries[0].entry_dn
        if not connection.delete(user_dn):
            error = connection.result
            connection.unbind()
            raise RuntimeError(f"Ошибка удаления в AD: {error}")
        connection.unbind()
        logging.info("Пользователь AD удалён: %s", login)

    def check_postgres_user_exists(self, login: str, host: str) -> bool:
        try:
            with self.connect_to_postgres(self.current_db) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (login,))
                    return cursor.fetchone() is not None
        except Exception as error:
            logging.error("Ошибка проверки существования пользователя PostgreSQL", exc_info=error)
            return False

    def create_postgres_user(self, login: str, password: str, host: str, roles: List[str]):
        try:
            with self.connect_to_postgres(self.current_db) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(sql.SQL('CREATE USER {} WITH PASSWORD %s').format(sql.Identifier(login)), (password,))
                    for role in roles:
                        cursor.execute(sql.SQL('GRANT {} TO {}').format(sql.Identifier(role), sql.Identifier(login)))
                connection.commit()
            logging.info("Пользователь PostgreSQL создан: %s на %s", login, host)
        except psycopg2.Error as error:
            logging.error("Ошибка создания пользователя PostgreSQL", exc_info=error)
            raise

    def update_postgres_password(self, login: str, password: str, host: str):
        try:
            with self.connect_to_postgres(self.current_db) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(sql.SQL('ALTER USER {} WITH PASSWORD %s').format(sql.Identifier(login)), (password,))
                connection.commit()
            logging.info("Пароль PostgreSQL обновлён для %s на %s", login, host)
        except Exception as error:
            logging.error("Ошибка обновления пароля PostgreSQL", exc_info=error)
            raise

    def remove_postgres_user(self, login: str, host: str):
        try:
            with self.connect_to_postgres(self.current_db) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(sql.SQL('DROP USER IF EXISTS {}').format(sql.Identifier(login)))
                connection.commit()
            logging.info("Пользователь PostgreSQL удалён: %s на %s", login, host)
        except Exception as error:
            logging.error("Ошибка удаления пользователя PostgreSQL", exc_info=error)
            raise

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Окно входа")
        self.setGeometry(200, 200, 400, 300)
        self._build_ui()

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
        ad_domain = self.ad_domain_input.text().strip()
        ad_admin_user = self.ad_admin_input.text().strip() + "@" + ad_domain
        ad_admin_password = self.ad_password_input.text().strip()
        postgres_host = self.postgres_host_input.text().strip()
        postgres_admin_user = self.postgres_admin_input.text().strip()
        postgres_admin_password = self.postgres_password_input.text().strip()
        ad_use_ssl = self.ad_ssl_checkbox.isChecked()

        if not all([ad_domain, ad_admin_user, ad_admin_password, postgres_host, postgres_admin_user, postgres_admin_password]):
            QMessageBox.warning(self, "Ошибка", "Заполните все поля")
            return

        try:
            server = ldap3.Server(ad_domain, use_ssl=ad_use_ssl, get_info=ldap3.NONE)
            connection = ldap3.Connection(server, user=ad_admin_user, password=ad_admin_password, auto_bind=True)
            connection.unbind()
        except Exception as error:
            QMessageBox.critical(self, "Ошибка AD", f"Не удалось подключиться к Active Directory:\n{error}")
            return

        try:
            test_connection = psycopg2.connect(
                host=postgres_host,
                user=postgres_admin_user,
                password=postgres_admin_password,
                dbname="postgres",
                connect_timeout=5
            )
            test_connection.close()
        except Exception as error:
            QMessageBox.critical(self, "Ошибка PostgreSQL", f"Не удалось подключиться к PostgreSQL:\n{error}")
            return

        self.open_main_window(ad_domain, ad_admin_user, ad_admin_password,
                              postgres_host, postgres_admin_user, postgres_admin_password, ad_use_ssl)

    def open_main_window(self, ad_domain: str, ad_admin_user: str, ad_admin_password: str,
                         postgres_host: str, postgres_admin_user: str, postgres_admin_password: str, ad_use_ssl: bool):
        self.main_window = UserManagementWindow(ad_domain, ad_admin_user, ad_admin_password,
                                                postgres_host, postgres_admin_user, postgres_admin_password, ad_use_ssl)
        self.main_window.show()
        self.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec_())

