import sys
import logging
import re
import os
from typing import List

from PyQt5.QtWidgets import (
    QApplication, QWidget, QGridLayout, QLabel, QLineEdit,
    QComboBox, QPushButton, QMessageBox, QGroupBox, QListWidget,
    QListWidgetItem, QCheckBox, QHBoxLayout, QVBoxLayout
)
from PyQt5.QtCore import Qt

import ldap3
from ldap3.core.exceptions import LDAPException
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv

# -------------------------
# load .env (connect.env next to this file)
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, "connect.env")
load_dotenv(dotenv_path=ENV_PATH)

# -------------------------
# logging
# -------------------------
logging.basicConfig(
    filename=os.path.join(BASE_DIR, 'user_creator.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_excepthook(exc_type, exc_value, exc_traceback):
    """Log uncaught exceptions to the file."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logging.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = log_excepthook

# -------------------------
# environment / helpers
# -------------------------
AD_SERVER = os.getenv("AD_SERVER")
AD_USER = os.getenv("AD_USER")
AD_PASS = os.getenv("AD_PASS")
AD_BASE_DN = os.getenv("AD_BASE_DN")
AD_DOMAIN = os.getenv("AD_DOMAIN")

# PostgreSQL admin creds (hidden from UI). PG_SERVERS is a CSV; we take the first by default.
PG_SERVERS = [s.strip() for s in os.getenv("PG_SERVERS", "localhost").split(",") if s.strip()]
PG_ADMIN_USER = os.getenv("PG_ADMIN_USER", "postgres")
PG_ADMIN_PASS = os.getenv("PG_ADMIN_PASS", "")

# quick env validation
_missing = []
for var in ("AD_SERVER", "AD_USER", "AD_PASS", "AD_BASE_DN", "AD_DOMAIN"):
    if not os.getenv(var):
        _missing.append(var)
if _missing:
    logging.error("Missing required environment variables: %s", ", ".join(_missing))
    # If script started from GUI-less mode it's ok; if launched normally, show message and exit.
    print(f"ERROR: Missing environment variables: {', '.join(_missing)}. Check {ENV_PATH}")
    # We don't exit here to allow import for unit tests, but user should be aware.

def ad_conn(use_ssl=True, timeout=10):
    """
    Create and return a bound ldap3.Connection.
    - use_ssl=True -> LDAPS (636)
    - Caller should handle LDAPException
    """
    server = ldap3.Server(AD_SERVER, use_ssl=use_ssl, get_info=ldap3.NONE, connect_timeout=timeout)
    conn = ldap3.Connection(server, user=AD_USER, password=AD_PASS, auto_bind=True)
    return conn

def get_pg_connection(host: str):
    """
    Returns psycopg2 connection to 'postgres' DB using admin creds from .env.
    """
    return psycopg2.connect(host=host, user=PG_ADMIN_USER, password=PG_ADMIN_PASS, dbname="postgres", connect_timeout=5)

def validate_password(password: str):
    """Password policy: min 8, at least one upper, lower, digit."""
    if len(password) < 8:
        return False, "Пароль должен содержать минимум 8 символов"
    if not re.search(r"[A-Z]", password):
        return False, "Пароль должен содержать минимум одну заглавную букву"
    if not re.search(r"[a-z]", password):
        return False, "Пароль должен содержать минимум одну строчную букву"
    if not re.search(r"[0-9]", password):
        return False, "Пароль должен содержать минимум одну цифру"
    return True, ""

# -------------------------
# Main window
# -------------------------
class UserCreator(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Управление пользователями")
        self.setGeometry(100, 100, 880, 520)
        self._build_ui()
        # initial load
        try:
            self.load_ous()
        except Exception as e:
            logging.error("Initial load_ous failed", exc_info=e)

    def _build_ui(self):
        main_layout = QVBoxLayout()  # главный вертикальный layout

        # --- AD group ---
        ad_group = QGroupBox("Active Directory")
        ad_layout = QVBoxLayout()  # вертикально: сначала "Информация", потом "Параметры учетной записи"

        # --- Информация из AD ---
        info_group = QGroupBox(AD_DOMAIN)
        info_layout = QHBoxLayout()  # два блока рядом

        # --- Учётные данные ---
        credentials_group = QGroupBox("Учётные данные")
        credentials_layout = QGridLayout()

        credentials_layout.addWidget(QLabel("Подразделение (OU):"), 0, 0)
        self.ou_combo = QComboBox()
        self.ou_combo.currentIndexChanged.connect(self.load_users_in_ou)
        credentials_layout.addWidget(self.ou_combo, 0, 1)

        credentials_layout.addWidget(QLabel("Отображаемое имя (CN):"), 1, 0)
        self.display_name_edit = QLineEdit()
        credentials_layout.addWidget(self.display_name_edit, 1, 1)

        credentials_layout.addWidget(QLabel("Логин:"), 2, 0)
        self.login_edit = QLineEdit()
        credentials_layout.addWidget(self.login_edit, 2, 1)

        credentials_layout.addWidget(QLabel("Пароль:"), 3, 0)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        credentials_layout.addWidget(self.password_edit, 3, 1)

        credentials_layout.addWidget(QLabel("Подтверждение:"), 4, 0)
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        credentials_layout.addWidget(self.confirm_edit, 4, 1)

        credentials_group.setLayout(credentials_layout)
        info_layout.addWidget(credentials_group, 1)  # растягивается на 50% ширины

        # --- Учётные записи ---
        accounts_group = QGroupBox("Учётные записи")
        accounts_layout = QVBoxLayout()
        accounts_layout.addWidget(QLabel("Пользователи (OU):"))
        self.users_list = QListWidget()
        self.users_list.itemSelectionChanged.connect(self.on_user_selected)
        accounts_layout.addWidget(self.users_list)
        accounts_group.setLayout(accounts_layout)
        info_layout.addWidget(accounts_group, 1)  # 50% ширины

        info_group.setLayout(info_layout)
        ad_layout.addWidget(info_group)

        # --- Параметры учётной записи AD ---
        opts_group = QGroupBox("Параметры учётной записи")
        opts_layout = QHBoxLayout()
        self.chk_must_change = QCheckBox("Требовать смену пароля")
        self.chk_cannot_change = QCheckBox("Запретить смену пароля")
        self.chk_pwd_never_expire = QCheckBox("Срок действия пароля не ограничен")
        opts_layout.addWidget(self.chk_must_change)
        opts_layout.addWidget(self.chk_cannot_change)
        opts_layout.addWidget(self.chk_pwd_never_expire)
        opts_group.setLayout(opts_layout)
        ad_layout.addWidget(opts_group)

        ad_group.setLayout(ad_layout)
        main_layout.addWidget(ad_group)

        # --- action buttons ---
        btn_layout = QHBoxLayout()
        self.btn_create = QPushButton("Создать")
        self.btn_create.clicked.connect(self.on_create_clicked)
        btn_layout.addWidget(self.btn_create)

        self.btn_modify = QPushButton("Изменить пароль")
        self.btn_modify.clicked.connect(self.on_modify_clicked)
        btn_layout.addWidget(self.btn_modify)

        self.btn_delete = QPushButton("Удалить")
        self.btn_delete.clicked.connect(self.on_delete_clicked)
        btn_layout.addWidget(self.btn_delete)

        main_layout.addLayout(btn_layout)

        # --- status bar ---
        self.status_label = QLabel("Готово к работе")
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)

        self.setLayout(main_layout)

    # -------------------------
    # AD loaders
    # -------------------------
    def load_ous(self):
        """Load OUs into the combo from AD."""
        try:
            self.status_label.setText("Загрузка подразделений (OU)...")
            QApplication.processEvents()
            conn = ad_conn(use_ssl=True)
            conn.search(
                search_base=AD_BASE_DN,
                search_filter='(objectClass=organizationalUnit)',
                search_scope=ldap3.SUBTREE,
                attributes=['distinguishedName', 'name']
            )
            self.ou_combo.clear()
            for entry in conn.entries:
                # entry.name may be 'name' attribute
                name = str(entry.name) if 'name' in entry else str(entry.entry_dn)
                dn = str(entry.distinguishedName) if 'distinguishedName' in entry else str(entry.entry_dn)
                self.ou_combo.addItem(name, dn)
            self.status_label.setText(f"Загружено {len(conn.entries)} OU")
            logging.info("Loaded %d OUs from AD", len(conn.entries))
            conn.unbind()
            # initial load users in selected OU
            QApplication.processEvents()
            self.load_users_in_ou()
        except LDAPException as e:
            logging.error("LDAP error while loading OUs", exc_info=e)
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить подразделения из AD:\n{e}")
            self.status_label.setText("Ошибка загрузки OU")
        except Exception as e:
            logging.error("Unexpected error in load_ous", exc_info=e)
            QMessageBox.critical(self, "Ошибка", f"Ошибка при загрузке OU:\n{e}")
            self.status_label.setText("Ошибка загрузки OU")

    def load_users_in_ou(self):
        """Populate the users_list for the selected OU."""
        try:
            ou_dn = self.ou_combo.currentData()
            if not ou_dn:
                return
            self.status_label.setText("Загрузка пользователей OU...")
            QApplication.processEvents()
            conn = ad_conn(use_ssl=True)
            filt = '(&(objectCategory=person)(objectClass=user))'
            conn.search(
                search_base=ou_dn,
                search_filter=filt,
                search_scope=ldap3.SUBTREE,
                attributes=['sAMAccountName', 'cn', 'displayName']
            )
            self.users_list.clear()
            for e in conn.entries:
                login = str(e.sAMAccountName) if 'sAMAccountName' in e else ''
                cn = str(e.cn) if 'cn' in e else ''
                disp = str(e.displayName) if 'displayName' in e else cn
                text = f"{login} — {disp}"
                item = QListWidgetItem(text)
                item.setData(Qt.UserRole, {'login': login, 'cn': cn, 'displayName': disp})
                self.users_list.addItem(item)
            self.status_label.setText(f"Пользователей: {self.users_list.count()}")
            logging.info("Loaded %d users from OU %s", len(conn.entries), ou_dn)
            conn.unbind()
        except LDAPException as e:
            logging.error("LDAP error while loading users in OU", exc_info=e)
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить пользователей OU:\n{e}")
            self.status_label.setText("Ошибка загрузки пользователей")
        except Exception as e:
            logging.error("Unexpected error in load_users_in_ou", exc_info=e)
            QMessageBox.critical(self, "Ошибка", f"Ошибка при загрузке пользователей OU:\n{e}")
            self.status_label.setText("Ошибка загрузки пользователей")

    def on_user_selected(self):
        """When a user is picked from the list, populate login/displayName."""
        items = self.users_list.selectedItems()
        if not items:
            return
        data = items[0].data(Qt.UserRole) or {}
        self.login_edit.setText(data.get('login', ''))
        self.display_name_edit.setText(data.get('displayName', data.get('cn', '')))

    # -------------------------
    # Button callbacks
    # -------------------------
    def on_create_clicked(self):
        try:
            self.create_user()
        except Exception as e:
            logging.error("Create user failed", exc_info=e)
            QMessageBox.critical(self, "Ошибка", str(e))

    def on_modify_clicked(self):
        try:
            self.modify_password()
        except Exception as e:
            logging.error("Modify password failed", exc_info=e)
            QMessageBox.critical(self, "Ошибка", str(e))

    def on_delete_clicked(self):
        try:
            self.delete_user()
        except Exception as e:
            logging.error("Delete user failed", exc_info=e)
            QMessageBox.critical(self, "Ошибка", str(e))

    # -------------------------
    # Core actions (AD + PG technical)
    # -------------------------
    def create_user(self):
        login = self.login_edit.text().strip()
        display_name = self.display_name_edit.text().strip()
        password = self.password_edit.text()
        confirm = self.confirm_edit.text()
        ou_dn = self.ou_combo.currentData()
        host = PG_SERVERS[0] if PG_SERVERS else "localhost"

        if not all([login, display_name, password, confirm, ou_dn]):
            raise ValueError("Заполните логин, отображаемое имя, пароль и выберите OU")
        if password != confirm:
            raise ValueError("Пароли не совпадают")
        ok, msg = validate_password(password)
        if not ok:
            raise ValueError(msg)

        ad_exists = self.check_ad_user_exists(login)
        pg_exists = self.check_pg_user_exists(login, host)

        if ad_exists or pg_exists:
            choice = QMessageBox.question(
                self, "Пользователь уже существует",
                "Пользователь найден в AD или PostgreSQL.\nУдалить его?",
                QMessageBox.Yes | QMessageBox.No
            )
            if choice == QMessageBox.Yes:
                self.delete_user()
            return

        # Create in AD
        self.create_ad_user(display_name, login, password, ou_dn)

        # Create in PostgreSQL (technical)
        try:
            self.create_pg_user(login, password, host, roles=[])
        except Exception as e:
            # If PG creation fails, AD user exists already; consider rolling back AD creation?
            logging.error("PG create failed after AD create, leaving AD user intact", exc_info=e)
            QMessageBox.warning(self, "Предупреждение", f"Пользователь создан в AD, но не в PostgreSQL:\n{e}")
            self.status_label.setText(f"Пользователь {login} создан в AD, ошибка в PG")
            return

        QMessageBox.information(self, "Успех", "Пользователь создан в AD и PostgreSQL")
        self.status_label.setText(f"Пользователь {login} создан")
        logging.info("User created: %s", login)
        self.load_users_in_ou()

    def modify_password(self):
        login = self.login_edit.text().strip()
        password = self.password_edit.text()
        confirm = self.confirm_edit.text()
        host = PG_SERVERS[0] if PG_SERVERS else "localhost"

        if not all([login, password, confirm]):
            raise ValueError("Заполните логин и новый пароль")
        if password != confirm:
            raise ValueError("Пароли не совпадают")
        ok, msg = validate_password(password)
        if not ok:
            raise ValueError(msg)

        # AD
        if self.check_ad_user_exists(login):
            self.update_ad_password(login, password)

        # PG
        if self.check_pg_user_exists(login, host):
            self.update_pg_password(login, password, host)

        QMessageBox.information(self, "Успех", "Пароль изменён в AD и PostgreSQL (если существовал)")
        self.status_label.setText(f"Пароль для {login} изменён")
        logging.info("Password modified for user: %s", login)

    def delete_user(self):
        login = self.login_edit.text().strip()
        host = PG_SERVERS[0] if PG_SERVERS else "localhost"
        if not login:
            raise ValueError("Введите логин для удаления")

        # AD
        if self.check_ad_user_exists(login):
            self.remove_ad_user(login)

        # PG
        if self.check_pg_user_exists(login, host):
            self.remove_pg_user(login, host)

        QMessageBox.information(self, "Успех", "Пользователь удалён из AD и PostgreSQL (если существовал)")
        self.status_label.setText(f"Пользователь {login} удалён")
        logging.info("User deleted: %s", login)
        self.load_users_in_ou()

    # -------------------------
    # AD operations
    # -------------------------
    def check_ad_user_exists(self, login: str) -> bool:
        try:
            conn = ad_conn(use_ssl=True)
            conn.search(
                search_base=AD_BASE_DN,
                search_filter=f"(sAMAccountName={login})",
                search_scope=ldap3.SUBTREE,
                attributes=['distinguishedName']
            )
            exists = len(conn.entries) > 0
            conn.unbind()
            return exists
        except LDAPException:
            raise

    def create_ad_user(self, display_name: str, login: str, password: str, ou_dn: str):
        conn = ad_conn(use_ssl=True)
        user_dn = f"CN={display_name},{ou_dn}"
        # userAccountControl bits
        UAC_NORMAL = 0x0200
        UAC_PWD_NO_EXPIRE = 0x10000
        UAC_PASSWD_CANT_CHANGE = 0x0040
        uac = UAC_NORMAL
        if self.chk_pwd_never_expire.isChecked():
            uac |= UAC_PWD_NO_EXPIRE
        if self.chk_cannot_change.isChecked():
            uac |= UAC_PASSWD_CANT_CHANGE

        attributes = {
            'cn': display_name,
            'displayName': display_name,
            'sAMAccountName': login,
            'userPrincipalName': f"{login}@{AD_DOMAIN}",
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        }

        if not conn.add(user_dn, attributes=attributes):
            err = conn.result
            conn.unbind()
            raise RuntimeError(f"AD add failed: {err}")

        # set password (requires LDAPS)
        if not conn.extend.microsoft.modify_password(user_dn, password):
            err = conn.result
            conn.unbind()
            raise RuntimeError(f"AD set password failed: {err}")

        # must change at first logon
        if self.chk_must_change.isChecked():
            if not conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [0])]}):
                err = conn.result
                conn.unbind()
                raise RuntimeError(f"AD set pwdLastSet=0 failed: {err}")

        # set userAccountControl
        if not conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [uac])]}):
            err = conn.result
            conn.unbind()
            raise RuntimeError(f"AD set UAC failed: {err}")

        conn.unbind()
        logging.info("AD user created: %s", user_dn)

    def update_ad_password(self, login: str, password: str):
        conn = ad_conn(use_ssl=True)
        conn.search(AD_BASE_DN, f"(sAMAccountName={login})", ldap3.SUBTREE, attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            raise RuntimeError("Пользователь не найден в AD")
        user_dn = conn.entries[0].entry_dn
        if not conn.extend.microsoft.modify_password(user_dn, password):
            err = conn.result
            conn.unbind()
            raise RuntimeError(f"AD change password failed: {err}")
        conn.unbind()
        logging.info("AD password updated for %s", login)

    def remove_ad_user(self, login: str):
        conn = ad_conn(use_ssl=True)
        conn.search(AD_BASE_DN, f"(sAMAccountName={login})", ldap3.SUBTREE, attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            logging.info("AD user not found for deletion: %s", login)
            return
        user_dn = conn.entries[0].entry_dn
        if not conn.delete(user_dn):
            err = conn.result
            conn.unbind()
            raise RuntimeError(f"AD delete failed: {err}")
        conn.unbind()
        logging.info("AD user deleted: %s", login)

    # -------------------------
    # PostgreSQL operations (technical, no UI)
    # -------------------------
    def check_pg_user_exists(self, login: str, host: str) -> bool:
        try:
            with get_pg_connection(host) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (login,))
                    return cur.fetchone() is not None
        except Exception as e:
            logging.error("Error checking PG user exists", exc_info=e)
            # bubble up? For safety return False so operations continue; but we log
            return False

    def create_pg_user(self, login: str, password: str, host: str, roles: List[str]):
        """
        Create role in PostgreSQL and optionally grant group-roles.
        Requires PG_ADMIN_USER to have CREATEROLE or be SUPERUSER.
        """
        try:
            with get_pg_connection(host) as conn:
                with conn.cursor() as cur:
                    cur.execute(sql.SQL('CREATE USER {} WITH PASSWORD %s').format(sql.Identifier(login)), (password,))
                    for r in roles:
                        cur.execute(sql.SQL('GRANT {} TO {}').format(sql.Identifier(r), sql.Identifier(login)))
                conn.commit()
            logging.info("PG user created: %s on %s", login, host)
        except psycopg2.Error as e:
            logging.error("PostgreSQL create user error", exc_info=e)
            raise

    def update_pg_password(self, login: str, password: str, host: str):
        try:
            with get_pg_connection(host) as conn:
                with conn.cursor() as cur:
                    cur.execute(sql.SQL('ALTER USER {} WITH PASSWORD %s').format(sql.Identifier(login)), (password,))
                conn.commit()
            logging.info("PG password updated for %s on %s", login, host)
        except Exception as e:
            logging.error("PostgreSQL update password error", exc_info=e)
            raise

    def remove_pg_user(self, login: str, host: str):
        try:
            with get_pg_connection(host) as conn:
                with conn.cursor() as cur:
                    cur.execute(sql.SQL('DROP USER IF EXISTS {}').format(sql.Identifier(login)))
                conn.commit()
            logging.info("PG user removed: %s on %s", login, host)
        except Exception as e:
            logging.error("PostgreSQL remove user error", exc_info=e)
            raise

# -------------------------
# app entry
# -------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = UserCreator()
    win.show()
    sys.exit(app.exec_())
