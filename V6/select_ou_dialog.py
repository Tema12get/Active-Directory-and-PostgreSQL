import logging
import ldap3
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QDialog, QTreeView, QDialogButtonBox, QVBoxLayout, QAbstractItemView
from theme_manager import load_theme, apply_theme

class SelectOUDialog(QDialog):
    def __init__(self, ad_connection, base_dn, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Выбор подразделения (OU)")
        self.setGeometry(200, 200, 600, 400)

        # Применение темы при инициализации
        theme = load_theme()
        apply_theme(self, theme)

        layout = QVBoxLayout()

        # Модель для дерева (с заголовком "Существующие подразделения")
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["Существующие подразделения"])

        # QTreeView с блокировкой редактирования
        self.tree_view = QTreeView()
        self.tree_view.setModel(self.model)
        self.tree_view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tree_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree_view.clicked.connect(self.on_item_clicked)
        self.tree_view.doubleClicked.connect(self.accept)
        layout.addWidget(self.tree_view)

        # Кнопки OK/Cancel
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

        # Загрузка дерева OU
        self.load_ou_tree(ad_connection, base_dn)

        self.selected_dn = None

    def load_ou_tree(self, connection, base_dn, parent_item=None):
        try:
            connection.search(
                search_base=base_dn,
                search_filter='(objectClass=organizationalUnit)',
                search_scope=ldap3.LEVEL,
                attributes=['distinguishedName', 'name']
            )
            if parent_item is None:
                parent_item = self.model.invisibleRootItem()

            for entry in connection.entries:
                name = str(entry.name) if 'name' in entry else str(entry.entry_dn)
                dn = str(entry.distinguishedName) if 'distinguishedName' in entry else str(entry.entry_dn)

                item = QStandardItem(name)
                item.setData(dn, Qt.UserRole)
                parent_item.appendRow(item)

                self.load_ou_tree(connection, dn, item)
        except ldap3.core.exceptions.LDAPException as e:
            logging.error(f"Ошибка загрузки OU: {e}")

    def on_item_clicked(self, index):
        item = self.model.itemFromIndex(index)
        self.selected_dn = item.data(Qt.UserRole)
        if item.hasChildren():
            self.tree_view.expand(index)

    def get_selected_dn(self):
        return self.selected_dn