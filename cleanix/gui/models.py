"""Qt models for Power mode: the cleaner list and the scan item table."""

from __future__ import annotations

from typing import Dict, List, Optional

from PySide6.QtCore import QAbstractListModel, QAbstractTableModel, QModelIndex, Qt

from cleanix.config import Config
from cleanix.core import catalog
from cleanix.core.models import CleanableItem, ItemKind, ScanResult
from cleanix.core.utils import human_size

# Custom roles for CleanerListModel.
IdRole = Qt.ItemDataRole.UserRole + 1
DescriptionRole = Qt.ItemDataRole.UserRole + 2
BadgeRole = Qt.ItemDataRole.UserRole + 3

COLUMNS = ["", "Cleaner", "Description", "Size", "Admin", "Type"]


def badge_for(info: catalog.CleanerInfo) -> str:
    badges = []
    if info.requires_root:
        badges.append("Admin")
    if info.category == "review":
        badges.append("Review only")
    if not info.default_enabled:
        badges.append("Opt-in")
    return ", ".join(badges)


class CleanerListModel(QAbstractListModel):
    def __init__(self, config: Config, parent=None) -> None:
        super().__init__(parent)
        self._infos: List[catalog.CleanerInfo] = catalog.list_cleaners(config)
        self._checked: Dict[str, bool] = {
            i.id: i.default_enabled for i in self._infos
        }

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._infos)

    def info_at(self, row: int) -> catalog.CleanerInfo:
        return self._infos[row]

    def flags(self, index):  # noqa: D401
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return (Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsUserCheckable)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._infos)):
            return None
        info = self._infos[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return info.name
        if role == IdRole:
            return info.id
        if role in (DescriptionRole, Qt.ItemDataRole.ToolTipRole):
            return info.description
        if role == BadgeRole:
            return badge_for(info)
        if role == Qt.ItemDataRole.CheckStateRole:
            return (Qt.CheckState.Checked if self._checked[info.id]
                    else Qt.CheckState.Unchecked)
        return None

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole) -> bool:  # noqa: N802
        if (not index.isValid() or role != Qt.ItemDataRole.CheckStateRole
                or not (0 <= index.row() < len(self._infos))):
            return False
        on = value in (Qt.CheckState.Checked, Qt.CheckState.Checked.value, 2, True)
        self._checked[self._infos[index.row()].id] = bool(on)
        self.dataChanged.emit(index, index, [role])
        return True

    def enabled_ids(self) -> List[str]:
        return [i.id for i in self._infos if self._checked[i.id]]


def _type_label(item: CleanableItem) -> str:
    if item.report_only:
        return "Review"
    return "Command" if item.kind is ItemKind.COMMAND else "Path"


def _target_text(item: CleanableItem) -> str:
    if item.kind is ItemKind.COMMAND:
        return " ".join(item.command or [])
    return item.path or ""


class ItemTableModel(QAbstractTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._items: List[CleanableItem] = []
        self._names: Dict[str, str] = {}
        self._checked: List[bool] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._items)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if (orientation == Qt.Orientation.Horizontal
                and role == Qt.ItemDataRole.DisplayRole
                and 0 <= section < len(COLUMNS)):
            return COLUMNS[section]
        return None

    def set_result(self, result: Optional[ScanResult]) -> None:
        self.beginResetModel()
        self._items = []
        self._names = {}
        if result is not None:
            for rep in result.reports:
                self._names[rep.cleaner_id] = rep.name
                self._items.extend(rep.items)
        # Items start checked unless report-only; opt-in handled by cleaner list.
        self._checked = [not i.report_only for i in self._items]
        self.endResetModel()

    def item_at(self, row: int) -> CleanableItem:
        return self._items[row]

    def cleaner_name(self, item: CleanableItem) -> str:
        return self._names.get(item.cleaner_id, item.cleaner_id)

    def set_checked(self, row: int, checked: bool) -> bool:
        if not (0 <= row < len(self._items)) or self._items[row].report_only:
            return False
        self._checked[row] = bool(checked)
        idx = self.index(row, 0)
        self.dataChanged.emit(idx, idx, [Qt.ItemDataRole.CheckStateRole])
        return True

    def checked_items(self) -> List[CleanableItem]:
        return [i for i, c in zip(self._items, self._checked)
                if c and not i.report_only]

    def flags(self, index):  # noqa: D401
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        f = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == 0 and not self._items[index.row()].report_only:
            f |= Qt.ItemFlag.ItemIsUserCheckable
        return f

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole) -> bool:  # noqa: N802
        if (not index.isValid() or index.column() != 0
                or role != Qt.ItemDataRole.CheckStateRole):
            return False
        on = value in (Qt.CheckState.Checked, Qt.CheckState.Checked.value, 2, True)
        return self.set_checked(index.row(), on)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._items)):
            return None
        item = self._items[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.CheckStateRole:
            if col == 0 and not item.report_only:
                return (Qt.CheckState.Checked if self._checked[index.row()]
                        else Qt.CheckState.Unchecked)
            return None
        if role == Qt.ItemDataRole.UserRole:
            # Raw sort keys so "10 MB" sorts after "900 KB".
            if col == 3:
                return item.size
            if col == 4:
                return int(item.requires_root)
            if col == 0:
                return int(self._checked[index.row()])
            return self._text(item, col).lower()
        if role == Qt.ItemDataRole.ToolTipRole:
            if col == 0:
                return None
            if col == 2:
                return f"{item.description}\n{_target_text(item)}"
            return self._text(item, col) if col != 3 else human_size(item.size)
        if role == Qt.ItemDataRole.TextAlignmentRole and col == 3:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.DisplayRole:
            return self._text(item, col)
        return None

    def _text(self, item: CleanableItem, col: int) -> str:
        if col == 0:
            return ""
        if col == 1:
            return self.cleaner_name(item)
        if col == 2:
            return item.description
        if col == 3:
            return human_size(item.size)
        if col == 4:
            return "Admin" if item.requires_root else ""
        return _type_label(item)
