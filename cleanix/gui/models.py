"""Qt models for Power mode: the cleaner list and the scan item table."""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from PySide6.QtCore import QAbstractListModel, QAbstractTableModel, QModelIndex, Qt

from cleanix.config import Config
from cleanix.core import catalog
from cleanix.core.models import CleanableItem, ItemKind, ScanResult, item_key, item_target
from cleanix.core.utils import human_size
from cleanix.gui import elevation

# Custom roles for CleanerListModel.
IdRole = Qt.ItemDataRole.UserRole + 1
DescriptionRole = Qt.ItemDataRole.UserRole + 2
BadgeRole = Qt.ItemDataRole.UserRole + 3

COLUMNS = ["", "Cleaner", "Description", "Size", "Admin", "Type"]

# Tooltip for the short "Admin" badge and column text.
ADMIN_TOOLTIP = "Needs administrator permission"


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
    def __init__(self, config: Config, parent=None, *, exclude=()) -> None:
        """``exclude``: cleaner ids never listed (e.g. the registry
        detectors, which live on their own tab)."""
        super().__init__(parent)
        skip = frozenset(exclude or ())
        self._infos: List[catalog.CleanerInfo] = [
            i for i in catalog.list_cleaners(config) if i.id not in skip]
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
        if role == DescriptionRole:
            return info.description
        if role == Qt.ItemDataRole.ToolTipRole:
            if info.requires_root:
                return f"{info.description}\n{ADMIN_TOOLTIP}"
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


def is_bulk_selectable(item: CleanableItem) -> bool:
    """Whether a bulk action (Select all, quick-selects) may tick the item.
    Registry entries are only ever ticked one by one or by their own group."""
    return not item.report_only and item.kind is not ItemKind.REGISTRY


def size_text(items) -> str:
    """Size cell text: registry entries have no size, shown as a dash."""
    items = list(items)
    if items and all(i.kind is ItemKind.REGISTRY for i in items):
        return "-"
    return human_size(sum(i.size for i in items))


def _type_label(item: CleanableItem) -> str:
    if item.report_only:
        return "Review"
    if item.kind is ItemKind.COMMAND:
        return "Command"
    return "Registry" if item.kind is ItemKind.REGISTRY else "Path"


def _target_text(item: CleanableItem) -> str:
    return item_target(item)


class ItemTableModel(QAbstractTableModel):
    def __init__(self, parent=None, *, allow_admin_items: bool = False) -> None:
        super().__init__(parent)
        self._allow_admin = allow_admin_items
        self._items: List[CleanableItem] = []
        self._names: Dict[str, str] = {}
        self._checked: List[bool] = []
        # id(item) -> why the elevated helper would always refuse it.
        self._problems: Dict[int, str] = {}

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

    def set_result(self, result: Optional[ScanResult],
                   preselect: Optional[Callable[[CleanableItem], bool]] = None) -> None:
        self.beginResetModel()
        self._items = []
        self._names = {}
        if result is not None:
            for rep in result.reports:
                self._names[rep.cleaner_id] = rep.name
                self._items.extend(rep.items)
        self._problems = elevation.admin_problems(self._items) if self._allow_admin else {}
        # Checked only when the caller's preselect rule says so (never for
        # report-only rows); with no rule everything starts unchecked.
        self._checked = [
            (bool(preselect(i)) and self._checkable(i)) if preselect else False
            for i in self._items]
        self.endResetModel()

    @property
    def allow_admin_items(self) -> bool:
        return self._allow_admin

    def set_allow_admin_items(self, allow: bool) -> None:
        self.beginResetModel()
        self._allow_admin = bool(allow)
        self._problems = elevation.admin_problems(self._items) if self._allow_admin else {}
        self._checked = [c and self._checkable(i)
                         for c, i in zip(self._checked, self._items)]
        self.endResetModel()

    def _checkable(self, item: CleanableItem) -> bool:
        if item.report_only:
            return False
        if not item.requires_root:
            return True
        return self._allow_admin and id(item) not in self._problems

    def admin_problem(self, item: CleanableItem) -> Optional[str]:
        """Why this administrator item can never be cleaned from the GUI."""
        return self._problems.get(id(item))

    def is_checked(self, row: int) -> bool:
        return self._checked[row] and self._checkable(self._items[row])

    def remove_keys(self, keys) -> None:
        keys = set(keys)
        self.beginResetModel()
        kept = [(i, c) for i, c in zip(self._items, self._checked)
                if item_key(i) not in keys]
        self._items = [i for i, _ in kept]
        self._checked = [c for _, c in kept]
        self.endResetModel()

    def item_at(self, row: int) -> CleanableItem:
        return self._items[row]

    def cleaner_name(self, item: CleanableItem) -> str:
        return self._names.get(item.cleaner_id, item.cleaner_id)

    def set_checked(self, row: int, checked: bool) -> bool:
        if not (0 <= row < len(self._items)) or not self._checkable(self._items[row]):
            return False
        self._checked[row] = bool(checked)
        idx = self.index(row, 0)
        self.dataChanged.emit(idx, idx, [Qt.ItemDataRole.CheckStateRole])
        return True

    def checked_items(self) -> List[CleanableItem]:
        return [i for i, c in zip(self._items, self._checked)
                if c and self._checkable(i)]

    def flags(self, index):  # noqa: D401
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        f = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == 0 and self._checkable(self._items[index.row()]):
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
            if col == 0 and self._checkable(item):
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
            problem = self._problems.get(id(item))
            if col == 0:
                return problem
            if col == 4:
                if not item.requires_root:
                    return None
                return f"{ADMIN_TOOLTIP}. {problem}" if problem else ADMIN_TOOLTIP
            if col == 2:
                return f"{item.description}\n{_target_text(item)}"
            return self._text(item, col) if col != 3 else size_text([item])
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
            return size_text([item])
        if col == 4:
            return "Admin" if item.requires_root else ""
        return _type_label(item)
