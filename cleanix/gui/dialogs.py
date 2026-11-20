"""Plain-text dialogs for confirmations and results.

Unlike ``QMessageBox`` (whose text format is "auto", so a file name such as
``<b>x</b>`` may be rendered as rich text), every text here is shown as
plain text: labels use ``Qt.PlainText`` and long listings sit in a read-only,
scrollable ``QPlainTextEdit``. No colours are set: everything follows the
palette. Escape cancels; Enter never triggers a destructive button (the
safe button is the default one).
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
    QVBoxLayout, QWidget,
)


def plain_label(text: str = "", name: str = "") -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    label.setText(text)
    if name:
        label.setAccessibleName(name)
    return label


def listing(text: str, name: str) -> QPlainTextEdit:
    box = QPlainTextEdit()
    box.setReadOnly(True)
    box.setPlainText(text)
    box.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
    box.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    box.setAccessibleName(name)
    box.setTabChangesFocus(True)
    return box


class TextDialog(QDialog):
    """A headline, a few summary lines, a scrollable listing and buttons.

    With ``accept_text`` there are two buttons: ``accept_button`` (never
    the default button) and ``cancel_button`` (default). Without it there
    is one ``close_button``. With ``phrase`` a ``phrase_edit`` is shown and
    ``accept_button`` stays disabled until its text equals ``phrase``
    EXACTLY (no stripping, no case folding); :meth:`phrase_ok` says the
    same for callers that double-check after ``exec``.
    """

    def __init__(self, title: str, headline: str, body: str, *,
                 summary: str = "", note: str = "",
                 accept_text: Optional[str] = None,
                 phrase: Optional[str] = None, phrase_label: str = "",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(760, 520)
        self._phrase = phrase
        layout = QVBoxLayout(self)
        self.headline = plain_label(headline, "Headline")
        font = self.headline.font()
        font.setBold(True)
        self.headline.setFont(font)
        layout.addWidget(self.headline)
        self.summary = plain_label(summary, "Summary")
        self.summary.setVisible(bool(summary))
        layout.addWidget(self.summary)
        self.body = listing(body, "Details")
        self.body.setVisible(bool(body))
        layout.addWidget(self.body, 1)
        self.note = plain_label(note, "Note")
        self.note.setVisible(bool(note))
        layout.addWidget(self.note)

        self.phrase_edit: Optional[QLineEdit] = None
        if phrase is not None:
            self.phrase_prompt = plain_label(phrase_label, "Confirmation phrase prompt")
            layout.addWidget(self.phrase_prompt)
            self.phrase_edit = QLineEdit()
            self.phrase_edit.setAccessibleName(f"Type {phrase} to confirm")
            self.phrase_edit.setPlaceholderText(phrase)
            self.phrase_prompt.setBuddy(self.phrase_edit)
            layout.addWidget(self.phrase_edit)

        bar = QHBoxLayout()
        bar.addStretch(1)
        self.accept_button: Optional[QPushButton] = None
        self.cancel_button: Optional[QPushButton] = None
        self.close_button: Optional[QPushButton] = None
        if accept_text is not None:
            self.accept_button = QPushButton(accept_text)
            self.accept_button.setAccessibleName(accept_text)
            self.accept_button.setAutoDefault(False)
            self.accept_button.setDefault(False)
            self.cancel_button = QPushButton("Cancel")
            self.cancel_button.setAccessibleName("Cancel")
            self.cancel_button.setDefault(True)
            bar.addWidget(self.accept_button)
            bar.addWidget(self.cancel_button)
            self.accept_button.clicked.connect(self._on_accept)
            self.cancel_button.clicked.connect(self.reject)
        else:
            self.close_button = QPushButton("Close")
            self.close_button.setAccessibleName("Close")
            self.close_button.setDefault(True)
            bar.addWidget(self.close_button)
            self.close_button.clicked.connect(self.accept)
        layout.addLayout(bar)

        # Keyboard order: the details first, then the phrase, then buttons.
        chain = [w for w in (self.body, self.phrase_edit, self.accept_button,
                             self.cancel_button, self.close_button) if w is not None]
        for a, b in zip(chain, chain[1:]):
            QWidget.setTabOrder(a, b)

        if self.phrase_edit is not None:
            self.phrase_edit.textChanged.connect(self._update)
            self.phrase_edit.setFocus()
        elif self.cancel_button is not None:
            self.cancel_button.setFocus()
        elif self.close_button is not None:
            self.close_button.setFocus()
        self._update()

    def phrase_ok(self) -> bool:
        if self._phrase is None:
            return True
        return self.phrase_edit is not None and self.phrase_edit.text() == self._phrase

    def _update(self, *_a) -> None:
        if self.accept_button is not None:
            self.accept_button.setEnabled(self.phrase_ok())

    def _on_accept(self) -> None:
        if self.phrase_ok():
            self.accept()

    def done(self, r) -> None:  # noqa: D401 - Qt API
        """Defence in depth: whatever path accepts the dialog, it is
        Rejected unless the required phrase is typed exactly."""
        accepted = int(QDialog.DialogCode.Accepted)
        if int(r) == accepted and not self.phrase_ok():
            r = QDialog.DialogCode.Rejected
        super().done(int(r))

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt API
        # Enter/Return neither acts nor cancels while the phrase field or the
        # Act button has focus: Act is pressed on purpose (click or Space),
        # and the default Cancel button only answers Escape / Enter elsewhere.
        if (event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
                and self.focusWidget() is not None
                and self.focusWidget() in (self.phrase_edit, self.accept_button)):
            event.accept()
            return
        super().keyPressEvent(event)
