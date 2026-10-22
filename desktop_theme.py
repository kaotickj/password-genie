"""Black and blue desktop theme."""
from PyQt6.QtGui import QFont, QPalette, QColor


def apply_theme(app):
    app.setStyle('Fusion')
    app.setFont(QFont('DejaVu Sans', 10))
    palette = QPalette()
    for role, color in {
        QPalette.ColorRole.Window: '#080c12', QPalette.ColorRole.WindowText: '#e4f0ff',
        QPalette.ColorRole.Base: '#080d16', QPalette.ColorRole.Text: '#e4f0ff',
        QPalette.ColorRole.Button: '#175eaa', QPalette.ColorRole.ButtonText: '#ffffff',
        QPalette.ColorRole.Highlight: '#2875c7', QPalette.ColorRole.HighlightedText: '#ffffff',
        QPalette.ColorRole.PlaceholderText: '#8299b5',
    }.items():
        palette.setColor(role, QColor(color))
    app.setPalette(palette)
    app.setStyleSheet('''
        QMainWindow, QDialog, QMessageBox { background: #080c12; }
        QWidget { color: #e4f0ff; font-size: 13px; }
        QWidget#canvas, QWidget#body, QScrollArea { background: #080c12; border: none; }
        QLabel { background: transparent; }
        QLabel#eyebrow { color: #7fc5ff; font-size: 11px; font-weight: 700; letter-spacing: 2px; }
        QLabel#title { color: #f4f8ff; font-size: 30px; font-weight: 700; }
        QLabel#subtitle, QLabel#hint { color: #91a7c2; font-size: 12px; }
        QLabel#fieldLabel { color: #bed3ed; font-size: 12px; font-weight: 600; }
        QLabel#status { background: #102842; color: #8dceff; border: 1px solid #28527c;
            border-radius: 13px; padding: 6px 14px; font-size: 11px; font-weight: 700; }
        QGroupBox { background: #101925; border: 1px solid #22364f; border-radius: 12px;
            margin-top: 14px; padding: 14px 18px 12px; font-size: 15px; font-weight: 600; }
        QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left;
            left: 18px; padding: 0 8px; color: #9ad3ff; }
        QLineEdit, QComboBox, QTextEdit { background: #080f19; border: 1px solid #2a405d;
            border-radius: 7px; padding: 7px 11px; color: #edf5ff; selection-background-color: #256db6; }
        QLineEdit:focus, QComboBox:focus, QTextEdit:focus { border: 1px solid #86caff; }
        QLineEdit:disabled, QComboBox:disabled { color: #647b96; border-color: #233248; background: #0c1420; }
        QLineEdit#result { color: #9bd6ff; font-family: monospace; font-size: 16px;
            border-color: #305f88; background: #071320; padding: 10px; }
        QComboBox { padding-right: 28px; }
        QComboBox::drop-down { border: none; width: 26px; }
        QComboBox QAbstractItemView { background: #101e30; color: #edf5ff;
            selection-background-color: #175eaa; border: 1px solid #4276a4; padding: 5px; }
        QPushButton { background: #175eaa; border: 1px solid #2975c0; border-radius: 7px;
            color: #ffffff; padding: 8px 16px; font-weight: 600; }
        QPushButton:hover { background: #2174c5; border-color: #86caff; }
        QPushButton:pressed { background: #104880; }
        QPushButton:focus { border: 2px solid #9bd6ff; padding: 7px 15px; }
        QPushButton[secondary="true"] { background: #152a42; color: #a6d9ff; border-color: #315375; }
        QPushButton[secondary="true"]:hover { background: #204267; border-color: #79bfff; }
        QCheckBox { color: #bed3ed; spacing: 8px; background: transparent; }
        QCheckBox::indicator { width: 17px; height: 17px; border: 1px solid #456789;
            border-radius: 4px; background: #080f19; }
        QCheckBox::indicator:checked { background: #79c4ff; border: 4px solid #245d91; }
        QCheckBox::indicator:focus { border-color: #c0e5ff; }
        QMenuBar { background: #080c12; color: #91a7c2; border-bottom: 1px solid #1c2d42; }
        QMenuBar::item { padding: 7px 12px; background: transparent; }
        QMenuBar::item:selected, QMenu::item:selected { background: #1c4e7e; color: #ffffff; }
        QMenu { background: #101925; border: 1px solid #315375; padding: 5px; }
        QMenu::item { padding: 8px 22px; }
        QScrollBar:vertical { background: #080c12; width: 9px; }
        QScrollBar::handle:vertical { background: #2c4c70; border-radius: 4px; min-height: 30px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        QToolTip { background: #163554; color: #e4f0ff; border: 1px solid #79c4ff; padding: 5px; }
    ''')
