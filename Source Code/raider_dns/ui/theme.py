"""Consistent application-wide Qt stylesheets for Raider DNS 0.1.3."""

DARK_QSS = r'''
* { font-family: "Segoe UI", "Inter", sans-serif; font-size: 13px; }
QMainWindow, QWidget#Root { background: #0b1019; color: #e7edf7; }
QWidget { color: #e7edf7; }
QFrame#Sidebar { background: #0e1521; border-right: 1px solid #202c3e; }
QFrame#TopBar { background: #0b1019; border-bottom: 1px solid #202c3e; }
QFrame[panel="true"] { background: #111a28; border: 1px solid #233044; border-radius: 15px; }
QFrame[panel="hero"] { background: #111d2c; border: 1px solid #254052; border-radius: 18px; }
QFrame[connectionModeCard="true"] { border: 1px solid #233044; border-radius: 12px; }
QFrame[connectionModeCard="selected"] { background: #111d2c; border: 1px solid #29d6c4; border-radius: 12px; }
QLabel { background: transparent; }
QLabel#Brand { font-size: 19px; font-weight: 750; color: #f4f8ff; }
QLabel#BrandMark { color: #29d6c4; font-size: 24px; font-weight: 900; }
QLabel#PageTitle { font-size: 23px; font-weight: 750; color: #f4f7fc; }
QLabel#Subtitle, QLabel#Muted { color: #a1aec1; font-size: 12px; }
QLabel#Heading { font-size: 15px; font-weight: 700; color: #edf4ff; }
QLabel#Metric { font-size: 22px; font-weight: 750; color: #f3f7ff; }
QLabel#Accent { color: #36dcc7; font-weight: 700; }
QLabel#TinyCaps { color: #9baac0; font-size: 10px; font-weight: 800; letter-spacing: 1px; }
QLabel#StatusPill { background: #15352f; color: #5ce2bd; border: 1px solid #235747; border-radius: 10px; padding: 6px 10px; font-weight: 700; }
QLabel#WarningPill { background: #3a2c19; color: #ffca79; border: 1px solid #614a25; border-radius: 10px; padding: 6px 10px; font-weight: 700; }
QLabel#ErrorPill { background: #3d2028; color: #ff9caa; border: 1px solid #673441; border-radius: 10px; padding: 6px 10px; font-weight: 700; }
QPushButton { background: #1b2738; color: #e7edf7; border: 1px solid #2b3b51; border-radius: 9px; padding: 9px 13px; font-weight: 650; }
QPushButton:hover { background: #24364b; border-color: #3a526d; }
QPushButton:pressed { background: #182536; }
QPushButton:disabled { color: #78879b; background: #18212e; border-color: #263344; }
QPushButton#PrimaryButton { background: #24bda9; color: #071a1c; border: 1px solid #24bda9; font-weight: 800; }
QPushButton#PrimaryButton:hover { background: #40d9c5; border-color: #40d9c5; }
QPushButton#DangerButton { background: #3d2028; color: #ffc4cb; border-color: #633441; }
QPushButton#NavButton { text-align: left; padding: 11px 13px; border: 1px solid transparent; background: transparent; color: #a1aec1; font-weight: 600; }
QPushButton#NavButton:hover { background: #162133; color: #eef5ff; }
QPushButton#NavButton:checked { background: #19323a; color: #54e4d0; border: 1px solid #27515a; }
QPushButton#IconButton { min-width: 35px; max-width: 35px; min-height: 35px; max-height: 35px; padding: 0px; font-size: 15px; }
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit { background: #0c1420; color: #edf4ff; border: 1px solid #2a394e; border-radius: 8px; padding: 9px 10px; selection-background-color: #207f79; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus { border: 1px solid #2bc9b9; }
QComboBox::drop-down { border: 0; width: 26px; }
QComboBox QAbstractItemView { background: #111a28; color: #edf4ff; border: 1px solid #2a394e; selection-background-color: #19423f; }
QCheckBox { spacing: 8px; color: #d6dfeb; }
QCheckBox::indicator { width: 17px; height: 17px; }
QCheckBox::indicator:unchecked { border: 1px solid #52647b; background: #0d1521; border-radius: 4px; }
QCheckBox::indicator:checked { border: 1px solid #29c9b7; background: #29c9b7; border-radius: 4px; }
QTableWidget, QTableView { background: #101824; alternate-background-color: #131e2c; color: #e7edf7; border: 1px solid #26364a; border-radius: 10px; gridline-color: #263448; selection-background-color: #1c4846; selection-color: #ffffff; }
QHeaderView::section { background: #162234; color: #b5c3d6; border: 0; border-bottom: 1px solid #2a394e; padding: 10px; font-weight: 700; }
QTableWidget::item { padding: 7px; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #2b3b50; border-radius: 5px; min-height: 25px; }
QScrollBar::handle:vertical:hover { background: #435b76; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QProgressBar { background: #172335; border: none; border-radius: 5px; height: 8px; text-align: center; }
QProgressBar::chunk { background: #2ed2bd; border-radius: 5px; }
QToolTip { background: #182536; color: #f5f8ff; border: 1px solid #3b4f68; padding: 5px; }
QDialog { background: #0d1420; }
QMenu { background: #111a28; color: #e7edf7; border: 1px solid #2a394e; padding: 5px; }
QMenu::item:selected { background: #19423f; }
'''

# Lighter, clearer surface hierarchy; keep body text and disabled-state contrast readable.
LIGHT_QSS = r'''
* { font-family: "Segoe UI", "Inter", sans-serif; font-size: 13px; }
QMainWindow, QWidget#Root { background: #eef2f7; color: #1b2a41; }
QWidget { color: #1b2a41; }
QFrame#Sidebar { background: #ffffff; border-right: 1px solid #d5deea; }
QFrame#TopBar { background: #f8fafd; border-bottom: 1px solid #d5deea; }
QFrame[panel="true"] { background: #ffffff; border: 1px solid #d6dfeb; border-radius: 14px; }
QFrame[panel="hero"] { background: #ffffff; border: 1px solid #c8e5e2; border-radius: 17px; }
QFrame[connectionModeCard="true"] { border: 1px solid #d6dfeb; border-radius: 12px; }
QFrame[connectionModeCard="selected"] { background: #f0faf8; border: 1px solid #087f75; border-radius: 12px; }
QLabel { background: transparent; }
QLabel#Brand { font-size: 19px; font-weight: 750; color: #152740; }
QLabel#BrandMark { color: #087f75; font-size: 24px; font-weight: 900; }
QLabel#PageTitle { font-size: 23px; font-weight: 750; color: #152740; }
QLabel#Subtitle, QLabel#Muted { color: #586b83; font-size: 12px; }
QLabel#Heading { font-size: 15px; font-weight: 700; color: #1b2d45; }
QLabel#Metric { font-size: 22px; font-weight: 750; color: #152740; }
QLabel#Accent { color: #087f75; font-weight: 700; }
QLabel#TinyCaps { color: #536780; font-size: 10px; font-weight: 800; letter-spacing: 1px; }
QLabel#StatusPill { background: #dff4eb; color: #08634f; border: 1px solid #a9dfcf; border-radius: 10px; padding: 6px 10px; font-weight: 700; }
QLabel#WarningPill { background: #fff0cf; color: #815006; border: 1px solid #e8c879; border-radius: 10px; padding: 6px 10px; font-weight: 700; }
QLabel#ErrorPill { background: #ffe7ea; color: #97283b; border: 1px solid #eab3bd; border-radius: 10px; padding: 6px 10px; font-weight: 700; }
QPushButton { background: #ffffff; color: #263b54; border: 1px solid #cbd7e5; border-radius: 9px; padding: 9px 13px; font-weight: 650; }
QPushButton:hover { background: #edf4fa; border-color: #aebfd2; }
QPushButton:pressed { background: #e4edf5; }
QPushButton:disabled { color: #75869b; background: #edf1f6; border-color: #d7e0ea; }
QPushButton#PrimaryButton { background: #087f75; color: #ffffff; border: 1px solid #087f75; font-weight: 800; }
QPushButton#PrimaryButton:hover { background: #0a9688; }
QPushButton#DangerButton { background: #ffe7ea; color: #97283b; border-color: #eab3bd; }
QPushButton#NavButton { text-align: left; padding: 11px 13px; border: 1px solid transparent; background: transparent; color: #536780; font-weight: 600; }
QPushButton#NavButton:hover { background: #eff4f9; color: #1b2d45; }
QPushButton#NavButton:checked { background: #dff3ef; color: #076d64; border: 1px solid #b3e2d9; }
QPushButton#IconButton { min-width: 35px; max-width: 35px; min-height: 35px; max-height: 35px; padding: 0px; font-size: 15px; }
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit { background: #ffffff; color: #1b2a41; border: 1px solid #cbd7e5; border-radius: 8px; padding: 9px 10px; selection-background-color: #b7e8e0; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus { border: 1px solid #087f75; }
QComboBox::drop-down { border: 0; width: 26px; }
QComboBox QAbstractItemView { background: #ffffff; color: #1b2a41; border: 1px solid #cbd7e5; selection-background-color: #dff3ef; }
QCheckBox { spacing: 8px; color: #263b54; }
QCheckBox::indicator { width: 17px; height: 17px; }
QCheckBox::indicator:unchecked { border: 1px solid #9cacc0; background: #ffffff; border-radius: 4px; }
QCheckBox::indicator:checked { border: 1px solid #087f75; background: #087f75; border-radius: 4px; }
QTableWidget, QTableView { background: #ffffff; alternate-background-color: #f5f8fc; color: #1b2a41; border: 1px solid #d6dfeb; border-radius: 10px; gridline-color: #dce4ed; selection-background-color: #d6eeea; selection-color: #16263b; }
QHeaderView::section { background: #e9eff6; color: #425770; border: 0; border-bottom: 1px solid #d6dfeb; padding: 10px; font-weight: 700; }
QTableWidget::item { padding: 7px; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #b5c4d5; border-radius: 5px; min-height: 25px; }
QScrollBar::handle:vertical:hover { background: #899db6; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QProgressBar { background: #e1e9f2; border: none; border-radius: 5px; height: 8px; text-align: center; }
QProgressBar::chunk { background: #087f75; border-radius: 5px; }
QToolTip { background: #ffffff; color: #1b2a41; border: 1px solid #b8c7d8; padding: 5px; }
QDialog { background: #f4f7fb; }
QMenu { background: #ffffff; color: #1b2a41; border: 1px solid #cbd7e5; padding: 5px; }
QMenu::item:selected { background: #dff3ef; }
'''


def _replace_colors(source: str, pairs: dict[str, str]) -> str:
    for old, new in pairs.items():
        source = source.replace(old, new)
    return source


def stylesheet(theme: str) -> str:
    if theme == "light":
        base = LIGHT_QSS
        page_background = "#eef2f7"
    elif theme == "midnight":
        base = _replace_colors(DARK_QSS, {
            "#0b1019": "#100d1b", "#0e1521": "#171228", "#111a28": "#1b1630",
            "#111d2c": "#211a39", "#202c3e": "#33264b", "#233044": "#382b52",
            "#29d6c4": "#b99cff", "#36dcc7": "#c4a9ff", "#24bda9": "#8d6be8",
            "#40d9c5": "#a98bff", "#19323a": "#34264d", "#54e4d0": "#d0baff",
            "#207f79": "#7256b8", "#19423f": "#3b2a59", "#2ed2bd": "#ae8bff",
        })
        page_background = "#100d1b"
    elif theme == "ocean":
        base = _replace_colors(DARK_QSS, {
            "#0b1019": "#071722", "#0e1521": "#0b202d", "#111a28": "#102b3a",
            "#111d2c": "#123344", "#202c3e": "#1d4152", "#233044": "#244454",
            "#29d6c4": "#5fcaff", "#36dcc7": "#72d2ff", "#24bda9": "#178ec2",
            "#40d9c5": "#44b9ef", "#19323a": "#123c51", "#54e4d0": "#81d8ff",
            "#207f79": "#1c83b2", "#19423f": "#174b63", "#2ed2bd": "#36b7ef",
        })
        page_background = "#071722"
    elif theme == "high_contrast":
        base = _replace_colors(DARK_QSS, {
            "#0b1019": "#000000", "#0e1521": "#000000", "#111a28": "#080808",
            "#111d2c": "#050505", "#202c3e": "#eeeeee", "#233044": "#eeeeee",
            "#e7edf7": "#ffffff", "#f4f8ff": "#ffffff", "#f4f7fc": "#ffffff",
            "#edf4ff": "#ffffff", "#a1aec1": "#eeeeee", "#93a2b7": "#eeeeee",
            "#29d6c4": "#00ffff", "#36dcc7": "#00ffff", "#24bda9": "#00ffff",
            "#40d9c5": "#66ffff", "#19323a": "#202020", "#54e4d0": "#00ffff",
            "#0c1420": "#000000", "#2a394e": "#ffffff", "#2b3b51": "#ffffff",
            "#26364a": "#ffffff", "#263448": "#cccccc", "#162234": "#111111",
            "#2b3b50": "#ffffff", "#435b76": "#eeeeee", "#2ed2bd": "#00ffff",
        })
        page_background = "#000000"
    else:
        base = DARK_QSS
        page_background = "#0b1019"

    # QScrollArea's viewport and its embedded page widget are separate widgets.
    # Give them explicit theme-aware surfaces so the native palette cannot leave
    # a stale dark/black area behind cards when the user selects the Light theme.
    page_surfaces = f"""
QWidget#PageContent {{ background-color: {page_background}; }}
QScrollArea#PageScrollArea {{ background-color: {page_background}; border: none; }}
QScrollArea#PageScrollArea QWidget#PageContent {{ background-color: {page_background}; }}
QStackedWidget {{ background-color: {page_background}; }}
"""
    return base + page_surfaces
