"""Desktop directory chooser isolated from Streamlit's script thread.

The child owns Tk's main thread; no Tk objects enter the web application's
process. Only a JSON-encoded path returns. No file contents are read or uploaded.
"""
import json
from pathlib import Path
import subprocess
import sys


class FolderPickerError(Exception):
    """A desktop chooser could not return a selection."""


def choose_folder(initial=''):
    try:
        result = subprocess.run(
            [sys.executable, '-I', str(Path(__file__).resolve()), str(initial)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=60, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise FolderPickerError('Folder selection timed out after 60 seconds. Click Browse folders again or paste a path.') from exc
    except OSError as exc:
        raise FolderPickerError('Cannot open the desktop folder chooser. You can still paste a folder path.') from exc
    if result.returncode != 0:
        raise FolderPickerError('Folder chooser unavailable. Run Sentinel on your desktop with Python Tk support, or paste a folder path.')
    try:
        path = json.loads(result.stdout)
        if not isinstance(path, str) or '\x00' in path:
            raise ValueError('Invalid selection')
        if path and (not Path(path).is_absolute() or not Path(path).is_dir()):
            raise ValueError('Folder no longer available')
        return path or None
    except (ValueError, OSError, UnicodeError) as exc:
        raise FolderPickerError('The selected folder is unavailable. Choose it again or paste an existing folder path.') from exc


def desktop_dialog(initial):
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    try:
        root.attributes('-topmost', True)
        root.update_idletasks()
        start = Path(initial).expanduser() if initial else Path.home()
        if not start.is_dir():
            start = Path.home()
        return filedialog.askdirectory(
            parent=root, title='Sentinel AI — Select folder to audit',
            initialdir=str(start), mustexist=True,
        ) or ''
    finally:
        root.destroy()


if __name__ == '__main__':
    try:
        # ASCII JSON preserves Unicode filenames on Windows console encodings.
        print(json.dumps(desktop_dialog(sys.argv[1] if len(sys.argv)>1 else ''), ensure_ascii=True))
    except Exception:
        # No OS/path details or traceback is returned to the browser.
        sys.exit(1)
