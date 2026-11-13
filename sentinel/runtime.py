"""Single-owner local application runtime; locks are released by the OS on exit."""
import atexit
import os
from pathlib import Path
import threading

class InstanceInUse(RuntimeError):
    pass


class InstanceLock:
    def __init__(self, data):
        directory = Path(data).expanduser().resolve()
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.file = None
        fd = os.open(directory/'instance.lock', os.O_CREAT | os.O_RDWR, 0o600)
        handle = os.fdopen(fd, 'r+b', buffering=0)
        try:
            # Lock byte zero, including beyond EOF on Windows. Never truncate or
            # delete the lock file: another process may already have it open.
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise InstanceInUse('Another Sentinel instance is using this data folder. Stop the other dashboard or CLI process, then retry. Do not delete instance.lock.') from exc
        self.file = handle

    def close(self):
        if self.file is not None:
            self.file.close()
            self.file = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


_runtimes = {}
_mutex = threading.Lock()


def open_engine(data):
    """Application entry points must use this instead of constructing Engine."""
    from .core import Engine
    key = str(Path(data).expanduser().resolve())
    with _mutex:
        if key in _runtimes:
            return _runtimes[key][1]
        owner = InstanceLock(key)
        try:
            engine = Engine(key)
        except BaseException:
            owner.close()
            raise
        _runtimes[key] = (owner, engine)
        return engine


def close_runtimes():
    """Release idle runtimes; keep ownership if a worker cannot stop yet."""
    with _mutex:
        for key, (owner, engine) in list(_runtimes.items()):
            engine.cancel()
            if engine.worker and engine.worker.is_alive():
                engine.worker.join(timeout=5)
                if engine.worker.is_alive():
                    continue
            owner.close()
            del _runtimes[key]

atexit.register(close_runtimes)
