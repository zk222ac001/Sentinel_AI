"""Windows-only filesystem adapter using no-follow Win32 handles.

Directory handles deny delete sharing while descending, so an opened directory
cannot be swapped out for a junction during traversal. Each opened handle is
checked against the approved root before content is read.
"""
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import stat
import time

REPARSE = 0x400
OFFLINE_OR_RECALL = 0x1000 | 0x40000 | 0x400000
DIRECTORY = 0x10


class UnsafeEntry(OSError):
    pass


if os.name == 'nt':
    import msvcrt
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)

    class FileInfo(ctypes.Structure):
        _fields_ = [('attributes',wintypes.DWORD), ('creation',wintypes.FILETIME),
                    ('access',wintypes.FILETIME), ('write',wintypes.FILETIME),
                    ('volume',wintypes.DWORD), ('size_high',wintypes.DWORD),
                    ('size_low',wintypes.DWORD), ('links',wintypes.DWORD),
                    ('index_high',wintypes.DWORD), ('index_low',wintypes.DWORD)]

    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,
                                  wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE,ctypes.POINTER(FileInfo)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE,wintypes.LPWSTR,wintypes.DWORD,wintypes.DWORD]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD


def normalized(path):
    text = str(path)
    if text.startswith('\\\\?\\UNC\\'):
        text = '\\\\' + text[8:]
    elif text.startswith('\\\\?\\'):
        text = text[4:]
    return os.path.normcase(os.path.normpath(text))


def final_path(handle):
    needed = kernel.GetFinalPathNameByHandleW(handle,None,0,0)
    if not needed:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(needed+1)
    count = kernel.GetFinalPathNameByHandleW(handle,buffer,len(buffer),0)
    if not count or count >= len(buffer):
        raise UnsafeEntry('Cannot establish final handle path')
    return normalized(buffer.value)


@contextmanager
def checked_handle(path, root, *, directory=False):
    if os.name != 'nt':
        raise OSError('Windows adapter used on another platform')
    # GENERIC_READ; SHARE_READ|SHARE_WRITE, deliberately no SHARE_DELETE;
    # OPEN_EXISTING; BACKUP_SEMANTICS|OPEN_REPARSE_POINT.
    handle = kernel.CreateFileW(str(path),0x80000000,3,None,3,0x02200000,None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = FileInfo()
        if not kernel.GetFileInformationByHandle(handle,ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.attributes & (REPARSE | OFFLINE_OR_RECALL):
            raise UnsafeEntry('Reparse point or cloud placeholder')
        if bool(info.attributes & DIRECTORY) != directory or kernel.GetFileType(handle) != 1:
            raise UnsafeEntry('Unexpected file type')
        approved = normalized(root)
        resolved = final_path(handle)
        if os.path.commonpath([approved,resolved]) != approved:
            raise UnsafeEntry('Handle is outside the approved scope')
        yield handle
    finally:
        kernel.CloseHandle(handle)


@contextmanager
def checked_file(path, root):
    with checked_handle(path,root) as handle:
        # Duplicate the handle because the CRT stream owns and closes its handle.
        current = kernel.GetCurrentProcess
        current.restype = wintypes.HANDLE
        duplicate = wintypes.HANDLE()
        kernel.DuplicateHandle.argtypes = [wintypes.HANDLE,wintypes.HANDLE,wintypes.HANDLE,
                                           ctypes.POINTER(wintypes.HANDLE),wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        kernel.DuplicateHandle.restype = wintypes.BOOL
        if not kernel.DuplicateHandle(current(),handle,current(),ctypes.byref(duplicate),0,False,2):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            fd = msvcrt.open_osfhandle(duplicate.value,os.O_RDONLY|os.O_BINARY)
        except Exception:
            kernel.CloseHandle(duplicate)
            raise
        with os.fdopen(fd,'rb') as source:
            yield source


def scan_windows(root, report, key, cancel, save, data, use_gitleaks):
    from .core import (detect, EXCLUDED, EXTENSIONS, MAX_BYTES, MAX_FILES,
                       MAX_ENTRIES, MAX_FINDINGS, MAX_SKIP_DETAILS, ScanLimitReached)
    from .gitleaks import Gitleaks
    scanner = Gitleaks() if use_gitleaks else None
    if scanner:
        report['engine'] += ' + ' + scanner.version
    report['filesystem_backend'] = 'windows-win32-handles'
    report['limitations'].append('Windows reparse points (including junctions and cloud placeholders) are skipped. NTFS ACLs govern access; POSIX mode bits do not enforce private storage on Windows.')
    started = time.monotonic()
    def skip(reason, path):
        report['skipped'][reason] = report['skipped'].get(reason,0)+1
        if len(report['skipped_details']) < MAX_SKIP_DETAILS:
            report['skipped_details'].append(dict(reason=reason,path=path))
        else:
            report['skipped_details_omitted'] += 1
    def walk(folder, relative='', depth=0):
        if depth>40:
            skip('depth_limit',relative)
            return
        with checked_handle(folder,root,directory=True), os.scandir(folder) as entries:
            for entry in entries:
                if cancel.is_set(): return
                if report['considered']>=MAX_ENTRIES or report['scanned']>=MAX_FILES or time.monotonic()-started>120:
                    raise ScanLimitReached
                report['considered'] += 1
                rel = str(Path(relative)/entry.name)
                path = folder/entry.name
                if entry.name in EXCLUDED or normalized(path)==normalized(data):
                    skip('excluded',rel)
                    continue
                try:
                    info = entry.stat(follow_symlinks=False)
                    if entry.is_symlink():
                        skip('symlink',rel)
                        continue
                    if getattr(info,'st_file_attributes',0) & (REPARSE|OFFLINE_OR_RECALL):
                        skip('reparse_or_placeholder',rel)
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        walk(path,rel,depth+1)
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        skip('special_file',rel)
                        continue
                    if path.suffix.lower() not in EXTENSIONS and not entry.name.startswith('.env'):
                        skip('unsupported_type',rel)
                        continue
                    if info.st_size>MAX_BYTES:
                        skip('size_or_type',rel)
                        continue
                    with checked_file(path,root) as source:
                        before=os.fstat(source.fileno())
                        if before.st_size>MAX_BYTES:
                            skip('size_or_type',rel)
                            continue
                        raw=source.read(MAX_BYTES+1)
                        after=os.fstat(source.fileno())
                    if len(raw)>MAX_BYTES or (before.st_mtime_ns,before.st_size)!=(after.st_mtime_ns,after.st_size):
                        skip('changed_or_large',rel)
                        continue
                    if b'\0' in raw:
                        skip('binary',rel)
                        continue
                    text=raw.decode('utf-8')
                    found=detect(text,key,rel)
                    if scanner: found+=scanner.scan(text,rel)
                    report['findings'].extend(found[:MAX_FINDINGS-len(report['findings'])])
                    report['scanned']+=1
                    if report['scanned']%20==0: save(report)
                    if len(report['findings'])>=MAX_FINDINGS or len(found)>=1000:
                        raise ScanLimitReached
                except (OSError,UnicodeError,ValueError):
                    skip('unreadable_or_encoding',rel)
    walk(root)
    report['status']='cancelled' if cancel.is_set() else ('partial' if report['skipped'] else 'completed')
