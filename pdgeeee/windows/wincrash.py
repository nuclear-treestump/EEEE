import ctypes
from ctypes import WINFUNCTYPE, POINTER, c_uint, c_void_p, c_ulong, windll
from threading import RLock
import os
import time

print("[wincrash] importing (pid={})".format(os.getpid()))

# --- Windows Constants ---
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_CONTINUE_EXECUTION = -1
EXCEPTION_CONTINUE_SEARCH = 0

# --- Exception Structs ---
class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", c_ulong),
        ("ExceptionFlags", c_ulong),
        ("ExceptionRecord", c_void_p),
        ("ExceptionAddress", c_void_p),
        ("NumberParameters", c_ulong),
        ("ExceptionInformation", c_ulong * 15),
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [("_", c_ulong)]  # Dummy, unused

class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
        ("ContextRecord", POINTER(CONTEXT)),
    ]

# --- Global state ---
_lock = RLock()
_registered = set()
_wincrash_handler_ref = None
_installed = False

def register_region(ptr: int, size: int):
    with _lock:
        _registered.add((ptr, size))
        print(f"[wincrash] registered region: {ptr:#x}, {size}")

def unregister_region(ptr: int):
    with _lock:
        global _registered
        _registered = {r for r in _registered if r[0] != ptr}

# --- Logging function (C-safe) ---
def _write_crash_log(content: bytes):
    kernel32 = ctypes.windll.kernel32
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    path = b"C:\\Users\\Ikari\\EEEE\\crashresult.log"

    handle = kernel32.CreateFileA(
        path,
        0x40000000,  # GENERIC_WRITE
        0,
        None,
        2,  # CREATE_ALWAYS
        0x80,  # FILE_ATTRIBUTE_NORMAL
        None
    )

    if handle == INVALID_HANDLE_VALUE:
        # Do not use OutputDebugStringA — just die
        return

    written = ctypes.c_ulong()
    kernel32.WriteFile(
        handle,
        content,
        len(content),
        ctypes.byref(written),
        None
    )
    kernel32.CloseHandle(handle)

# --- VEH install ---
HANDLERFUNC = WINFUNCTYPE(c_uint, POINTER(EXCEPTION_POINTERS))

def _debug(msg: str):
    try:
        ctypes.windll.kernel32.OutputDebugStringA(msg.encode("ascii"))
    except Exception:
        print(msg)
        pass  # fail silently

def _write_wiped_memory(ptr: int, size: int):
    buf = ctypes.string_at(ptr, size)
    handle = ctypes.windll.kernel32.CreateFileA(
        b"C:\\Users\\Ikari\\EEEE\\dump.bin",
        0x40000000,  # GENERIC_WRITE
        0,
        None,
        4,  # OPEN_ALWAYS (open or create)
        0,
        None
    )
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    if handle != INVALID_HANDLE_VALUE:
        # Move file pointer to end for append
        ctypes.windll.kernel32.SetFilePointer(handle, 0, None, 2)  # FILE_END = 2
        written = ctypes.c_ulong()
        ctypes.windll.kernel32.WriteFile(handle, buf, len(buf), ctypes.byref(written), None)
        ctypes.windll.kernel32.CloseHandle(handle)

def install():
    global _installed, _wincrash_handler_ref
    if _installed:
        return
    print("[wincrash] installing VEH")
    _installed = True

    @HANDLERFUNC
    def handler(exception_pointers):
        rec = exception_pointers.contents.ExceptionRecord.contents
        if rec.ExceptionCode == EXCEPTION_ACCESS_VIOLATION:
            _debug("[wincrash] VEH handler triggered")
            result = b""
            for (ptr, size) in list(_registered):
                try:
                    _debug(f"[wincrash] WIPING: {ptr:#x} SIZE: {size}")
                    try: 
                        patterns = [0xAB, 0xCD, 0xEF]
                        ctypes.windll.kernel32.Sleep(100)
                        old_prot = ctypes.c_ulong()
                        prot_result = ctypes.windll.kernel32.VirtualProtect(
                        ctypes.c_void_p(ptr), size, 0x04,  # PAGE_READWRITE
                        ctypes.byref(old_prot)
                        )
                        for i in range(3):
                            _debug(f"[wincrash] Wiping with pattern {patterns[i]:#x}")
                            res = ctypes.memset(ctypes.c_void_p(ptr), patterns[i], size)
                            _debug(f"[wincrash] Wiped {size} bytes at {ptr:#x} with pattern {patterns[i]:#x}")
                            _write_wiped_memory(ptr, size)
                    except Exception as e:
                        _debug(f"[wincrash] Wipe failed for {ptr:#x}: {e}")
                        continue
                    result += f"WIPED: {ptr:#x} SIZE: {size}\r\n".encode("ascii")
                    ctypes.windll.kernel32.VirtualProtect(
                        ctypes.c_void_p(ptr), size, old_prot.value,
                        ctypes.byref(ctypes.c_ulong())
                    )
                except Exception:
                    _debug(f"[wincrash] Wipe failed for {ptr:#x}")
                    result += f"FAILED: {ptr:#x}\r\n".encode("ascii")
            _debug("[wincrash] WIPED: {}".format(result.decode("ascii")))
            _write_crash_log(result)
            ctypes.windll.kernel32.ExitProcess(1)
            return EXCEPTION_CONTINUE_SEARCH
            
        return EXCEPTION_CONTINUE_SEARCH

    _wincrash_handler_ref = handler
    res = windll.kernel32.AddVectoredExceptionHandler(1, _wincrash_handler_ref)
    if not res:
        err = ctypes.windll.kernel32.GetLastError()
        print(f"[wincrash] VEH registration failed: {err} {ctypes.FormatError(err)}")
    else:
        print(f"[wincrash] VEH registered: {res}")

install()
