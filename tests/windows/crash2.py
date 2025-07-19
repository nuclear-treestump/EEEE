import ctypes
from ctypes import wintypes, WINFUNCTYPE, POINTER, c_uint
import sys

EXCEPTION_CONTINUE_SEARCH = 0
EXCEPTION_ACCESS_VIOLATION = 0xC0000005

if sys.maxsize > 2**32:
    ULONG_PTR = ctypes.c_uint64
else:
    ULONG_PTR = ctypes.c_uint32

# Exception structures
class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", wintypes.DWORD),
        ("ExceptionFlags", wintypes.DWORD),
        ("ExceptionRecord", wintypes.LPVOID),
        ("ExceptionAddress", wintypes.LPVOID),
        ("NumberParameters", wintypes.DWORD),
        ("ExceptionInformation", ULONG_PTR * 15),
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [("_", wintypes.DWORD)]  # Dummy

class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
        ("ContextRecord", POINTER(CONTEXT)),
    ]

HandlerProto = WINFUNCTYPE(c_uint, POINTER(EXCEPTION_POINTERS))

@HandlerProto
def veh_handler(ptrs):
    print("[VEH] VEH handler triggered")
    return EXCEPTION_CONTINUE_SEARCH

# Register VEH
ctypes.windll.kernel32.AddVectoredExceptionHandler(1, veh_handler)

print("[VEH] Handler registered. Triggering exception...")

# Trigger it manually
ctypes.windll.kernel32.RaiseException(
    EXCEPTION_ACCESS_VIOLATION,
    0,  # dwExceptionFlags
    0,  # nNumberOfArguments
    None
)

print("[VEH] If you see this, VEH did not run.")
