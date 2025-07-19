import ctypes
import pytest
import os
import platform
print(f"CWD: {os.getcwd()}, Platform: {platform.system()} {platform.release()}" )
from pdgeeee.basemem import SecureMemory
from pdgeeee.windows.winmem import WindowsSecureMemory
import time
import secrets

# Alloc secure memory
mem = SecureMemory(WindowsSecureMemory, 4096)
false_bytes = secrets.token_bytes(4096)
mem.write(false_bytes)
with open("real.bin", "wb") as f:
    f.write(false_bytes)

# Force it to be protected
mem.protect()

# CRASH: Read from protected region
ctypes.memmove(ctypes.create_string_buffer(1), ctypes.c_void_p(mem.get_ptr()), 1)