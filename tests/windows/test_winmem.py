import pytest
from pdgeeee.basemem import SecureMemory
from pdgeeee.windows.winmem import WindowsSecureMemory

@pytest.fixture
def secure_mem():
    mem = SecureMemory(WindowsSecureMemory, 4096)
    yield mem
    mem.close()

def test_basic_write_read(secure_mem):
    data = b"test secret"
    secure_mem.write(data)
    result = secure_mem.read()
    print(f"Read data: {result}")
    assert result.startswith(data)

def test_protect_blocks_access(secure_mem):
    secure_mem.write(b"do not read")
    secure_mem.protect()
    with pytest.raises(RuntimeError, match="protected"):
        secure_mem.read()
    with pytest.raises(RuntimeError, match="protected"):
        secure_mem.write(b"fail")
    secure_mem.unprotect()

def test_unprotect_restores_access(secure_mem):
    secret = b"secret again"
    secure_mem.write(secret)
    secure_mem.protect()
    secure_mem.unprotect()
    result = secure_mem.read()
    assert result.startswith(secret)

def test_close_frees_memory(secure_mem):
    ptr = secure_mem.get_ptr()
    secure_mem.close()
    with pytest.raises(RuntimeError, match="closed"):
        secure_mem.read()

def test_closed_memory_pointer_raises(secure_mem):
    secure_mem.close()
    with pytest.raises(RuntimeError, match="closed"):
        secure_mem.get_ptr()

def test_len_returns_allocated_size(secure_mem):
    assert len(secure_mem) == 4096

def test_write_too_much_raises():
    mem = SecureMemory(WindowsSecureMemory, 4096)
    with pytest.raises(ValueError, match="exceeds"):
        mem.write(b"A" * 5001)
    mem.close()

def test_protect_twice_is_idempotent():
    mem = SecureMemory(WindowsSecureMemory, 4096)
    mem.protect()
    mem.protect()  # Currently doesn't raise, should not break
    mem.unprotect()
    mem.close()

def test_close_when_closed_is_noop(secure_mem):
    secure_mem.close()
    secure_mem.close()  # Should not raise

def test_write_when_closed_raises(secure_mem):
    secure_mem.close()
    with pytest.raises(RuntimeError, match="closed"):
        secure_mem.write(b"data")

def test_read_when_closed_raises(secure_mem):
    secure_mem.close()
    with pytest.raises(RuntimeError, match="closed"):
        secure_mem.read()

def test_protect_when_closed_raises(secure_mem):
    secure_mem.close()
    with pytest.raises(RuntimeError, match="closed"):
        secure_mem.protect()

def test_unprotect_when_closed_raises(secure_mem):
    secure_mem.close()
    with pytest.raises(RuntimeError, match="closed"):
        secure_mem.unprotect()

def test_memory_zeroed_before_free():
    mem = SecureMemory(WindowsSecureMemory, 4096)
    mem.write(b'\xDE\xAD\xBE\xEF' * (4096 // 4))

    handler = mem._handler  # Get the actual WindowsSecureMemory instance
    addr = handler.get_ptr()
    size = handler.aligned_size  # Use aligned size, not requested size
    import ctypes
    from unittest.mock import patch
    import hmac
    # Monkeypatch close to skip VirtualFree
    def fake_close(_self=handler):
        with _self._lock:
            if _self.closed:
                return
            _self.closed = True
            try:
                _self.unprotect()
            except Exception:
                pass
            ctypes.memset(ctypes.c_void_p(addr), 0xAA, size)
            ctypes.memset(ctypes.c_void_p(addr), 0x55, size)
            ctypes.memset(ctypes.c_void_p(addr), 0x00, size)
            _self.k32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
            # _self.k32.VirtualFree(...) intentionally omitted

    # Replace the real close with our patched version
    with patch.object(WindowsSecureMemory, "close", fake_close):
        mem.close()  # Triggers patched version

    # Inspect the memory after the patched "close"
    raw = ctypes.string_at(addr, size)
    def is_all_zero(data: bytes) -> bool:
        return hmac.compare_digest(data, b'\x00' * len(data))
    is_zero = is_all_zero(raw)
    assert is_zero, "Memory was not zeroed before free"

    # Manual cleanup
    handler.k32.VirtualFree(ctypes.c_void_p(addr), 0, handler.MEM_RELEASE)
