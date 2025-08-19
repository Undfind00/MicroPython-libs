# cbor.py — Minimal CBOR for MicroPython (RP2040/Pico)
# Supports: None, bool, int(±64b), bytes, str(utf-8), list/tuple, dict(str/bytes keys), float64
# Stream-safe encoding/decoding + file-bytes streaming helpers.

try:
    import ustruct as struct
    import uio as io
except ImportError:
    import struct
    import io

# ---------------------------
# Helpers (low-level)
# ---------------------------

def _write_uint(w, major, val):
    # major: 0=uint,1=negint,2=bytes,3=str,4=array,5=map,7=simple/float
    if val < 24:
        w.write(bytes([(major << 5) | val]))
    elif val <= 0xFF:
        w.write(bytes([(major << 5) | 24, val]))
    elif val <= 0xFFFF:
        w.write(bytes([(major << 5) | 25]))
        w.write(struct.pack('>H', val))
    elif val <= 0xFFFFFFFF:
        w.write(bytes([(major << 5) | 26]))
        w.write(struct.pack('>I', val))
    elif val <= 0xFFFFFFFFFFFFFFFF:
        w.write(bytes([(major << 5) | 27]))
        w.write(struct.pack('>Q', val))
    else:
        raise ValueError("integer too large for this minimal CBOR")

def _read_exact(r, n):
    b = r.read(n)
    if b is None or len(b) != n:
        raise EOFError("unexpected EOF")
    return b

def _read_len(r, ai):
    if ai < 24:
        return ai
    elif ai == 24:
        return _read_exact(r, 1)[0]
    elif ai == 25:
        return struct.unpack('>H', _read_exact(r, 2))[0]
    elif ai == 26:
        return struct.unpack('>I', _read_exact(r, 4))[0]
    elif ai == 27:
        return struct.unpack('>Q', _read_exact(r, 8))[0]
    else:
        raise ValueError("indefinite length not supported by this minimal CBOR")

# ---------------------------
# Encoder
# ---------------------------

def dump(obj, w):
    """Encode `obj` to CBOR and write to stream `w` (has .write)."""
    t = type(obj)
    if obj is None:
        w.write(b'\xf6')  # null
    elif obj is True:
        w.write(b'\xf5')  # true
    elif obj is False:
        w.write(b'\xf4')  # false
    elif t is int:
        if obj >= 0:
            _write_uint(w, 0, obj)
        else:
            # negative integer n is encoded as (major=1, value = -1 - n)
            _write_uint(w, 1, -1 - obj)
    elif t is bytes or t is bytearray:
        b = obj if t is bytes else bytes(obj)
        _write_uint(w, 2, len(b))
        w.write(b)
    elif t is str:
        b = obj.encode('utf-8')
        _write_uint(w, 3, len(b))
        w.write(b)
    elif t in (list, tuple):
        _write_uint(w, 4, len(obj))
        for it in obj:
            dump(it, w)
    elif t is dict:
        _write_uint(w, 5, len(obj))
        # For determinism, sort by key if all keys are str; else write as-is.
        keys = list(obj.keys())
        try:
            keys.sort()
        except:
            pass
        for k in keys:
            if not (isinstance(k, (str, bytes, bytearray))):
                raise TypeError("dict keys must be str/bytes")
            dump(k, w)
            dump(obj[k], w)
    elif t is float:
        # encode as 64-bit float
        w.write(b'\xfb')  # major 7, ai=27
        w.write(struct.pack('>d', obj))
    else:
        raise TypeError("unsupported type: %s" % (t,))

def dumps(obj):
    """Return CBOR bytes for `obj`."""
    bio = io.BytesIO()
    dump(obj, bio)
    return bio.getvalue()

# ---------------------------
# Decoder
# ---------------------------

def _load_one(r):
    ib = _read_exact(r, 1)[0]
    major = ib >> 5
    ai = ib & 0x1F

    if major == 0:  # unsigned
        val = _read_len(r, ai)
        return val
    elif major == 1:  # negative
        val = _read_len(r, ai)
        return -1 - val
    elif major == 2:  # bytes
        n = _read_len(r, ai)
        return _read_exact(r, n)
    elif major == 3:  # text
        n = _read_len(r, ai)
        return _read_exact(r, n).decode('utf-8')
    elif major == 4:  # array
        n = _read_len(r, ai)
        arr = []
        for _ in range(n):
            arr.append(_load_one(r))
        return arr
    elif major == 5:  # map
        n = _read_len(r, ai)
        d = {}
        for _ in range(n):
            k = _load_one(r)
            v = _load_one(r)
            d[k] = v
        return d
    elif major == 7:  # simple/float
        if ai == 20:  # false
            return False
        elif ai == 21:  # true
            return True
        elif ai == 22:  # null
            return None
        elif ai == 26:  # float32
            return struct.unpack('>f', _read_exact(r, 4))[0]
        elif ai == 27:  # float64
            return struct.unpack('>d', _read_exact(r, 8))[0]
        else:
            raise ValueError("unsupported simple/float ai=%d" % ai)
    else:
        raise ValueError("unsupported major=%d" % major)

def load(r):
    """Read one CBOR item from stream `r` and return Python object."""
    return _load_one(r)

def loads(b):
    """Decode CBOR bytes `b` to Python object."""
    bio = io.BytesIO(b)
    return _load_one(bio)

# ---------------------------
# File transfer helpers (bytes as CBOR)
# ---------------------------

_CHUNK = 4096  # tune if needed

def dump_file_bytes(src_file, w, file_size=None):
    """
    Encode a file as a CBOR 'bytes' item, streaming from `src_file` (path or file-like),
    writing to stream `w` without loading the whole file to RAM.
    """
    close_src = False
    if isinstance(src_file, str):
        import os
        st = os.stat(src_file)
        if file_size is None:
            file_size = st[6] if hasattr(st, 'st_size') else st[0] if isinstance(st, tuple) else st.st_size
        f = open(src_file, 'rb')
        close_src = True
    else:
        f = src_file
        if file_size is None:
            raise ValueError("file_size required when src_file is file-like")

    _write_uint(w, 2, file_size)  # bytes header with definite length
    # Stream copy
    while True:
        chunk = f.read(_CHUNK)
        if not chunk:
            break
        w.write(chunk)
    if close_src:
        f.close()

def load_bytes_to_file(r, dst_file, expected_len=None):
    """
    Read one CBOR item (must be 'bytes') from stream `r` and write its content to `dst_file`
    in chunks (no big buffers). Returns total bytes written.
    """
    ib = _read_exact(r, 1)[0]
    major = ib >> 5
    ai = ib & 0x1F
    if major != 2:
        raise ValueError("next CBOR item is not 'bytes'")
    n = _read_len(r, ai)
    if expected_len is not None and expected_len != n:
        raise ValueError("length mismatch: expected %d got %d" % (expected_len, n))

    close_dst = False
    if isinstance(dst_file, str):
        f = open(dst_file, 'wb')
        close_dst = True
    else:
        f = dst_file

    remain = n
    total = 0
    while remain:
        to_read = _CHUNK if remain > _CHUNK else remain
        chunk = _read_exact(r, to_read)
        f.write(chunk)
        remain -= to_read
        total += to_read

    if close_dst:
        f.close()
    return total
