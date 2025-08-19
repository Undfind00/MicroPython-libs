# test_cbor.py
import .cbor as cbor

def rt(x):
    b = cbor.dumps(x)
    y = cbor.loads(b)
    assert y == x, "roundtrip failed: %r -> %r" % (x, y)

def test_basic():
    rt(None)
    rt(True); rt(False)
    rt(0); rt(23); rt(24); rt(255); rt(256); rt(2**32-1); rt(-1); rt(-24); rt(-1000)
    rt(b'\x00\x01\x02hello')
    rt("HELLO WORLD 🌍")
    rt([1, "a", b"b", True, None, 3.14159])
    rt({"k":"v", "n":123, "b":b"xx", "t":True, "nil":None})
    rt(3.1415926535)

def test_file_roundtrip():
    data = b"ABCD" * 2048  # ~8KB
    # Encode as CBOR bytes to a buffer
    import uio as io
    bio = io.BytesIO()
    cbor.dump_file_bytes(io.BytesIO(data), bio, file_size=len(data))
    payload = bio.getvalue()

    # Decode back to bytes
    bio2 = io.BytesIO(payload)
    out = io.BytesIO()
    n = cbor.load_bytes_to_file(bio2, out)
    assert n == len(data)
    assert out.getvalue() == data

def run_all():
    test_basic()
    test_file_roundtrip()
    print("All tests passed.")

if __name__ == "__main__":
    run_all()

