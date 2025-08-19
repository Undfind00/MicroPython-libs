import uhashlib
import ubinascii
import urandom
import time


class MicroRSA:
    def __init__(self, key_length=384):
        self.key_length = min(key_length, 512)  # minimum key length 512b
        self.e = 65537  # exponent value
        self.max_attempts = 500  # maximum try to generate first num
        self.prime_certainty = 5  # prime number test accuracy

    @staticmethod
    def gcd(a, b): # GCD lib code
        while b:
            a, b = b, a % b
        return a

    def is_prime(self, n): # optimized miller robin test
        if n <= 3:
            return n > 1
        if n % 2 == 0:
            return False

        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(self.prime_certainty):
            a = urandom.getrandbits(16) % (n - 4) + 2
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for __ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime_candidate(self): # generate prime number candidate
        while True:
            p = urandom.getrandbits(32)
            if p < 3:
                continue
            # check length and oddity
            p |= (1 << (self.key_length // 2 - 1)) | 1
            return p

    def generate_prime(self): # generate prime number with time limit
        start_time = time.ticks_ms()
        for _ in range(self.max_attempts):
            candidate = self.generate_prime_candidate()
            if self.is_prime(candidate):
                return candidate
            if time.ticks_diff(time.ticks_ms(), start_time) > 8000:  # 8 ثانیه
                break
        raise ValueError("Prime number generation failed")

    def generate_keys(self): # generate RSA key + error control
        p = self.generate_prime()
        q = self.generate_prime()

        while p == q:  # check q,p differences
            q = self.generate_prime()

        n = p * q
        phi = (p - 1) * (q - 1)

        # ensuring (e) suitability
        while self.gcd(self.e, phi) != 1:
            p = self.generate_prime()
            q = self.generate_prime()
            n = p * q
            phi = (p - 1) * (q - 1)

        # calculate private key
        d = self.modinv(self.e, phi)
        return (n, self.e), (n, d)

    def modinv(self, a, m): # modular inverse calculation
        g, x, y = self.extended_gcd(a, m)
        if g != 1:
            return None
        return x % m

    @staticmethod
    def extended_gcd(a, b): # extended euclidean algorithm
        if a == 0:
            return (b, 0, 1)
        g, y, x = MicroRSA.extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

    def sign(self, message, private_key):
        n, d = private_key
        msg_hash = self._hash_message(message)
        m = self._os2ip(msg_hash)
        s = pow(m, d, n)
        return self._i2osp(s, self.key_length // 8)

    def verify(self, message, signature, public_key):
        n, e = public_key
        msg_hash = self._hash_message(message)
        m = self._os2ip(msg_hash)
        s = self._os2ip(signature)
        v = pow(s, e, n)
        return m == v

    @staticmethod
    def _hash_message(message): # hash using sha256
        if isinstance(message, str):
            message = message.encode()
        return uhashlib.sha256(message).digest()

    @staticmethod
    def _os2ip(octets): # convert byte to integer
        return int.from_bytes(octets, 'big')

    @staticmethod
    def _i2osp(x, x_len): # convert integer to byte
        return x.to_bytes(x_len, 'big')

'''

def test_rsa():
    print("آماده‌سازی RSA...")
    rsa = MicroRSA(key_length=384)  # 384 بیت برای میکروکنترلرها مناسب است

    try:
        print("در حال تولید کلیدها... (ممکن است چند ثانیه طول بکشد)")
        public_key, private_key = rsa.generate_keys()
        print("✅ کلیدها با موفقیت تولید شدند")

        message = "این یک پیام تست است"
        print("\nپیام:", message)

        print("در حال ایجاد امضا...")
        signature = rsa.sign(message, private_key)
        print("امضا:", ubinascii.hexlify(signature))

        print("\nدر حال تأیید امضا...")
        is_valid = rsa.verify(message, signature, public_key)
        print("نتیجه تأیید:", "✅ معتبر" if is_valid else "❌ نامعتبر")

        # تست تغییر پیام
        fake_message = message + "!"
        is_valid_fake = rsa.verify(fake_message, signature, public_key)
        print("تست تغییر پیام:", "✅ کارکرد صحیح" if not is_valid_fake else "❌ خطا")

    except Exception as e:
        print("❌ خطا:", e)


test_rsa()
'''