import uhashlib
import ubinascii
import urandom
import time
import uos
from machine import Pin


class MicroEd25519:
    def __init__(self):
        # static parameters for ed25519
        self.p = 2 ** 255 - 19
        self.d = -121665 * self.inv(121666) % self.p
        self.l = 2 ** 252 + 27742317777372353535851937790883648493
        self.G = self.point_compress(
            15112221349535400772501151409588531511454012693041857206046113283949847762202,
            46316835694926478169428394003475163141307993866256225615783033603165251855960
        )
        self.led = Pin(25, Pin.OUT)

    def inv(self, x):
        return pow(x, self.p - 2, self.p)

    def point_compress(self, x, y):
        return (x & ((1 << 255) - 1)) | ((y & 1) << 255)

    def point_decompress(self, compressed):
        x = compressed & ((1 << 255) - 1)
        y_sign = (compressed >> 255) & 1

        # calculate y from x
        y2 = (x * x - 1) * self.inv(self.d * x * x + 1) % self.p
        y = pow(y2, (self.p + 3) // 8, self.p)

        if (y * y - y2) % self.p != 0:
            y = y * pow(2, (self.p - 1) // 4, self.p) % self.p

        if y % 2 != y_sign:
            y = -y % self.p

        return (x, y)

    def scalar_mult(self, k, P_compressed):
        P = self.point_decompress(P_compressed)
        Q = None

        # using window algorithm for more optimisation
        window_size = 3
        windows = []
        mask = (1 << window_size) - 1

        # precalculation points
        points = [None] * (1 << window_size)
        points[0] = (0, 1, 1, 0)
        points[1] = P

        for i in range(2, 1 << window_size):
            points[i] = self.point_add(points[i - 1], P)

        # divide K to windows
        while k > 0:
            windows.append(k & mask)
            k >>= window_size

        # scalar mult
        for i in reversed(range(len(windows))):
            for _ in range(window_size):
                if Q is not None:
                    Q = self.point_add(Q, Q)

            if windows[i] != 0:
                if Q is None:
                    Q = points[windows[i]]
                else:
                    Q = self.point_add(Q, points[windows[i]])

        return self.point_compress(*Q) if Q else None

    def point_add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        # middle calculation
        A = (y1 - y2) % self.p
        B = (x1 - x2) % self.p
        C = (y1 + y2) % self.p
        D = (x1 + x2) % self.p
        E = (A * A) % self.p
        F = (B * B) % self.p
        G = (C * C) % self.p
        H = (D * D) % self.p
        I = (E * F) % self.p
        J = (G * H) % self.p
        K = (J - I) % self.p

        # result
        x3 = ((A * B) * (J + self.d * I)) % self.p
        y3 = ((C * D) * (J - self.d * I)) % self.p
        z3 = (K * (self.p - 1)) % self.p  # prevent divide

        # normalising
        inv_z3 = self.inv(z3)
        x3 = (x3 * inv_z3) % self.p
        y3 = (y3 * inv_z3) % self.p

        return (x3, y3)

    def generate_secret(self):
        for _ in range(5):
            try:
                seed = uos.urandom(32)
                h = uhashlib.sha256(seed).digest()
                a = int.from_bytes(h[:32], 'little')
                a &= ~7  # clear last 3 byts
                a &= ~(1 << 254)  # clear byte 254
                a |= (1 << 254)  # set bit 254
                return a
            except:
                time.sleep_ms(50)
        raise ValueError("Failed to generate Private Key")

    def generate_keys(self):
        self.led.on()
        secret = self.generate_secret()
        public = self.scalar_mult(secret, self.G)
        self.led.off()
        return secret, public

    def sign(self, msg, secret):
        self.led.on()
        h = uhashlib.sha256(secret.to_bytes(32, 'little')).digest()
        a = int.from_bytes(h[:32], 'little')
        a &= ~7
        a &= ~(1 << 254)
        a |= (1 << 254)

        r = int.from_bytes(uhashlib.sha256(h[32:] + msg).digest(), 'little') % self.l
        R = self.scalar_mult(r, self.G)

        S = (r + int.from_bytes(
            uhashlib.sha256(R.to_bytes(32, 'little') +
                            self.scalar_mult(a, self.G).to_bytes(32, 'little') +
                            msg
                            ).digest(), 'little') * a) % self.l

        self.led.off()
        return R.to_bytes(32, 'little') + S.to_bytes(32, 'little')

    def verify(self, msg, sig, public):
        self.led.on()
        if len(sig) != 64:
            self.led.off()
            return False

        R = int.from_bytes(sig[:32], 'little')
        S = int.from_bytes(sig[32:], 'little')

        if S >= self.l:
            self.led.off()
            return False

        A = public
        h = int.from_bytes(
            uhashlib.sha256(sig[:32] + A.to_bytes(32, 'little') + msg).digest(),
            'little'
        ) % self.l

        left = self.scalar_mult(S, self.G)
        right = self.point_add(
            self.point_decompress(R),
            self.point_decompress(self.scalar_mult(h, A))
        )

        self.led.off()
        return left == self.point_compress(*right) if right else False

