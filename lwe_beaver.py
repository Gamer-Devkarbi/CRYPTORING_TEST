# lwe_beaver.py
import secrets
import hashlib

class LWEBeaver:
    def __init__(self, q=4096, n=128, m=128):
        self.q = q
        self.n = n
        self.m = m
        # Generate a random public matrix A ∈ ℤ_q^(n×m)
        self.A = [[secrets.randbelow(q) for _ in range(m)] for _ in range(n)]
        # Generate a secret vector s with small entries
        self.s = [secrets.choice([-1, 0, 1]) for _ in range(m)]
        # Generate error vector e with small entries
        self.e = [secrets.choice([-1, 0, 1]) for _ in range(n)]
        # Compute public vector y = A * s + e (mod q)
        self.y = []
        for i in range(n):
            dot = sum(self.A[i][j] * self.s[j] for j in range(m)) % q
            self.y.append((dot + self.e[i]) % q)
        # Generate Beaver triple parameter 'a'
        self.a = secrets.randbelow(q)

    def encrypt_session_key(self, session_key: int) -> tuple:
        """
        Encrypt a binary session key (0 or 1) using an extremely simplified LWE-based approach.
        For demonstration:
          0 -> 0, 1 -> q/2.
        Returns a ciphertext tuple (u, v_masked).
        """
        m_scaled = (self.q // 2) * session_key
        # Sample a random binary vector r ∈ {0,1}^n.
        r = [secrets.choice([0, 1]) for _ in range(self.n)]
        # Compute u = r^T * A (for each column)
        u = []
        for j in range(self.m):
            col_sum = sum(r[i] * self.A[i][j] for i in range(self.n)) % self.q
            u.append(col_sum)
        # Compute v = r^T * y + m_scaled
        v_partial = sum(r[i] * self.y[i] for i in range(self.n)) % self.q
        v = (v_partial + m_scaled) % self.q
        # Generate a mask using a simple PRG seeded by the Beaver element 'a'
        mask = int(hashlib.sha256(f"{self.a}_0".encode('utf-8')).hexdigest(), 16) % self.q
        v_masked = (v + mask) % self.q
        return (u, v_masked)

    def decrypt_session_key(self, ciphertext: tuple) -> int:
        """
        Decrypts the given ciphertext using the secret vector s and Beaver parameter 'a'
        to recover the binary session key.
        """
        u, v_masked = ciphertext
        mask = int(hashlib.sha256(f"{self.a}_0".encode('utf-8')).hexdigest(), 16) % self.q
        v_prime = (v_masked - mask) % self.q
        us = sum(u[j] * self.s[j] for j in range(self.m)) % self.q
        diff = (v_prime - us) % self.q
        # Use thresholding to decide the binary key.
        return 1 if (self.q // 4 < diff < 3 * self.q // 4) else 0
