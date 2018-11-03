import gmpy2
import sympy
import binascii
from Crypto.PublicKey import RSA

def factor(n, d=0, dx=1):
    while True:
        r = gmpy2.isqrt(n + (d/2) ** 2) + d//2
        s = r - d
        if r * s == n: return (r, s)
        d += dx

def decrypt(p, q, e, ciphertext):
	n = p * q
	phi = (p - 1) * (q - 1)
	d = int(sympy.invert(e, phi))
	m = pow(ciphertext, d, n)
	return m

key1 = RSA.importKey(open('./publickey1.pem', 'r').read())
key2 = RSA.importKey(open('./publickey2.pem', 'r').read())
ciphertext1 = int(open('./ciphertext1.txt', 'r').read().strip())
ciphertext2 = int(open('./ciphertext2.txt', 'r').read().strip())

e = key1.e

n1 = key1.n
n2 = key2.n

# Let d = s - r
# r * (r + d) = n2
# r ** 2 + r * d = n2
# (r + d/2) ** 2 = n2 + (d / 2) ** 2
r, s = factor(n2, d=2, dx=2)
f1 = decrypt(r, s, e, ciphertext2)

# r = x + f1
# x = |p - q| + k
# |p - q| < r - f1
p, q = factor(n1, d=min(r, s) - f1, dx=-1)
f2 = decrypt(p, q, e, ciphertext1)

print(binascii.unhexlify(hex(f1)[2:]) + binascii.unhexlify(hex(f2)[2:]))
