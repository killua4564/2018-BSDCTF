import string
import binascii
from Crypto.Cipher import AES

key = b'\xa2y\xdb\x92\xc6\x0e\xad?]\x8c\xfb\xe6Z\x11\x88\xfa'
ciphertext = b'n\xca\xe0\xc5\x9d\x1eq\xe1N\x1f\xe7\x99V\x1b\x84\x11&\xd0\xf9\xa8 \xcfj\x125Tv@\x0b\x07\xc4\xca\t\x12\xfcO\xa1%\x88\xac\xe6|\xb6\x89\xf8\xf9FC'

printable = [i for i in bytes(string.printable, 'utf-8')]
xor = lambda x, y: bytes([i ^ j for i, j in zip(x, y)])
is_printable = lambda x: all(i in printable for i in x)

def unpad(plaintext):
	k = plaintext[-1]
	if k > 15: return plaintext
	elif plaintext.endswith(bytes([k]) * k): return plaintext[:-k]
	else: return plaintext + b'\xff'

def leak(key, ciphertext):
	key = key[:-1]
	for i in range(256):
		try_key = bytes([i]) + key
		aes = AES.new(try_key, AES.MODE_ECB)
		plaintext = unpad(aes.decrypt(ciphertext))
		if is_printable(plaintext):
			return try_key, plaintext

if __name__ == '__main__':
	flag = []

	for i in range(0, len(ciphertext), 16):
		key = xor(key, ciphertext[i:i+16])

	for i in range(len(ciphertext), 0, -16):
		key, plaintext = leak(key, ciphertext[i-16:i])
		flag.append(plaintext)

	print(b''.join(flag[::-1]))
