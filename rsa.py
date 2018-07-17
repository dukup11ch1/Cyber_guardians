from pwn import *
from gmpy2 import *

p = remote('13.209.119.32', 9999)

p.recvuntil('[+] p : ')
p_1 = int(p.recvuntil('\n'))
print p_1

p.recvuntil('[+] n : ')
n = int(p.recvuntil('\n'))
print n

p.recvuntil('[+] Encrypted Msg : ')
msg = int(p.recvuntil('\n'))
print msg

q_1 = n / p_1
phi = (q_1-1) * (p_1-1)
e = 65537

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

gcd, a, b = egcd(e, phi)
d = a

decrypted_data = powmod(int(msg), d, n)

print p.recvline()
print p.recvline()
print p.recvline()
print '[*] decrypted_data : ' + str(decrypted_data)

result = hex(decrypted_data)[2:].decode('hex')
print p.recv()
p.send(str(result)+'\n')
print str(p.recv(2048*1000))

print p.recv(2014)
