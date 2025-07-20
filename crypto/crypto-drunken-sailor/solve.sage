import itertools as itt
from multiprocessing import Pool
import os
os.environ['TERM'] = 'linux'
from pwn import process
import time
proof.all(False)

PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]

CSIDH_PRIMES = PRIMES[:6]
p = 4*prod(PRIMES) - 1

Fp = GF(p)
Fp2.<w> = GF(p**2, modulus = x**2 + 1)
E0 = EllipticCurve(Fp2, [1,0])

def action(pub, priv):
    E = pub
    es = list(priv[:])
    while any(es):
        E._order = (p + 1)**2 # else sage computes this
        P = E.lift_x(GF(p).random_element())
        s = +1 if P.xy()[1] in GF(p) else -1
        k = prod(l for l, e in zip(CSIDH_PRIMES, es) if sign(e) == s)
        P *= (p + 1) // k
        for i, (l, e) in enumerate(zip(CSIDH_PRIMES, es)):
            if sign(e) != s: continue
            Q = k // l * P
            if not Q: continue
            Q._order = l # else sage computes this
            phi = E.isogeny(Q)
            E, P = phi.codomain(), phi(P)
            es[i] -= s
            k //= l
    return E

def sectoj(sec):
    E = action(E0, sec)
    jE = int(E.j_invariant())
    return (sec, jE)

all_js = {}
print('Precomputation...')
small_keys = list(itt.product(range(-2, 3), repeat=len(CSIDH_PRIMES)))

t1 = time.time()
with Pool() as PP:
    outs = PP.map(sectoj, small_keys)

all_js = {j:sec for sec, j in outs}
t2 = time.time()
print(f'Done in {t2-t1:.3f}s')

while True:
    r = process(['sage', 'chall.sage'])
    jA = int(r.recvline().decode().split(' = ')[-1])
    if jA in all_js:
        break
    r.close()

sec = all_js[jA]
sec = b','.join(str(t).encode() for t in sec)
print(f'{sec = }')
r.sendline(sec)
r.interactive()

