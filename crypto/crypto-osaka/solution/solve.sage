from sage.all import *

from Crypto.Cipher import AES
import json
from hashlib import sha256
import os
import random
from ortools.sat.python import cp_model
from multiprocessing import Pool

Q = 8380417
K = 4
L = 4
ETA = 2
TAU = 39
BETA = 78
GAMMA1 = (1 << 17)
GAMMA2 = ((Q-1)/88)
N = 256

F = GF(Q)
P, X = PolynomialRing(F, 'X').objgen()
R, tbar = P.quotient_ring(X**N + 1, 'tbar').objgen()

def center_s(s, p):
    t = int(s) % p
    return t - p if t > p // 2 else t

def center_vec(v, p):
    return [[center_s(s, p) for s in pol] for pol in v]

def high_bits(vf):
    vz = [[int(s) for s in pol] for pol in vf]
    vlo = center_vec(vz, 2 * GAMMA2)
    vhi = [[(x-y) // (2 * GAMMA2) for x, y in zip(pol, pol2)] for pol, pol2 in zip(vz, vlo)]
    return vector(R, vhi)

def low_bits(vf):
    vz = [[int(s) for s in pol] for pol in vf]
    vlo = center_vec(vz, 2 * GAMMA2)
    return vlo


def hash_2_ball(msg, w1, N):

    pre = msg.encode() + b'\xff' 
    pre += str(w1).encode()
    h = sha256(pre).digest()
    r = random.Random(h)

    # Not exactly ideal, but no intended vulnerability here
    inds = r.sample(range(N), TAU)
    signs = [1 - 2*r.randint(0, 1) for _ in range(TAU)]
    c = [0 for _ in range(N)]
    for i in range(TAU):
        c[inds[i]] = signs[i]
    return R(c)

def vfy(A, t, sig, msg):
    (z, c) = sig
    zc = center_vec(z, Q)
    if not all(abs(x) < GAMMA1 - BETA for pol in zc for x in pol):
        return False

    w = A * z - c * t
    w1 = high_bits(w)

    cp = hash_2_ball(msg, w1, N)
    return cp == c

file = open("output.txt", "r")

data = json.loads(file.readline())
seed = bytes.fromhex(data["seed"])
set_random_seed(int.from_bytes(seed, "big"))
A = random_matrix(R, K, L)

ct = bytes.fromhex(data["ct"])
t_pk = vector(R, data["t"])

NSIGS = 1<<19
CHK_SIZE = int(1<<12)

def find_idx(sig, msg):
    (z, c) = sig
    myw = A * z - c * t_pk
    myw1 = high_bits(myw)

    for idx in range(K):
        for i in range(256):
            tmp = center_s(myw[idx][i], 2 * GAMMA2)
            if abs(tmp) <= GAMMA2 - 2 * BETA:
                continue

            s = sgn(tmp)
            cur = copy(myw1)
            cur[idx] += s * tbar**i
            cp = hash_2_ball(msg, cur, N)
            if cp == c:
                return (idx, i, s)

    else:
        return None

def fetch_constr(tup):
    m, zl, cl = tup
    z = vector(R, zl)
    c = R(cl)
    sig = (z, c)

    if vfy(A, t_pk, sig, m):
        return None

    if (out := find_idx(sig, m)) is None:
        print("RARE")
        return None

    idx, coef, s = out

    cc = [center_s(x, Q) for x in c]
    myw = A * z - c * t_pk
    rhs = center_s(myw[idx][coef], 2 * GAMMA2)

    if s == 1:
        return (idx, coef, cc, GAMMA2 - rhs + 1, BETA)
    else:
        return (idx, coef, cc, -BETA, GAMMA2 + rhs - 1)

cs_map = []
for k in range(N):
    m = []
    for i in range(k+1):
        m.append((k-i, 1))
    for i in range(k+1, N):
        m.append((N+k-i, -1))
    cs_map.append(m)

models = [cp_model.CpModel() for _ in range(K)]
s2_vars = [[models[i].NewIntVar(-ETA, ETA, f's_{i}_{j}') for j in range(N)] for i in range(K)]
cnts = [0 for _ in range(K)]

import os
from tqdm import trange

NTH = os.cpu_count() + 1

with Pool(NTH) as pool:
    for i in trange(NSIGS // CHK_SIZE, desc="Processing signatures"):
        tups = [json.loads(file.readline()) for _ in range(CHK_SIZE)]
        for out in pool.imap(fetch_constr, tups):
            if not out:
                continue

            idx, coef, cc, lb, ub = out
            val = cs_map[coef]
            cs = 0
            for j in range(N):
                cs += val[j][1] * cc[j] * s2_vars[idx][val[j][0]]
            models[idx].AddLinearConstraint(cs, lb, ub)
            cnts[idx] += 1

        print(cnts)

s2 = []
for i in range(K):
    solver = cp_model.CpSolver()
    T = walltime()
    print(f"[*] Starting to solve model {i}...")
    status = solver.Solve(models[i])
    print(f"[*] Finished solving model {i}, status {status}, took {walltime(T)}")
    s2_i = [int(solver.Value(s2_vars[i][j])) for j in range(N)]
    s2.append(R(s2_i))

# This is the correct s2, heuristically
s2 = vector(R, s2)
s1 = A**-1 * (t_pk - s2)
k = sha256(str([s1, s2]).encode()).digest()
pt = AES.new(k, AES.MODE_ECB).decrypt(ct)
print(pt)
