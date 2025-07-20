# Drunken Sailor

The challenge is about a CSIDH key exchange. Alice first computes her public
curve using a modified algorithm, and publishes the j-invariant of the curve.
Our goal is to find a secret key that produces the same public curve, when
checked with the standard CSIDH algorithm.

## Vulnerability

The first thing to observe is that the parameters are quite non-standard. The
security is significantly lowered, with roughly 2^32 possible keys (which in
principle would be vulnerable to bruteforce in real life, hopefully not in a
24h ctf). More importantly, the shape of the parameters is changed: we have few
primes with much larger allowed exponents. This is not a vulnerability in
itself (CSIDH parameters are chosen the way they are mostly for efficiency),
but opens the way for the next step.

The key observation is that Alice does not check the "sign" of a point. After
sampling the x coordinate to be a random element, if the y coordinate is over
$F_p$ we say that the point is positive, otherwise negative. If $P$ is a point
of $l$-torsion with y coordinate over $F_p$, the isogeny with kernel (generated
by) $P$ will correspond to the exponent $+1$ for $l$, and if the y coordinate
is over $F_{p^2}$ instead it will correspond to the exponent $-1$. While this
is only a convention (we associate positive exponents to the ideals
corresponding to points fully defined over $F_p$), it is important to be
consistent: if we act with a positive point and then a negative one their
action will cancel out. This is exactly what happens here.

## Exploitation

Despite the exponents being chosen between -20 and 20, many steps in Alice's
walk will cancel out. In practice, we will hit quite often keys where the
resulting action has all exponents between -2 and 2. Since there are only 5^6 ~
15000 such curves, we can precompute all of them, and start querying the server
until we hit one of those. A match will occur after only a few tries, giving us
the flag.
