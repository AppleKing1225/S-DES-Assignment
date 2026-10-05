"""Assignment-defined S-DES transformation tables.

Important:
The SBOX2 below follows the homework specification supplied by the instructor,
which differs from some textbook / online S-DES variants.
"""

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)

IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)

EP = (4, 1, 2, 3, 2, 3, 4, 1)
SP = (2, 4, 3, 1)

SBOX1 = (
    (1, 0, 3, 2),
    (3, 2, 1, 0),
    (0, 2, 1, 3),
    (3, 1, 0, 2),
)

SBOX2 = (
    (0, 1, 2, 3),
    (2, 3, 1, 0),
    (3, 0, 1, 2),
    (2, 1, 0, 3),
)
