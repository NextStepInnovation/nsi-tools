import random
import string
from typing import Sequence

from .common import pipe, curry

# ----------------------------------------------------------------------
#
# Random content creation functions
#
# ----------------------------------------------------------------------

def random_str(n=8, *, rng=None, exclude: Sequence = None):
    rng = rng or random
    r_str = ''.join(rng.choice(string.ascii_letters) for _ in range(n))
    if exclude and r_str in exclude:
        return random_str(n, rng=rng, exclude=exclude)
    return r_str

def random_sentence(w=10, *, rng=None):
    rng = rng or random
    return pipe(
        [random_str(rng.randrange(4, 10), rng=rng) for i in range(w)],
        lambda s: [s[0].capitalize()] + s[1:],
        ' '.join,
        lambda s: s + '.'
    )

def random_user(n=8, *, rng=None):
    rng = rng or random
    return ''.join(rng.choice(string.ascii_lowercase) for _ in range(n))

def random_pw(n=16, *, rng=None, pop=string.printable[:64]):
    rng = rng or random
    return ''.join(rng.choice(pop) for _ in range(n))

@curry
def random_sample(N, seq, *, rng=None):
    rng = rng or random
    return rng.sample(tuple(seq), N)


