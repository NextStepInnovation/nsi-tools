import random
import string
from typing import Sequence

from .common import pipe, curry

# ----------------------------------------------------------------------
#
# Random content creation functions
#
# ----------------------------------------------------------------------

@curry
def random_str(n=8, *, rng=None, population: Sequence = string.ascii_letters, 
               exclude_chars: Sequence[str] = (),
               exclude_words: Sequence[str] = (), try_index=0, max_tries=100):
    if try_index + 1 == max_tries:
        raise RecursionError(
            f'Could not find a suitable random word with population: {population}'
            f' and exclude_words: {exclude_words}'
        )
    rng = rng or random
    clean_pop = pipe(set(population) - set(exclude_chars), tuple)
    r_str = ''.join(rng.choice(population) for _ in range(n))
    if exclude_words and (r_str in exclude_words):
        return random_str(
            n, rng=rng, population=population,
            exclude_chars=exclude_chars, exclude_words=exclude_words,
            try_index = try_index + 1, max_tries=max_tries,
        )
    return r_str

@curry
def random_sentence(w=10, *, rng=None):
    rng = rng or random
    return pipe(
        [random_str(rng.randrange(4, 10), rng=rng) for i in range(w)],
        lambda s: [s[0].capitalize()] + s[1:],
        ' '.join,
        lambda s: s + '.'
    )

@curry
def random_user(n=8, *, rng=None):
    rng = rng or random
    return ''.join(rng.choice(string.ascii_lowercase) for _ in range(n))

@curry
def random_pw(n=16, *, rng=None, pop=string.printable[:64]):
    rng = rng or random
    return ''.join(rng.choice(pop) for _ in range(n))

@curry
def sample(k, seq, *, rng=None, seed=None):
    rng = rng or (random if seed is None else random.Random(seed))
    return rng.sample(tuple(seq), k)


