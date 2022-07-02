import random as random
import string
import logging
from typing import Sequence

from .common import pipe, curry, merge

__all__ = [
    # random
    'random_pw', 'sample', 'random_sentence', 'random_str', 'random_user',
    'random_str_word_set',
]

# ----------------------------------------------------------------------
#
# Random content creation functions
#
# ----------------------------------------------------------------------

@curry
def random_str(width=8, *, rng=random, population: Sequence = string.ascii_letters, 
               exclude_chars: Sequence[str] = (),
               exclude_words: Sequence[str] = (), try_index=0, max_tries=100):
    if try_index + 1 == max_tries:
        raise RecursionError(
            f'Could not find a suitable random word with population: {population}'
            f' and exclude_words: {exclude_words}'
        )
    clean_pop = pipe(set(population) - set(exclude_chars), tuple)
    r_str = ''.join(rng.choice(clean_pop) for _ in range(width))
    if exclude_words and (r_str in exclude_words):
        return random_str(
            n, rng=rng, population=population,
            exclude_chars=exclude_chars, exclude_words=exclude_words,
            try_index = try_index + 1, max_tries=max_tries,
        )
    return r_str

_tracked_str_word_sets = {}
@curry
def random_str_word_set(set_name: str, width: int, **random_str_kw):
    exclude_words = _tracked_str_word_sets.get((set_name, width), [])
    word = random_str(width, **merge(
        random_str_kw, {'exclude_words': exclude_words}
    ))
    exclude_words.append(word)
    return word

@curry
def random_sentence(w=10, *, rng=random):
    return pipe(
        [random_str(rng.randrange(4, 10), rng=rng) for i in range(w)],
        lambda s: [s[0].capitalize()] + s[1:],
        ' '.join,
        lambda s: s + '.'
    )

@curry
def random_user(n=8, *, rng=random):
    return ''.join(rng.choice(string.ascii_lowercase) for _ in range(n))

@curry
def random_pw(n=16, *, rng=random, pop=string.printable[:64]):
    return ''.join(rng.choice(pop) for _ in range(n))

@curry
def sample(k, seq, *, rng=None, seed=None):
    rng = rng or (random if seed is None else random.Random(seed))
    return rng.sample(tuple(seq), k)


