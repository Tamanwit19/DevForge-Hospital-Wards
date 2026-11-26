"""Deterministic normalization for English, Hindi and Hinglish name clues."""
import re
import unicodedata

from indic_transliteration import sanscript
from indic_transliteration.sanscript import transliterate


_NAME_VARIANTS = {
    'md': 'muhammad', 'mhd': 'muhammad', 'mohd': 'muhammad',
    'mohammad': 'muhammad', 'mohammed': 'muhammad',
    'muhammed': 'muhammad', 'mohammada': 'muhammad',
    'muhammada': 'muhammad'
}
_HONORIFICS = {
    'mr', 'mrs', 'ms', 'shri', 'sri', 'smt', 'kumari', 'ji', 'sahab',
    'didi', 'babu', 'bhai', 'behenji', 'dr'
}
_DEVANAGARI_CONSONANTS = set(chr(value) for value in range(0x0915, 0x093A)) | set(
    chr(value) for value in range(0x0958, 0x0960)
)


def _transliterate_devanagari(match):
    source = match.group()
    word = transliterate(source, sanscript.DEVANAGARI, sanscript.IAST)
    if source[-1] in _DEVANAGARI_CONSONANTS and word.endswith('a'):
        word = word[:-1]
    return word.replace('ś', 'sh').replace('ṣ', 'sh')


def canonical_tokens(value):
    text = unicodedata.normalize('NFKC', str(value)).casefold()
    from_devanagari = any('\u0900' <= c <= '\u097f' for c in text)
    if from_devanagari:
        text = re.sub(r'[\u0900-\u097f]+', _transliterate_devanagari, text)
    text = unicodedata.normalize('NFKD', text)
    text = ''.join(c for c in text if not unicodedata.combining(c))
    tokens = re.findall(r'[a-z]+', text)
    result = []
    for word in tokens:
        word = word.replace('ph', 'f')
        if word in _HONORIFICS:
            continue
        word = word.replace('aa', 'a').replace('ee', 'i').replace('ii', 'i')
        word = word.replace('oo', 'u').replace('uu', 'u')
        word = word.replace('w', 'v')
        word = _NAME_VARIANTS.get(word, word)
        if word and word not in _HONORIFICS:
            result.append(word)
    return tuple(sorted(result))
