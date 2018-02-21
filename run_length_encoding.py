"""
Implement run-length encoding and decoding.
Args:
    string: any string
Example:
    encoding:
        "WWWWWBWWWWWWWWWWWWBBBWWWWWWWWWWWWWWWWWWWWWB"  ->  "5WB9W3B24WB"
    decoding:
        "2AB3CD4E"  ->  "AABCCCDEEEE"
"""
from itertools import groupby
from re import match, findall


def encode(string):
    """
    Encodes string
    """
    return ''.join(map(lambda single: remove_one(single), [list(single) for k, single in groupby(string)]))

def remove_one(single):
    """
    If the count is only '1', it will not show the count.
    Example:
        "AAAAEBB" encodes to "4AE2B" not "4A1E2B"
    """
    return single[0] if len(single) == 1 else str(len(single)) + single[0]

def decode(string):
    """
    Decodes string
    """
    groups = findall('(\d*\D{1})', string)
    pairs = map(lambda single: [match('\d*', single).group(), single[-1]], groups)
    return ''.join(map(lambda x: int(x[0]) * x[1] if x[0].isdigit() else x[1],
                       pairs))
