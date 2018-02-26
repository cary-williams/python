"""
Given a string of digits, output all the contiguous substrings of length `n` in
that string.

For example, the string "49142" has the following 3-digit series:
- 491
- 914
- 142
And the following 4-digit series:
- 4914
- 9142
"""

from collections import deque

def slices(series, length):
    ''' determine contiguous substrings of series using length ''
    if length < 1 or length > len(series):
        raise ValueError("Length must be <= the length of series and not 0")
    else:
        q = deque(series, length)
        return [
            list(q) for i, x in enumerate(series)
            if q.append(int(x)) or i >= length - 1
        ]
