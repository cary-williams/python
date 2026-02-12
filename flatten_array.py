"""
Take a nested list and return a single flattened list with all values except nil/null.

accepts an arbitrarily-deep nested list-like structure and returns a flattened structure without any nil/null values.

For Example

flatten([1,[2,3,null,4],[null],5])

returns: [1,2,3,4,5]
"""

from collections.abc import Iterable

def flatten_gen(iterable):
    '''takes lists from flatten function, and flattens it'''
    for item in iterable:
        # don't flatten strings to avoid infinite recursion
        if isinstance(item, Iterable) and not isinstance(item, (str, bytes)):
            yield from flatten_gen(item)
        else:
            yield item


def flatten(iterable):
    '''function actually called. returns the flattened array'''
    return [ item for item in flatten_gen(iterable) if item is not None ]

