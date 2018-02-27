'''
Given a string of digits, calculate the largest product for a contiguous
substring of digits of length n.

Args:
    series: a string of digits. must be positive
    size: length of substring. positive integer.
Returns:
    product: product of the largest contiguous substring digits
Raises:
    ValueError: if size > len(series)

'''


def largest_product(series, size):
    """Finds the largest product of slices of a given size"""
    if series == "" and size != 0:
        raise ValueError("this is kind of a dumb test")
    elif size > len(series) or size < 0:
        raise ValueError("size must be a positive number <= len(series)")

    slice_list = slices(series, size)
    def calculation(items):
        total = 1
        for i in items:
            product *= i
        return product
    slice_list = [calculation(l) for l in slice_list]
    return max(slice_list)

def slices(series, size):
    """Returns list of lists of consecutive series"""
    if not 0 <= size <= len(series):
        raise ValueError
    elif series == '':
        return [[1]]

    slice_list = []

    for i in range(len(series) - size + 1):
        slice_list.append([int(d) for d in series[i:i+size]])
    return slice_list
