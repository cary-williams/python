"""
Given a number, find the sum of all the unique multiples of particular numbers up to
but not including that number.

If we list all the natural numbers below 20 that are multiples of 3 or 5,
we get 3, 5, 6, 9, 10, 12, 15, and 18.

The sum of these multiples is 78.
"""

def sum_of_multiples(limit, multiples):
    tot = 0
    used = []
    for num in range(limit)[1:]:
        for mul in multiples:
            if not num % mul and num not in used:
                tot += num
                used.append(num)
    return tot
