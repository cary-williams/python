"""
Find the difference between the square of the sum and the sum of the squares of the first N natural numbers.

The square of the sum of the first ten natural numbers is (1 + 2 + ... + 10)² = 55² = 3025.

The sum of the squares of the first ten natural numbers is 1² + 2² + ... + 10² = 385.

Hence the difference between the square of the sum of the first ten natural numbers
and the sum of the squares of the first ten natural numbers is 3025 - 385 = 2640.

Args:
    count: integer of the first N natural numbers
Returns:
    square_of_sum - sum_of_squares
"""


def square_of_sum(count):
    """find the square of sums."""
    sum = 0
    for i in range(1, count + 1):
        sum += i
    return pow(sum, 2)


def sum_of_squares(count):
    """find the sum of the squares"""
    SumOfSquare =  0
    for i in range(1, count +1):
        SumOfSquare += pow(i, 2)
    return SumOfSquare


def difference(count):
    """finds the difference of the square of sums and sums of squares"""
    return square_of_sum(count) - sum_of_squares(count)
