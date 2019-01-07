"""
    Function to determine if a given number is an armstrong number.

    Args:
        number: the number to check
    Returns:
        Returns True if number is an armstrong number.
    Raises:
        ValueError if argument is not an integer
"""

def is_armstrong(number):
    """
    Takes integer as input. Returns True if the number is an armstrong number.
    """
    # make sure we're given a integer
    try:
        int(number)
    except ValueError:
        print("This is not a whole number.")

    # set running total and get the length of the number in question
    total = 0
    length = len(str(number))

    for digit in str(number):
        total += int(digit) ** length

    return number == total
