"""
Determine the moment a person has lived for 10^9 seconds
Args:
    birth_date: the date of birth using datetime. May include time as well.
Example:
    add_gigasecond(datetime(1973, 10, 28))
    2005-07-06 01:46:40

"""

from datetime import timedelta, datetime
def add_gigasecond(birth_date):
    """ finds the date and time a person ages 10^9 seconds"""
    return birth_date + timedelta(seconds=10**9)
