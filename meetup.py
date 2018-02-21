"""
Calculate the date of meetups.
Args:
    year: the year
    month: the month
    day_of_the_week: the day of the week
    which: which descriptor such as 1st
Returns:
    date_time: Returns the actual date needed.

Comments:

Typically meetups happen on the same day of the week.  This will
take a description of a meetup date, and return the actual meetup date.

Examples of general descriptions are:

- The first Monday of January 2017
- The third Tuesday of January 2017
- The wednesteenth of January 2017
- The last Thursday of January 2017

The descriptors are:
first, second, third, fourth, fifth, last, monteenth, tuesteenth, wednesteenth,
thursteenth, friteenth, saturteenth, sunteenth

Note that "monteenth", "tuesteenth", etc are all made up words. There was a
meetup whose members realized that there are exactly 7 numbered days in a month
that end in '-teenth'. Therefore, one is guaranteed that each day of the week
(Monday, Tuesday, ...) will have exactly one date that is named with '-teenth'
in every month.

Given examples of a meetup dates, each containing a month, day, year, and
descriptor calculate the date of the actual meetup.  For example, if given
"The first Monday of January 2017", the correct meetup date is 2017/1/2.
"""

import datetime

def meetup_day(year, month, day_of_the_week, which):
    """Determines date of meetup when given year, month, DoW, and descriptor"""
    indexes = {'1st': 0, '2nd': 1, '3rd': 2, '4th': 3, '5th': 4, 'last': -1}
    what_dow = {'Monday': [], 'Tuesday': [], 'Wednesday': [], 'Thursday': [], 'Friday': [], 'Saturday': [], 'Sunday': []}
    date_time = datetime.date(year, month, 1)

    while date_time.month == month:
        day_name = date_time.strftime('%A')
        what_dow[day_name].append(date_time.day)
        date_time = date_time + datetime.timedelta(days=1)

    if which in indexes:
        index = indexes[which]
        day = what_dow[day_of_the_week][index]

    if which == 'teenth':
        day = [d for d in what_dow[day_of_the_week] if 12 < d < 20][0]

    return datetime.date(year, month, day)
