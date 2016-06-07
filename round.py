# Simple function that rounds a number(input) to the nearest multiple of X(base)
# where X can be any positive integer. Numbers should be rounded
# up or down based on their proximity to the nearest X.
# Numbers at the midpoint should be rounded up.
# The only exception is that a number must not round to 0 (i.e., rounding(1, 5) == 5, not 0
# 
# EXAMPLES: 
# round to nearest 50
# 54 -> 50
# 75 ->100
# round to nearest 22
# 22 -> 22
# 29 -> 22
# 33 -> 44



def rounding(input, base):
         try:
                  int(input)
                  int(base)
         except ValueError as e:
                  print "Arguments must be integers"
                  raise
         eqa = int(base * round(float(input)/base))
         if input < 0:
                  print "must be a positive int"
                  exit()
         elif eqa == 0:
                  return base
         else:
                  return eqa 




