"""
Use the Sieve of Eratosthenes to find all prime numbers up to the limit.
Process:
    1- Create a list of consecutive integers from 2 through n
    2- Start with p = 2, the smallest prime number.
    3- Enumerate the multiples of by counting to n increments of p, and mark them in the list
    the p itself should not be marked).
    4- Find the p+1 in the list that is not marked. If there was no such number, stop.
    5- Otherwise, let p now equal this new number (which is the next prime), and repeat from step 3.
    When it, the numbers remaining not marked in the list are all the primes below n.
"""
def sieve(limit):
    """ Returns list of primes using the Sieve of Eratosthenes"""
    not_prime = []
    prime = []
    for i in range(2, limit + 1):
        if i not in not_prime:
            prime.append(i)
            for j in range(i * i, limit + 1, i):
                not_prime.append(j)
    return prime
