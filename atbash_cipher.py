"""
Create an implementation of the atbash cipher.

The Atbash cipher is a simple substitution cipher that relies on
transposing all the letters in the alphabet such that the resulting
alphabet is backwards.

Ciphertext is written out in groups of fixed length, the traditional group size
being 5 letters, and punctuation is excluded.

Args:
     plain_text: plain text to be encoded
     ciphered_text: ciphered text to be decoded

"""

from string import ascii_lowercase

regular = ascii_lowercase
reverse = regular[::-1]

def encode(plain_text):
    '''encodes text using Atbash cipher'''
    encoded = ''
    for c in plain_text:
        if c.isalpha():
            i = regular.index(c.lower())
            encoded = encoded + reverse[i]
        elif c.isnumeric():
            encoded = encoded + c
    # Return the cipher using the traditional fixed length of 5
    return  ' '.join(encoded[i:i+5] for i in range(0,len(encoded),5))

def decode(ciphered_text):
    '''Decodes text from atbash ciphered text'''
    decoded = ''
    for c in ciphered_text:
        if c.isalpha():
            index = reverse.index(c.lower())
            decoded = decoded + regular[index]
        elif c.isnumeric():
            decoded = decoded + c
    return decoded
