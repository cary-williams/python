"""
    Function for encoding a rotational cipher (rot13),
    also known as a Caesar cipher.

    Args:
        text: string of text to encoded
        key:  integer value for shifting Ciphertext
    Returns:
        encoded: the encoded text of the ciphers
    Examples:
        - ROT5  `omg` gives `trl`
        - ROT0  `c` gives `c`
        - ROT26 `Cool` gives `Cool`
        - ROT13 `The quick brown fox` gives `Gur dhvpx oebja sbk`
"""
from string import ascii_lowercase

def rotate(text, key):
    "Rotational or Caesar cipher encoding"
    letters = ascii_lowercase
    encoded = ''
    for character in text:
        if character.isalpha():
            index = letters.index(character.lower()) + key
            index = (letters.index(character.lower()) + key) % 26

            encoded_letter = letters[index]
            if character.isupper():
                encoded = encoded + encoded_letter.upper()
            else:
                encoded = encoded + encoded_letter
        else:
            encoded = encoded + character

    return encoded
