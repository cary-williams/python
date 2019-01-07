"""
Given a word and a list of possible anagrams, select the correct sublist.

Given "listen" as a word, and a list of candidates like
"enlists" "google" "inlets" "banana"
the program should return a list containing "inlets".

Args:
    word: a string that will be matched to
    candidates: a list of words to check against.

Returns:
    matches: list of words that are anagrams to 'word'

Usage:
    detect_anagrams("master", ["stream", "pigeon", "maters"])
    Returns ["stream", "maters"]

"""


def detect_anagrams(word, candidates):
    """ determines if any words in list are an anagram of the chosen word"""
    matches = []
    sorted_word = ''.join(sorted(word.lower()))
    for i in candidates:
        if i.lower() != word.lower() and i not in matches:
            if sorted_word == ''.join(sorted(i.lower())):
                matches.append(i)
    return matches
