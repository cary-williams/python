"""
Given a phrase, count the occurrences of each word in that phrase.

Args:
    phrase: any phrase
Returns:
    counts: dictionary count of word occurrences

Example:
    for the input `"olly olly in come free"`
       returns
           olly: 2
           in: 1
           come: 1
           free: 1

"""
def word_count(phrase):
    """ Count occurrences of each word in a phrase excluding punctuations"""
    punctuations = '''!()-[]{};:"\<>./?@#$%^&*~'''
    counts = dict()
    no_punct = ""
    for char in phrase:
        if char not in punctuations:
            no_punct = no_punct + char

    no_punct = no_punct.replace('_', ' ')
    no_punct = no_punct.replace(',', ' ')

    for word in no_punct.lower().split():
        if word in counts:
            counts[word] += 1
        else:
            counts[word] = 1
    return counts
