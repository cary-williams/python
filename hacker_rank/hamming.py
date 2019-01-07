"""
Calculates the hamming distance between 2 DNA strands
The Hamming distance is only defined for sequences of equal length.

Args:
    strand_a: DNA nucleotide strand
    strand_b: Another DNA nucleotides strand
Returns:
    distance: hamming distance between strand_a and strand_b
Raises:
    ValueError: if strands are not the same length
Example:
     strand_a = GAGCCTACTAACGGGAT
     strand_b = CATCGTAATGACGGCCT
                ^ ^ ^  ^ ^    ^^
    The Hamming distance between these two DNA strands is 7.
"""

def distance(strand_a, strand_b):
    """Calculates hamming distance between strand_a and strand_b"""
    if len(strand_a) != len(strand_b):
        raise ValueError("Stands must be of equal length")
    distance = 0
    for a_character, b_character in zip(strand_a, strand_b):
        if a_character != b_character:
            distance += 1
    return distance
