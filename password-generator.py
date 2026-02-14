""" 
Generate Strong Random Passwords
"""
import secrets
import string

# This script will generate an 24 character password
WORD_LENGTH= 24

# Generate a list of letters, digits, and some punctuation
components = [string.ascii_letters, string.digits, "!@#$%&"]

# flatten the components into a list of characters
chars = []
for clist in components:
    for item in clist:
        chars.append(item)

def generate_password():
    """ Create the password """
    # Store the generated password
    password = []
    # Choose a random item from 'chars' and add it to 'password'
    for _ in range(WORD_LENGTH):
        rchar = secrets.choice(chars)
        password.append(rchar)
    # Return the composed password as a string
    return "".join(password)

# Output generated password
print(generate_password())
