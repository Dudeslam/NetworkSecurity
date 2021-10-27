import os
import sys
import Crypto
from Crypto.Util.number import getPrime, bytes_to_long
from Crypto.Random import get_random_bytes

def generate_q_and_p(bits):
    # Generate p prime number
    # According to Cryptodomes webpage, there's a 10^-6 percent chance
    # that the prime is not actually a prime
    while True:
            p = getPrime(bits, randfunc=get_random_bytes)
            if ((p % 4) == 3): break
    # Generate q prime number
    # q most be different than p
    while True:
            q = getPrime(bits, randfunc=get_random_bytes)
            if ((q % 4) == 3) and (q != p): break
    # Return the prime numbers
    return p, q

def encrypt(message, n):
    # Return the encrypted message
    return (pow(message, 2)) % n

def string_to_int(string):
    # Generate a return string
    return_string = ''
    # Run through the string
    for i in range(len(string)):
        # Convert each letter to an int
        letter = ord(string[i])
        as_number = str(letter)
        # Check the length of the int, to enable easier conversion
        # back to a string
        if len(as_number) == 3:
            return_string = return_string + as_number
        if len(as_number) == 2:
            return_string = return_string + '0' + as_number
        if len(as_number) == 1:
            return_string = return_string + '00' + as_number
    # Return the return string
    return return_string

def revert_to_string(int_string):
    # Generate return string
    return_string = ''
    # Change to ordinary string incase of an int
    ord_string = str(int_string)
    # Check each int of length 3 what character the are and append them to
    # the return string
    for i in range(0, len(ord_string), 3):
        return_string = return_string + chr(int(ord_string[i:i+3]))
    # Return the return string
    return return_string

def egcd(a, b):
    # Math for extended Euclian algorithm
    if a == 0:
        return b, 0, 1
    else:
        gcd, y, x = egcd(b % a, a)
        return gcd, x - (b // a) * y, y

def decrypt(p, q, c):
    # Use extended Euclian algorithm to find values
    g, x, y = egcd(p, q)
    # Calculate n
    n = p * q

    r = pow(c, ((p + 1) // 4), p)
    s = pow(c, ((q + 1) // 4), q)
    # Calculate the roots
    r1 = ((x * p * s) + (y * q * r)) % n
    r2 = ((x * p * s) - (y * q * r)) % n
    r3 = (-r1) % n
    r4 = (-r2) % n
    # Return the four roots
    return r1, r2, r3, r4

def pad(message, length=18):
    # Change to ordinary string incase of an int
    string_message = str(message)
    # Pad the message such that only one of the four possible ways fit the
    # padding, by replicating bits
    if len(string_message) > length:
        string_message = string_message + string_message[:-length-1:-1]
        return int(string_message)

def choose(r1, r2, r3, r4, padding_length=18):
    # Generate string from r1
    r1_string = str(r1)
    # Check if string is longer than the padding*2
    if(len(r1_string) >= 2*padding_length):
        # Take the padding and reverse it
        r1_pad = r1_string[:-padding_length-1:-1]
        # Take the end of the original string
        r1_end = r1_string[-2*padding_length:-padding_length]
        if(r1_pad == r1_end):
            print("The found message: " + revert_to_string(int(r1_string[:-padding_length])))
            return int(r1_string[:-padding_length])

    # Generate string from r2
    r2_string = str(r2)
    # Check if string is longer than the padding*2
    if(len(r2_string) >= 2*padding_length):
        # Take the padding and reverse it
        r2_pad = r2_string[:-padding_length-1:-1]
        # Take the end of the original string
        r2_end = r2_string[-2*padding_length:-padding_length]
        if(r2_pad == r2_end):
            print("The found message: " + revert_to_string(int(r2_string[:-padding_length])))
            return int(r2_string[:-padding_length])

    # Generate string from r3
    r3_string = str(r3)
    # Check if string is longer than the padding*2
    if(len(r3_string) >= 2*padding_length):
        # Take the padding and reverse it
        r3_pad = r3_string[:-padding_length-1:-1]
        # Take the end of the original string
        r3_end = r3_string[-2*padding_length:-padding_length]
        if(r3_pad == r3_end):
            print("The found message: " + revert_to_string(int(r3_string[:-padding_length])))
            return int(r3_string[:-padding_length])

    # Generate string from r4
    r4_string = str(r4)
    # Check if string is longer than the padding*2
    if(len(r4_string) >= 2*padding_length):
        # Take the padding and reverse it
        r4_pad = r4_string[:-padding_length-1:-1]
        # Take the end of the original string
        r4_end = r4_string[-2*padding_length:-padding_length]
        if(r4_pad == r4_end):
            print("The found message: " + revert_to_string(int(r4_string[:-padding_length])))
            return int(r4_string[:-padding_length])
    # If none of the r's match, no message is found
    print("No message was found!")
    return 0

if __name__ == '__main__':
    # Changeable variables
    bits=1536
    padding_len = 18

    # Open the rabin.txt and read the txt into a string
    with open(os.path.abspath(os.getcwd()) + "/rabin.txt", 'r') as file:
        msg = file.read()
    # Print the message
    print(("\nMessage: %s") % msg)

    # Generate p and q prime numbers as private keys
    p, q = generate_q_and_p(bits)
    # Generate n as public key
    n = p*q
    # Print the private and public keys
    print(("Private keys (%d bits generated prime numbers):") % bits)
    print(("p: %d \n\nq: %d") % (p,q))
    print("\nPublic key:")
    print("n: %d" %  n)

    # Encrypt the message
    plaintext = int(string_to_int(msg))
    enc_plaintext = encrypt(plaintext, n)
    # Print the encrypted message without padding
    print(("\nEncrypted message (without padding):\n%d") % enc_plaintext)
    # Encrypt the message with padding
    plaintext_pad = int(pad(string_to_int(msg), padding_len))
    if plaintext_pad < n:
        enc_plaintext_pad = encrypt(plaintext_pad, n)
    else:
        sys.exit('\nProgram exited: n not bigger than the message')


    # The four square roots are calculated using the quadratic congruence
    r1, r2, r3, r4 = decrypt(p, q, enc_plaintext_pad)
    # Print the four roots
    print(("\nR1: %d \n\nR2: %d \n\nR3: %d \n\nR4: %d \n") % (r1,r2,r3,r4))

    # The right string is choosen, by the help of the padding, the padding
    # reverses the last digits and adds them to the int. Therefore it is
    # possible to check for equality in the message
    choosen_r = choose(r1, r2, r3, r4, padding_len)

    # Generate a new p and q and test if possible to decrypt the message
    # with these new primes private keys
    p, q = generate_q_and_p(bits)

    print("Try with new generated key: ")

    r1, r2, r3, r4 = decrypt(p, q, enc_plaintext_pad)

    choosen_r = choose(r1, r2, r3, r4, padding_len)
