"""
Author: Andrew R. Hansen
Copyright: July 2021

This work is based on "How SHA-256 works step-by-step" by Lane Wagner.
(https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/)
The process described in this website is brilliantly clear and the computational demonstration of each of the steps
allowed me to find and correct errors in my code.  Thank you.

The structure of the code follows the steps of the process as described.  It should be pointed out that this
application is for teaching / demonstration purposes only and should not be used in a production setting.
"""

from hashlib import sha256 # This is just so we can check our output against the real thing.

def make_h_values():
    """
    The h values for sha256 are easily found but I thought, being a purist, I would calculate them by hand.
    The process for this can be found here: https://medium.com/swlh/the-mathematics-of-bitcoin-74ebf6cefbb0
    under 4.2 - Initial Hash Values.
    While I could have used the sqrt function from the math library, there is no cube root function in there
    and since I had to do cube roots the long way I thought I would do square roots as well.
    :return: a python dictionary of h values.
    """
    h_values = {}  # dict
    primes = [2, 3, 5, 7, 11, 13, 17, 19]  # the first 8 primes
    for p in primes:
        sqr_root_p = p ** (1.0 / 2.0)  # Since we have to do the cube root by hand we might as well do this one too.
        h = format(int((sqr_root_p % 1) * 16 ** 8), '032b')  # All values are stored as 32 bit binary representations
        h_values[primes.index(p)] = h

    return h_values


def get_primes():
    """
        The round constants are based on the fractional parts of the cube roots of the first 64 primes (2 - 311).
        That's too many to put into a list so I'm going to calculate them.
        :return: A list of the first 64 primes
        """
    primes = []
    num = 2
    while len(primes) < 64:
        is_prime = True
        for i in range(2, num):
            if (num % i) == 0:
                is_prime = False
        if is_prime:
            primes.append(num)
        num += 1
    return primes


def make_k_values():
    """
    Like the h values, the round constant (k) values are well established but I want to make this hash from
    scratch so I'll calculate them from the cube roots of the fractional parts of the first 64 primes.
    :return: A python dictionary of k values
    """
    primes = get_primes()
    k_values = {}
    for p in primes:
        cube_root_p = p ** (1.0 / 3.0)  # There is not a math function for cube root so this will have to do.
        k = format(int((cube_root_p % 1) * 16 ** 8), '032b')  # Again, values are stored as 32 bit binary
        k_values[primes.index(p)] = k

    return k_values


def make_block(text):
    """
    This function takes the input text (which we assume to be a short phrase for the purpose of the demo) and
    builds it up to the 512 bit block required.
    :param text:
    :return:
    """
    # Start by appending the 8 bit binary form of the ascii value of each letter in the input text
    # to a single bit string
    block = ''
    for char in text:
        block += format(ord(char), "08b")

    # Append a single "1" at the end of the bit string.
    block += '1'

    # Pad the block with zeros to a length of 448 bits.
    for i in range(448 - len(block)):
        block += '0'

    # Finally append the message length (in bits) to the end of the block as a 64 bit value.
    length = len(text) * 8
    block += format(length, "064b")

    return block


def make_word_schedule(block):
    """
    This function takes the initial 512 bit block and divides it up into 16 x 32 bit words.
    It then appends a further 48 x 16 bit words (all set to zero) to bring the word schedule
    up to 64 words each of 32 bits.
    :param block:
    :return:
    """
    words = []

    for i in range(16):
        word = ''
        for j in range(i * 32, i * 32 + 32):
            word += block[j]
        words.append(word)

    for i in range(48):
        word = ''
        for j in range(32):
            word += '0'
        words.append(word)

    return words


def initialise_variables(h_values):
    a = h_values[0]
    b = h_values[1]
    c = h_values[2]
    d = h_values[3]
    e = h_values[4]
    f = h_values[5]
    g = h_values[6]
    h = h_values[7]

    variables = [a, b, c, d, e, f, g, h]
    return variables


def rotate(string, bits):
    """
    Given that all our words are stored as strings, using slice notation is the easiest way to perform rotations.
    :param string:
    :param bits:
    :return:
    """
    rf = string[0: len(string) - bits]
    rs = string[len(string) - bits:]

    return rs + rf


def shift(string, bits):
    """
    The shift function is like the rotate function in that it is a rightwards functions but the values that fall off
    the right hand end are lost and 0's are added to the front to maintain 32 bits.
    :param string:
    :param bits:
    :return:
    """
    end = string[:len(string) - bits]
    start = ''
    for i in range(bits):
        start += '0'

    return start + end


def make_s0_value(word):
    s0 = int(rotate(word, 7), 2) ^ int(rotate(word, 18), 2) ^ int(shift(word, 3), 2)
    return format(s0, '032b')


def make_s1_value(word):
    s1 = int(rotate(word, 17), 2) ^ int(rotate(word, 19), 2) ^ int(shift(word, 10), 2)
    return format(s1, '032b')


def make_word(word0, s0, word1, s1):
    word = (int(word0, 2) + int(s0, 2) + int(word1, 2) + int(s1, 2)) % 2 ** 32
    return word


def complete_word_list(words):
    for i in range(16, 64):
        s0 = make_s0_value(words[i - 15])
        s1 = make_s1_value(words[i - 2])
        word = make_word(words[i - 16], s0, words[i - 7], s1)

        words[i] = format(word, '032b')

    return words


def scramble(variables, k_values, word_schedule):
    """
    This is the guts of the application.  Each step is preceeded by the instruction as it appears on the website.
    In some cases, such as instructions like "h = g" this probably makes the code harder to read rather than easier.
    Sorry.
    :param variables:
    :param k_values:
    :param word_schedule:
    :return:
    """
    a = variables[0]
    b = variables[1]
    c = variables[2]
    d = variables[3]
    e = variables[4]
    f = variables[5]
    g = variables[6]
    h = variables[7]
    for i in range(64):
        # S1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        s1 = format(int(rotate(e, 6), 2) ^ int(rotate(e, 11), 2) ^ int(rotate(e, 25), 2), '032b')
        # ch = (e and f) xor ((not e) and g)
        ch = format(int(e, 2) & int(f, 2) ^ ~int(e, 2) & int(g, 2), '032b')
        # temp1 = h + S1 + ch + k[i] + w[i]
        temp1 = format(((int(h, 2) + int(s1, 2) + int(ch, 2) + int(k_values[i], 2) + int(word_schedule[i], 2)) % 2 ** 32),
                       '032b')
        # S0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        s0 = format(int(rotate(a, 2), 2) ^ int(rotate(a, 13), 2) ^ int(rotate(a, 22), 2), '032b')
        # maj = (a and b) xor (a and c) xor (b and c)
        maj = format(int(a, 2) & int(b, 2) ^ int(a, 2) & int(c, 2) ^ int(b, 2) & int(c, 2), '032b')
        # temp2 := S0 + maj
        temp2 = format(((int(s0, 2) + int(maj, 2)) % 2 ** 32), '032b')
        # h = g
        h = g
        # g = f
        g = f
        # f = e
        f = e
        # e = d + temp1
        e = format(((int(d, 2) + int(temp1, 2)) % 2 ** 32), '032b')
        # d = c
        d = c
        # c = b
        c = b
        # b = a
        b = a
        # a = temp1 + temp2
        a = format(((int(temp1, 2) + int(temp2, 2)) % 2 ** 32), '032b')

    final_values = [a, b, c, d, e, f, g, h]
    return final_values


def assemble_hash(h_values, variables):
    hash_binary = ''
    for i in range(8):
        hash_binary += format((int(h_values[i], 2) + int(variables[i], 2)) % 2 ** 32, '032b')

    return hex(int(hash_binary, 2))[2:].zfill(64)


if __name__ == '__main__':
    plain_text = '88484'
    new_block = make_block(plain_text)
    new_words = make_word_schedule(new_block)
    final_words = complete_word_list(new_words)
    h_values = make_h_values()
    k_values = make_k_values()
    variables = initialise_variables(h_values)
    hashed_data = scramble(variables, k_values, final_words)
    output = assemble_hash(h_values, hashed_data)
    
    print('Our output:', output)
    print('Test output:', sha256(plain_text.encode()).hexdigest())
