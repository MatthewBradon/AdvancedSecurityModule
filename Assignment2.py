import random
from collections import Counter




# Miller-Rabin Algorithm

def millerRabin(n, iterations=5):
    # Step 1: Find integers k and q such that (n - 1) = 2^k * q, with k > 0 and q odd
    q = n - 1
    k = 0
    while q % 2 == 0:
        q //= 2
        k += 1

    # Perform the test multiple times for accuracy
    for _ in range(iterations):
        # Step 2: Select a random integer a, 1 < a < n - 1
        a = random.randint(2, n - 2)

        # Step 3: Compute a^q mod n; if it equals 1, the result is "inconclusive"
        if pow(a, q, n) == 1:
            continue

        # Step 4: Check if any of the values a^(2^j * q) mod n equals n - 1 for j = 0 to k - 1
        inconclusive = False
        for j in range(k):
            if pow(a, 2**j * q, n) == n - 1:
                inconclusive = True
                break

        if inconclusive:
            continue
        # If none of the conditions for inconclusiveness were met, return "composite"
        return "composite"

    # If all rounds are inconclusive, return "probably prime"
    return "probably prime"

# Example usage
n = 561  #  Carmichael Number 
result = millerRabin(n)
print(f"The number {n} is {result}.")

n = 7919 # Known probable prime
result = millerRabin(n)
print(f"The number {n} is {result}.")


n = 17 # Known probable prime
result = millerRabin(n)
print(f"The number {n} is {result}.")

















# AES S-Box for SubWord function
s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]


# Rcon array for key expansion
Rcon = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000,
    0x08000000, 0x10000000, 0x20000000, 0x40000000,
    0x80000000, 0x1b000000, 0x36000000
]

def sub_word(word):
    """Applies the SubWord transformation to each byte using AES S-Box."""
    return (
        (s_box[(word >> 24) & 0xFF] << 24) |
        (s_box[(word >> 16) & 0xFF] << 16) |
        (s_box[(word >> 8) & 0xFF] << 8) |
        s_box[word & 0xFF]
    )

def rot_word(word):
    """Performs a cyclic permutation on a 4-byte word (left-rotate by 8 bits)."""
    return ((word << 8) | (word >> 24)) & 0xFFFFFFFF

def key_expansion(key):
    """Performs AES key expansion for 128-bit key."""
    w = [0] * 44
    # Initialize the first four words with the key
    for i in range(4):
        w[i] = (
            (key[4 * i] << 24) |
            (key[4 * i + 1] << 16) |
            (key[4 * i + 2] << 8) |
            key[4 * i + 3]
        )
    
    # Generate the remaining words
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp)) ^ Rcon[i // 4]
        w[i] = w[i - 4] ^ temp
    
    return w

# Convert hex key to a list of integers
key = [0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59,
       0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98]

# Perform key expansion
expanded_keys = key_expansion(key)

# Print the expanded keys in hex format
for i in range(len(expanded_keys)):
    print(f"w{i} = {expanded_keys[i]:08x}")











from collections import Counter

# Cipher text from the provided image
cipher_text = "UZQSOVUOHXMOPVGPOZPEVSGZWSZOPFPESXUDBMETSXAIZVUEPHZHMDZSHZOWSFPAPPDTSVPQUZWYMXUZUHSXEPYEPOPDZSZUFPOMBZWPFUPZHMDJUDTMOHMQ"

# Frequency of letters in English (from the table)
english_frequency = {
    'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 
    'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8, 
    'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0, 
    'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2, 
    'Q': 0.1, 'Z': 0.1
}

# Step 1: Calculate frequency of each letter in the cipher text
cipher_frequency = Counter(cipher_text)
total_letters = sum(cipher_frequency.values())
cipher_freq_percentage = {char: (count / total_letters) * 100 for char, count in cipher_frequency.items()}

# Sort the letters in the cipher text by frequency
sorted_cipher_freq = dict(sorted(cipher_freq_percentage.items(), key=lambda x: x[1], reverse=True))

# Print frequency of each letter in the cipher text
print("Frequency of each letter in the cipher text:")
for letter, freq in sorted_cipher_freq.items():
    print(f"{letter}: {freq:.2f}%")

# Step 2: Define the standard frequency order for English letters
ENGLISH_FREQ_ORDER = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'

# Step 3: Perform letter frequency attack
def letter_frequency_attack(cipher_text):
    # Count the frequency of each letter in the cipher text
    cipher_letter_counts = Counter(filter(str.isalpha, cipher_text.upper()))
    
    # Sort the letters by frequency in the cipher text
    cipher_freq_order = ''.join([pair[0] for pair in cipher_letter_counts.most_common()])
    
    # Generate multiple guesses by slightly shifting the letter frequency alignment
    guesses = []
    for shift in range(5):  # Try slight shifts in alignment
        guess_mapping = {}
        for j in range(len(cipher_freq_order)):
            cipher_letter = cipher_freq_order[j]
            if j + shift < len(ENGLISH_FREQ_ORDER):
                guess_mapping[cipher_letter] = ENGLISH_FREQ_ORDER[(j + shift) % len(ENGLISH_FREQ_ORDER)]
            else:
                guess_mapping[cipher_letter] = cipher_letter  # Map to itself as fallback if out of bounds
        guesses.append(guess_mapping)
    
    # Decrypt the cipher text using each guess mapping
    possible_plaintexts = []
    for guess_mapping in guesses:
        plaintext = ''.join(
            guess_mapping.get(char, char) if char.isalpha() else char for char in cipher_text
        )
        possible_plaintexts.append(plaintext)
    
    # Print the top guesses in rough order of likelihood
    print("\nTop likely plaintext guesses:")
    for idx, plaintext in enumerate(possible_plaintexts, 1):
        print(f"Guess {idx}:\n{plaintext}\n")

# Execute the letter frequency attack on the cipher text
letter_frequency_attack(cipher_text)






# Step 1: Calculate the frequency of each letter in the cipher text
cipher_frequency = Counter(cipher_text)
total_letters = sum(cipher_frequency.values())
cipher_freq_percentage = {char: (count / total_letters) * 100 for char, count in cipher_frequency.items()}

# Sort cipher text letters by their frequency in descending order
sorted_cipher_freq = sorted(cipher_freq_percentage.items(), key=lambda x: x[1], reverse=True)

# Sort English letters by their frequency in descending order
sorted_english_freq = sorted(english_frequency.items(), key=lambda x: x[1], reverse=True)

# Step 2: Create a mapping from the most frequent cipher letters to the most frequent English letters
mapping = {cipher_char: english_char for (cipher_char, _), (english_char, _) in zip(sorted_cipher_freq, sorted_english_freq)}

# Step 3: Decrypt the cipher text using the frequency-based mapping
decoded_text = ''.join(mapping.get(char, char) for char in cipher_text)

# Print the frequency mapping and the decoded text
print("Frequency Mapping:")
for cipher_char, english_char in mapping.items():
    print(f"{cipher_char} -> {english_char}")

print("\nDecoded Text (Likeliest Plaintext):")
print(decoded_text)