CeaserCipherText = """RQH YDULDWLRQ WR WKH VWDQGDUG FDHVDU FLSKHU LV ZKHQ WKH DOSKDEHW LV "NHBHG" EB XVLQJ D ZRUG. LQ WKH WUDGLWLRQDO YDULHWB, RQH FRXOG ZULWH WKH DOSKDEHW RQ WZR VWULSV DQG MXVW PDWFK XS WKH VWULSV DIWHU VOLGLQJ WKH ERWWRP VWULS WR WKH OHIW RU ULJKW. WR HQFRGH, BRX ZRXOG ILQG D OHWWHU LQ WKH WRS URZ DQG VXEVWLWXWH LW IRU WKH OHWWHU LQ WKH ERWWRP URZ. IRU D NHBHG YHUVLRQ, RQH ZRXOG QRW XVH D VWDQGDUG DOSKDEHW, EXW ZRXOG ILUVW ZULWH D ZRUG (RPLWWLQJ GXSOLFDWHG OHWWHUV) DQG WKHQ ZULWH WKH UHPDLQLQJ OHWWHUV RI WKH DOSKDEHW. IRU WKH HADPSOH EHORZ, L XVHG D NHB RI "UXPNLQ.FRP" DQG BRX ZLOO VHH WKDW WKH SHULRG LV UHPRYHG EHFDXVH LW LV QRW D OHWWHU. BRX ZLOO DOVR QRWLFH WKH VHFRQG "P" LV QRW LQFOXGHG EHFDXVH WKHUH ZDV DQ P DOUHDGB DQG BRX FDQ'W KDYH GXSOLFDWHV."""

vigenereKey = "leg"
vigenerePlainText = "explanation"

# Part 2 - Implement a program to decrypt the Ceaser Cipher
def encryptCeaserCipher(plaintext, shift):
    cipherText = ""

    for char in plaintext:
        if char.isalpha():
            # Convert the character to ascii value
            asciiValue = ord(char)

            cipherText += chr((asciiValue + shift - 97) % 26 + 97)
        else:
            cipherText += char
    return cipherText

def decryptCeaserCipher(cipherText, shift):
    decryptedText = ""
    cipherText = cipherText.lower()

    for char in cipherText:
        if char.isalpha():
            # Convert the character to ascii value
            asciiValue = ord(char)

            decryptedText += chr((asciiValue - shift - 97) % 26 + 97)
        else:
            decryptedText += char

    return decryptedText


# Brute force check all 25 keys
for shift in range(1,26):
    print("Shift: ", shift)
    print(decryptCeaserCipher(CeaserCipherText, shift))
    print("\n")

ceaserPlainText = "hello"
ceaserShift = 3
print("-Ceaser Cipher-")
ceaserCipherText = encryptCeaserCipher(ceaserPlainText, ceaserShift)
print("Encrypted Text: ", ceaserCipherText)
print("Decrypted Text: ", decryptCeaserCipher(ceaserCipherText, ceaserShift))

def breakCeaserCipher(cipherText):
    # Frequency of letters in English language
    frequency = {
        'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702, 'f': 0.02228, 'g': 0.02015,
        'h': 0.06094, 'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749,
        'o': 0.07507, 'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056, 'u': 0.02758,
        'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974, 'z': 0.00074
    }

    # Convert the cipher text to lowercase
    cipherText = cipherText.lower()

    # Calculate the frequency of each letter in the cipher text
    letterFrequency = {}
    for char in cipherText:
        if char.isalpha():
            if char in letterFrequency:
                letterFrequency[char] += 1
            else:
                letterFrequency[char] = 1

    # Calculate the total number of letters in the cipher text
    totalLetters = sum(letterFrequency.values())

    # Calculate the frequency of each letter
    for key in letterFrequency:
        letterFrequency[key] = letterFrequency[key] / totalLetters

    # Calculate the chi-squared value for each shift
    chiSquaredValues = {}
    for shift in range(26):
        chiSquaredValue = 0
        for key in frequency:
            shiftedKey = chr((ord(key) - 97 + shift) % 26 + 97)
            chiSquaredValue += (frequency[key] - letterFrequency.get(shiftedKey, 0)) ** 2 / frequency[key]

        chiSquaredValues[shift] = chiSquaredValue
    
    # Find the shift with the minimum chi-squared value
    minChiSquaredValue = min(chiSquaredValues.values())

    for shift in chiSquaredValues:
        if chiSquaredValues[shift] == minChiSquaredValue:
            return shift
    
    return -1


print("Break Ceaser Cipher: ", decryptCeaserCipher(CeaserCipherText, breakCeaserCipher(CeaserCipherText)))

# 4 - Implement Vigenere Cipher
def encryptVignere(plaintext, key):
    encryptedText = ""
    keyIndex = 0

    for char in plaintext:
        if char.isalpha():
            keyChar = key[keyIndex % len(key)]
            keyIndex += 1

            shift = ord(keyChar) - 97
            asciiValue = ord(char)

            if char.isupper():
                encryptedText += chr((asciiValue + shift - 65) % 26 + 65)
            elif char.islower():
                encryptedText += chr((asciiValue + shift - 97) % 26 + 97)
        else:
            encryptedText += char

    return encryptedText

def decryptVigenere(cipherText, key):
    decryptedText = ""
    keyIndex = 0

    for char in cipherText:
        if char.isalpha():
            keyChar = key[keyIndex % len(key)]
            keyIndex += 1

            shift = ord(keyChar) - 97
            asciiValue = ord(char)

            if char.isupper():
                decryptedText += chr((asciiValue - shift - 65) % 26 + 65)
            elif char.islower():
                decryptedText += chr((asciiValue - shift - 97) % 26 + 97)
        else:
            decryptedText += char

    return decryptedText

print("-Vigenere Cipher-")
vigenereCipherText = encryptVignere(vigenerePlainText, vigenereKey)
print("Encrypted Text: ", vigenereCipherText)
print("Decrypted Text: ", decryptVigenere(vigenereCipherText, vigenereKey))




# 5 Encrypt and Decrypt using 2 x 2 Hill Cipher
hillKey = [[1, 12], [5, 23]]
hillPlainText = "enigmamachine"

def char_to_num(c):
    return ord(c.upper()) - ord('A')

# Convert number to character (0=A, 1=B, ..., 25=Z)
def num_to_char(n):
    return chr((n % 26) + ord('A'))

def determinant_2x2(matrix):
    return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]

# Function to find the modular inverse of a number mod
def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 0:
            return -1  # Inverse doesn't exist
        if (a * x) % m == 1:
            return x
    return -1

def inverse_matrix_2x2(matrix):
    det = determinant_2x2(matrix) % 26
    det_inv = mod_inverse(det, 26)
    
    if det_inv == -1:
        raise ValueError("Matrix is not invertible in mod 26.")
    
    # Inverse matrix formula for 2x2 matrix:
    # [a, b]    ->   [ d, -b]
    # [c, d]    ->   [-c,  a]
    inverse = [[matrix[1][1] * det_inv % 26, -matrix[0][1] * det_inv % 26],
               [-matrix[1][0] * det_inv % 26, matrix[0][0] * det_inv % 26]]
    
    # Mod 26 can't handle negatives directly, so we handle it manually
    for i in range(2):
        for j in range(2):
            inverse[i][j] = inverse[i][j] % 26
    
    return inverse


# Encrypt using Hill cipher with a 2x2 matrix
def encryptHillCipher(plaintext, key_matrix):
    # Make sure the plaintext length
    if len(plaintext) % 2 != 0:
        plaintext += 'X'  # Padding with 'X

    # Convert plaintext to number pairs
    plaintext_pairs = [char_to_num(c) for c in plaintext]
    
    # Split plaintext into 2-letter blocks
    ciphertext = ''
    for i in range(0, len(plaintext_pairs), 2):
        x1 = plaintext_pairs[i]
        x2 = plaintext_pairs[i + 1]
        
        # Apply matrix multiplication and mod 26
        c1 = (key_matrix[0][0] * x1 + key_matrix[0][1] * x2) % 26
        c2 = (key_matrix[1][0] * x1 + key_matrix[1][1] * x2) % 26
        
        # Convert back to characters
        ciphertext += num_to_char(c1)
        ciphertext += num_to_char(c2)

    return ciphertext

# Decrypt using Hill cipher with a 2x2 matrix
def decryptHillCipher(ciphertext, key_matrix):
    # Find the inverse of the key matrix mod 26
    key_matrix_inv = inverse_matrix_2x2(key_matrix)
    
    # Convert ciphertext to number pairs
    ciphertext_pairs = [char_to_num(c) for c in ciphertext]
    
    # Split ciphertext into 2-letter blocks
    plaintext = ''
    for i in range(0, len(ciphertext_pairs), 2):
        c1 = ciphertext_pairs[i]
        c2 = ciphertext_pairs[i + 1]
        
        # Apply matrix multiplication with the inverse key matrix and mod 26
        p1 = (key_matrix_inv[0][0] * c1 + key_matrix_inv[0][1] * c2) % 26
        p2 = (key_matrix_inv[1][0] * c1 + key_matrix_inv[1][1] * c2) % 26
        
        # Convert back to characters
        plaintext += num_to_char(p1)
        plaintext += num_to_char(p2)

    return plaintext



print("-Hill Cipher-")
hillCipherText = encryptHillCipher(hillPlainText, hillKey)
print("Encrypted Text: ", hillCipherText)
print("Decrypted Text: ", decryptHillCipher(hillCipherText, hillKey))