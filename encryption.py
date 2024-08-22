from Crypto.Cipher import DES, AES, ARC4, Blowfish
# from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import DES3
from Crypto.Util.strxor import strxor

def encrypt_Caesar(data, shift):
    """
    Encrypts data using the Caesar Cipher algorithm.
    
    Parameters:
        data (str): The data to be encrypted.
        shift (int): The number of positions to shift the characters.
    
    Returns:
        str: The encrypted data.
    """
    encrypted_data = ""
    for char in data:
        if char.isalpha():  # Check if the character is alphabetic
            base = ord('a') if char.islower() else ord('A')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
        else:
            encrypted_char = char  # Non-alphabetic characters remain unchanged
        encrypted_data += encrypted_char
    return encrypted_data

def encrypt_Hill(data, key):
    """
    Encrypts data using the Hill Cipher algorithm.
    
    Parameters:
        data (str): The data to be encrypted (only alphabetic characters are considered).
        key (list of lists): The encryption key represented as a matrix.
            For example, for a 2x2 key matrix: [[a, b], [c, d]].
    
    Returns:
        str: The encrypted data.
    """
    # Convert data to uppercase and remove non-alphabetic characters
    data = ''.join(filter(str.isalpha, data.upper()))
    # Ensure the length of the data is a multiple of the key matrix size
    if len(data) % len(key[0]) != 0:
        raise ValueError("Data length must be a multiple of the key matrix size")
    # Convert characters to their respective numerical values (A=0, B=1, ..., Z=25)
    numeric_data = [(ord(char) - ord('A')) for char in data]
    encrypted_data = ""
    for i in range(0, len(numeric_data), len(key[0])):
        # Extract a block of data
        block = numeric_data[i:i+len(key[0])]
        # Encrypt the block using matrix multiplication
        encrypted_block = [(sum([key[j][k] * block[k] for k in range(len(key[0]))]) % 26) for j in range(len(key))]
        # Convert back to characters
        encrypted_data += ''.join([chr(val + ord('A')) for val in encrypted_block])
    return encrypted_data

def encrypt_Playfair(data, key):
    """
    Encrypts data using the Playfair Cipher algorithm.

    Parameters:
        data (str): The data to be encrypted (only alphabetic characters are considered).
        key (str): The encryption key (a string of unique alphabetic characters, usually a keyword).

    Returns:
        str: The encrypted data.
    """
    # Convert data to uppercase and remove non-alphabetic characters
    data = ''.join(filter(str.isalpha, data.upper()))
    
    # Create the Playfair square
    key = ''.join(dict.fromkeys(key.upper()))  # Remove duplicates and convert to uppercase
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J is omitted
    playfair_square = key
    for char in alphabet:
        if char not in playfair_square:
            playfair_square += char
    
    # Generate the encryption key table
    key_table = [[playfair_square[i+j*5] for i in range(5)] for j in range(5)]
    
    # Adjust the data for digraphs and encrypt
    digraphs = [(data[i], data[i+1]) if data[i] != data[i+1] else (data[i], 'X') for i in range(0, len(data), 2)]
    encrypted_data = ""
    for digraph in digraphs:
        encrypted_digraph = ""
        for char in digraph:
            row, col = [(row, col) for row in range(5) for col in range(5) if key_table[row][col] == char][0]
            if digraph.index(char) == 0:
                encrypted_digraph += key_table[row][(col+1) % 5]
            else:
                encrypted_digraph += key_table[(row+1) % 5][col]
        encrypted_data += encrypted_digraph
    return encrypted_data

def encrypt_Vernam(data, key):
    """
    Encrypts data using the Vernam Cipher algorithm.
    
    Parameters:
        data (str): The data to be encrypted.
        key (str): The encryption key (a string of characters).
    
    Returns:
        str: The encrypted data.
    """
    # Ensure the length of the key is at least as long as the data
    if len(key) < len(data):
        raise ValueError("Key length must be at least as long as the data")
    # Convert data and key to uppercase
    data = data.upper()
    key = key.upper()
    # Encrypt by XORing each character with the corresponding character in the key
    encrypted_data = ''.join([chr(ord(data[i]) ^ ord(key[i])) for i in range(len(data))])
    return encrypted_data

def encrypt_Railfence(data, key):
    """
    Encrypts data using the Rail Fence Cipher algorithm.
    
    Parameters:
        data (str): The data to be encrypted.
        key (int): The number of rails for the rail fence.
    
    Returns:
        str: The encrypted data.
    """
    # Create empty rails
    rails = ['' for _ in range(key)]
    # Fill the rails with the data
    direction = -1  # Direction of movement along the rails (down or up)
    row = 0  # Current row
    for char in data:
        rails[row] += char
        # Change direction if we reach the top or bottom rail
        if row == 0 or row == key - 1:
            direction *= -1
        row += direction
    # Join the rails to get the encrypted data
    encrypted_data = ''.join(rails)
    return encrypted_data

def encrypt_ColumnarTransposition(data, key):
    """
    Encrypts data using the Columnar Transposition Cipher algorithm.
    
    Parameters:
        data (str): The data to be encrypted.
        key (str): The encryption key (a string representing the order of columns).
    
    Returns:
        str: The encrypted data.
    """
    # Create a dictionary to store the position of each character in the key
    key_positions = {char: i for i, char in enumerate(key)}
    # Sort the key and use the sorted order to determine the column order
    sorted_key = ''.join(sorted(key))
    # Calculate the number of rows needed
    num_rows = len(data) // len(key) + (1 if len(data) % len(key) != 0 else 0)
    # Create an empty grid to store the data
    grid = [['' for _ in range(len(key))] for _ in range(num_rows)]
    # Fill the grid with the data
    for i, char in enumerate(data):
        row = i // len(key)
        col = i % len(key_positions)
        grid[row][key_positions[sorted_key[col]]] = char
    # Read the data from the grid in column order
    encrypted_data = ''.join(''.join(row) for row in grid)
    return encrypted_data

def encrypt_AES(data, key):
    """
    Encrypts data using AES (Advanced Encryption Standard) algorithm.
    
    Parameters:
        data (str): The data to be encrypted.
        key (bytes): The encryption key (must be 16, 24, or 32 bytes long).
    
    Returns:
        str: The encrypted data.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = _pad_data(data)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data.hex().strip()

def encrypt_DES(data, key):
    """
    Encrypts data using DES (Data Encryption Standard) algorithm.
    
    Parameters:
        data (str): The data to be encrypted.
        key (bytes): The encryption key (must be 8 bytes long).
    
    Returns:
        str: The encrypted data.
    """
    cipher = DES.new(key, DES.MODE_ECB)
    padded_data = _pad_data(data)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data.hex()

def encrypt_3DES(data, key):
    """
    Encrypts data using Triple DES (3DES) algorithm.
    
    Parameters:
        data (str): The data to be encrypted.
        key (bytes): The encryption key (must be 16 or 24 bytes long).
    
    Returns:
        str: The encrypted data.
    """
    # For Triple DES, we need to use TripleDES.new() instead of DES.new()
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_data = _pad_data(data)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data.hex()


def encrypt_Blowfish(data, key):
    """
    Encrypts data using Blowfish algorithm.
    
    Parameters:
        data (str): The data to be encrypted.
        key (bytes): The encryption key (must be 8 to 56 bytes long).
    
    Returns:
        str: The encrypted data.
    """
    # Ensure the key length is correct
    if not (8 <= len(key) <= 56):
        raise ValueError("Incorrect Blowfish key length (must be between 8 and 56 bytes)")
    
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_data = _pad_data(data)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data.hex()


def encrypt_RC4(data, key):
    """
    Encrypts data using RC4 (Rivest Cipher 4) algorithm.
    
    Parameters:
        data (str): The data to be encrypted.
        key (bytes): The encryption key.
    
    Returns:
        str: The encrypted data.
    """
    cipher = ARC4.new(key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data.hex()

def _pad_data(data):
    """
    Pads data to be encrypted.
    
    Parameters:
        data (str): The data to be padded.
    
    Returns:
        str: The padded data.
    """
    block_size = AES.block_size
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length  # Encode to bytes
    padded_data = data + padding
    return padded_data

