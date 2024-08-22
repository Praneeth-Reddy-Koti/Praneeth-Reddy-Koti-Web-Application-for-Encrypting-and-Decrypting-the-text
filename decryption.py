from Crypto.Cipher import DES, AES, Blowfish
from Crypto.Cipher import DES3
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import unpad
from encryption import encrypt_AES, encrypt_DES, encrypt_3DES, encrypt_Blowfish, encrypt_RC4, encrypt_Caesar, encrypt_Hill, encrypt_Playfair, encrypt_Vernam, encrypt_Railfence, encrypt_ColumnarTransposition

def decrypt_Caesar(encrypted_data, shift):
    """
    Decrypts data encrypted using the Caesar Cipher algorithm.
    
    Parameters:
        encrypted_data (str): The encrypted data.
        shift (int): The number of positions the characters were shifted.
    
    Returns:
        str: The decrypted data.
    """
    return encrypt_Caesar(encrypted_data, -shift)

def decrypt_Hill(encrypted_data, key):
    """
    Decrypts data encrypted using the Hill Cipher algorithm.
    NOTE: Requires matrix inversion and modulo operation over Z26 which is not implemented here.

    Parameters:
        encrypted_data (str): The encrypted data.
        key (list of lists): The encryption key matrix used during encryption.
    
    Returns:
        str: The decrypted data.
    """
    # This function needs a proper implementation of the matrix inverse modulo 26.
    raise NotImplementedError("Matrix inversion under modulo 26 not implemented.")

def decrypt_Playfair(encrypted_data, key):
    """
    Decrypts data encrypted using the Playfair Cipher algorithm.

    Parameters:
        encrypted_data (str): The encrypted data.
        key (str): The encryption key used during encryption.

    Returns:
        str: The decrypted data.
    """
    # This function would need a full implementation of the Playfair decryption process.
    raise NotImplementedError("Full decryption for Playfair Cipher not implemented.")

def decrypt_Vernam(encrypted_data, key):
    """
    Decrypts data encrypted using the Vernam Cipher algorithm.
    
    Parameters:
        encrypted_data (str): The encrypted data.
        key (str): The encryption key used during encryption.
    
    Returns:
        str: The decrypted data.
    """
    # Vernam decryption is identical to encryption, just apply the same function.
    return encrypt_Vernam(encrypted_data, key)

def decrypt_Railfence(encrypted_data, key):
    """
    Decrypts data encrypted using the Rail Fence Cipher algorithm.
    
    Parameters:
        encrypted_data (str): The encrypted data.
        key (int): The number of rails used during encryption.
    
    Returns:
        str: The decrypted data.
    """
    # The actual Rail Fence decryption implementation
    # First figure out the distribution of characters over the rails
    length = len(encrypted_data)
    rails = ['' for _ in range(key)]
    # Calculate how many full cycles of zig-zagging we can perform with the data length
    cycle_len = 2 * key - 2
    full_cycles = length // cycle_len
    remain = length % cycle_len
    
    # Determine how many characters each rail gets
    counts = [full_cycles * (1 if i == 0 or i == key-1 else 2) for i in range(key)]
    for i in range(remain):
        counts[min(i, cycle_len - i)] += 1
    
    # Now distribute the encrypted data into the rails
    pos = 0
    for i in range(key):
        rails[i] = encrypted_data[pos:pos+counts[i]]
        pos += counts[i]

    # Reconstruct the original message
    direction = -1
    row = 0
    decrypted_data = ''
    for i in range(length):
        decrypted_data += rails[row][0]
        rails[row] = rails[row][1:]
        if row == 0 or row == key - 1:
            direction *= -1
        row += direction

    return decrypted_data

def decrypt_ColumnarTransposition(encrypted_data, key):
    """
    Decrypts data encrypted using the Columnar Transposition Cipher algorithm.
    
    Parameters:
        encrypted_data (str): The encrypted data.
        key (str): The encryption key (a string representing the order of columns).
    
    Returns:
        str: The decrypted data.
    """
    # Create a dictionary to store the position of each character in the key
    key_positions = {char: i for i, char in enumerate(key)}
    # Sort the key and use the sorted order to determine the column order
    sorted_key = ''.join(sorted(key))
    # Calculate the number of rows
    num_rows = len(encrypted_data) // len(key) + (1 if len(encrypted_data) % len(key) != 0 else 0)
    # Create an empty grid to store the data
    grid = [['' for _ in range(len(key))] for _ in range(num_rows)]
    # Fill the grid with the encrypted data
    for i, char in enumerate(encrypted_data):
        row = i // len(sorted_key)
        col = i % len(sorted_key)
        grid[row][key_positions[sorted_key[col]]] = char
    # Read the data from the grid in row order
    decrypted_data = ''.join(''.join(row) for row in grid)
    return decrypted_data.rstrip()


def decrypt_AES(encrypted_data, key):
    """
    Decrypts data encrypted using AES (Advanced Encryption Standard) algorithm.
    
    Parameters:
        encrypted_data (str): The encrypted data in hexadecimal.
        key (bytes): The encryption key used during encryption.
    
    Returns:
        str: The decrypted data.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

def decrypt_DES(encrypted_data, key):
    """
    Decrypts data encrypted using DES (Data Encryption Standard) algorithm.
    
    Parameters:
        encrypted_data (str): The encrypted data in hexadecimal.
        key (bytes): The encryption key used during encryption.
    
    Returns:
        str: The decrypted data.
    """
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

def decrypt_3DES(encrypted_data, key):
    """
    Decrypts data encrypted using Triple DES (3DES) algorithm.
    
    Parameters:
        encrypted_data (str): The encrypted data in hexadecimal.
        key (bytes): The encryption key used during encryption.
    
    Returns:
        str: The decrypted data.
    """
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

def decrypt_Blowfish(encrypted_data, key):
    """
    Decrypts data encrypted using Blowfish algorithm.
    
    Parameters:
        encrypted_data (str): The encrypted data in hexadecimal.
        key (bytes): The encryption key used during encryption.
    
    Returns:
        str: The decrypted data.
    """
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

def decrypt_RC4(encrypted_data, key):
    """
    Decrypts data encrypted using RC4 (Rivest Cipher 4) algorithm.
    
    Parameters:
        encrypted_data (str): The encrypted data.
        key (bytes): The encryption key used during encryption.
    
    Returns:
        str: The decrypted data.
    """
    cipher = ARC4.new(key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

def _unpad_data(data):
    """
    Removes padding from the decrypted data according to PKCS#7.
    
    Parameters:
        data (bytes): The padded data.
    
    Returns:
        bytes: The unpadded data.
    """
    return unpad(data, AES.block_size)

# Example usage (provide appropriate encrypted_data and keys):
# decrypted_text = decrypt_AES('encrypted_hex_data', b'sixteen_byte_key')
# print(decrypted_text)
