import numpy as np
from numpy.linalg import inv, det

def gcd(a, b):
    """Compute the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def mod_inv(x, mod):
    """Find the modular inverse of x under modulo."""
    return pow(x % mod, -1, mod)

def mod_matrix_inv(matrix, mod=26):
    """Find the modular inverse of a matrix under modulo."""
    det_val = int(round(det(matrix)))
    det_inv = mod_inv(det_val, mod)
    minors = np.array([
        det(np.delete(np.delete(matrix, i, axis=0), j, axis=1))
        for i in range(matrix.shape[0])
        for j in range(matrix.shape[1])
    ]).reshape(matrix.shape)
    cofactors = ((-1) ** (np.arange(matrix.shape[0])[:, None] + np.arange(matrix.shape[1]))) * minors
    adjugate = cofactors.T
    matrix_inv = (det_inv * adjugate) % mod
    return np.round(matrix_inv).astype(int) % mod

def generate_key(key_string):
    """Generate a key matrix from a key string."""
    if len(key_string) != 9:
        raise ValueError("Invalid key length. Key must be 9 characters long.")
    key = np.array([ord(c) - ord('A') for c in key_string.upper()]).reshape((3, 3))
    det_val = int(round(det(key))) % 26
    if det_val == 0 or gcd(det_val, 26) != 1:
        raise ValueError("Invalid key. Determinant must not be zero and must be coprime with 26.")
    return key % 26

def pad_text(text, block_size):
    """Add padding to the text to make its length a multiple of block_size."""
    text = text.upper().replace(" ", "")
    if len(text) % block_size != 0:
        text += 'X' * (block_size - len(text) % block_size)
    return text

def unpad_text(text):
    """Remove padding from the text."""
    return text.rstrip('X')

def process_text(text, block_size):
    """Convert text to a matrix with padding if needed."""
    text = pad_text(text, block_size)
    return np.array([ord(c) - ord('A') for c in text]).reshape(-1, block_size)

def encrypt(plain_text, key):
    """Encrypt plaintext using the given key matrix."""
    plain_blocks = process_text(plain_text, 3)
    cipher_blocks = (key @ plain_blocks.T) % 26
    return ''.join(chr(int(val) + ord('A')) for val in cipher_blocks.T.flatten())

def decrypt(cipher_text, key):
    """Decrypt ciphertext using the given key matrix."""
    cipher_blocks = process_text(cipher_text, 3)
    key_inv = mod_matrix_inv(key, 26)
    plain_blocks = (key_inv @ cipher_blocks.T) % 26
    plain_text = ''.join(chr(int(val) + ord('A')) for val in plain_blocks.T.flatten())
    return unpad_text(plain_text)

def text_to_matrix(text, size=3):
    """Convert a string of text to a matrix of given size."""
    numbers = [ord(char) - ord('A') for char in text]
    return np.array(numbers).reshape(size, size)

def matrix_to_text(matrix):
    """Convert a matrix of numbers to a string of text."""
    return ''.join(chr(int(num) + ord('A')) for num in matrix.flatten())

def find_key(plaintext, ciphertext):
    """Find the key matrix from given plaintext and ciphertext."""
    size = 3
    plain_matrix = text_to_matrix(plaintext, size)
    cipher_matrix = text_to_matrix(ciphertext, size) 
    plain_matrix_inv = mod_matrix_inv(plain_matrix)
    key_matrix = (cipher_matrix @ plain_matrix_inv) % 26 
    return np.round(key_matrix).astype(int) % 26

def main():
    try:
        key_input = input("Enter the key (9 letters): ")
        key = generate_key(key_input)
        
        message = input("Enter the message to encrypt: ")
        encrypted_message = encrypt(message, key)
        print(f"Encrypted Message: {encrypted_message}")
        
        decrypted_message = decrypt(encrypted_message, key)
        print(f"Decrypted Message: {decrypted_message}")
        
        plaintext = input("Enter the plaintext for key finding: ")
        ciphertext = input("Enter the ciphertext for key finding: ")
        key_matrix = find_key(plaintext[:9], ciphertext[:9])
        print(f"Found Key Matrix: {matrix_to_text(key_matrix)}")
        
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
