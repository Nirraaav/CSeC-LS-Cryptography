from sympy import isprime, mod_inverse
import random
from Crypto.Util import number

class RSA:
    """Implements the RSA public key encryption / decryption."""

    def __init__(self, key_length):
        self.key_length = key_length
        self.p = number.getPrime(self.key_length)
        self.q = number.getPrime(self.key_length)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = 65537
        while gcd(self.e, self.phi) != 1:
            self.e = number.getRandomInteger(self.phi.bit_length())
        self.d = pow(self.e, -1, self.phi)

    def encrypt(self, binary_data):
        """Encrypt the binary data."""
        message = number.bytes_to_long(binary_data)
        return pow(message, self.e, self.n)

    def decrypt(self, encrypted_int_data):
        """Decrypt the encrypted data."""
        decrypted_message = pow(encrypted_int_data, self.d, self.n)
        return number.long_to_bytes(decrypted_message).decode()

class RSAParityOracle(RSA):
    """Extends the RSA class by adding a method to verify the parity of data."""

    def is_parity_odd(self, encrypted_int_data):
        """Decrypt the input data and return whether the resulting number is odd."""
        decrypted_message = pow(encrypted_int_data, self.d, self.n)
        return (decrypted_message % 2 == 1)

def parity_oracle_attack(ciphertext, rsa_parity_oracle):
    """Implement the attack and return the obtained plaintext."""
    left = 0
    right = rsa_parity_oracle.n
    
    while right - left > 1:
        c = (ciphertext * pow(2, rsa_parity_oracle.e, rsa_parity_oracle.n)) % rsa_parity_oracle.n
        odd = rsa_parity_oracle.is_parity_odd(c)
        if odd:
            left = (left + right) // 2
        else:
            right = (left + right) // 2

    return number.long_to_bytes(right)

def main():
    input_bytes = input("Enter the message: ").encode()

    # Generate a 1024-bit RSA pair    
    rsa_parity_oracle = RSAParityOracle(1024)

    # Encrypt the message
    ciphertext = rsa_parity_oracle.encrypt(input_bytes)
    print("Encrypted message is:", ciphertext)

    # Check if the attack works
    plaintext = parity_oracle_attack(ciphertext, rsa_parity_oracle)
    print("Obtained plaintext:", plaintext.decode())
    #assert plaintext == input_bytes

if __name__ == '__main__':
    main()
