from random import randint
import unittest
import sender
import receiver
from sympy import isprime

# Unit Test Cases
class UnitTestFunctions(unittest.TestCase):
    
    def setUp(self):
        self.key = receiver.gen_aes_key()
        self.elgamal_public_key, self.elgamal_private_key = sender.elgamal_keygen()
        self.elgamal_p, self.elgamal_g, self.elgamal_y = self.elgamal_public_key
        self.RSA_private_key, self.RSA_public_key = sender.generate_rsa_keys()
        self.sample_plaintext = randint(1, self.p - 1)
        
        
    def tearDown(self):
        test_method = self._testMethodName
        result = self.defaultTestResult()
        test_outcome = [test for test in result.errors + result.failures if test[0] == self]
        if test_outcome:
            print(f"Test '{test_method}' FAILED: {self.description}")
        else:
            print(f"Test '{test_method}' PASSED: {self.description}")
    
    def test_AES_encrypt_decrypt(self):
        self.description = "AES Encrypts and decrypts a message correctly."
        plaintext = "This is a test message"
        ciphertext = sender.aes_encrypt(self.key, plaintext)
        decrypted_text = receiver.aes_decrypt(self.key, ciphertext)
        self.assertEqual(plaintext, decrypted_text, "Decrypted text should match the original plaintext")
    
    def test_AES_invalid_key(self):
        self.description = "Fails to decrypt with an incorrect AES key."
        plaintext = "Another message"
        ciphertext = sender.aes_encrypt(self.key, plaintext)
        wrong_key = receiver.get_random_bytes(16)
        with self.assertRaises(ValueError):
            receiver.aes_decrypt(wrong_key, ciphertext)
            
    def test_AES_invalid_ciphertext(self):
        self.description = "AES Fails to decrypt a corrupted ciphertext."
        plaintext = "Valid plaintext"
        ciphertext = sender.aes_encrypt(self.key, plaintext)
        corrupted_ciphertext = ciphertext[:-4] + "abcd"
        with self.assertRaises(ValueError):
            receiver.aes_decrypt(self.key, corrupted_ciphertext)
            
    def test_AES_empty_plaintext(self):
        self.description = "AES Handles empty plaintext correctly."
        plaintext = ""
        ciphertext = sender.aes_encrypt(self.key, plaintext)
        decrypted_text = receiver.aes_decrypt(self.key, ciphertext)
        self.assertEqual(plaintext, decrypted_text, "Decrypted text for empty input should also be empty")
    
    
    def test_AES_large_text(self):
        self.description = "AES Encrypts and decrypts large plaintext correctly."
        plaintext = "A" * 10000
        ciphertext = sender.aes_encrypt(self.key, plaintext)
        decrypted_text = receiver.aes_decrypt(self.key, ciphertext)
        self.assertEqual(plaintext, decrypted_text, "Decrypted text should match the original large plaintext")

    
    def test_elgamal_key_generation(self):
        self.description = "Test ElGamal key generation."
        p, g, y = self.public_key
        x = self.private_key
        self.assertTrue(isprime(p), "Generated p should be a prime number.")
        self.assertTrue(1 < g < p, "Generator g should be in the range (1, p).")
        self.assertTrue(1 <= x < p, "Private key x should be in the range (1, p).")
        self.assertEqual(pow(g, x, p), y, "Public key component y should match g^x mod p.")

    def test_elgamal_encrypt_decrypt(self):
        self.description = "Test ElGamal Encrypt and Decrypt."
        ciphertext = receiver.elgamal_encrypt(self.public_key, self.sample_plaintext)
        decrypted_plaintext = sender.elgamal_decrypt(self.private_key, self.public_key, ciphertext)
        self.assertEqual(self.sample_plaintext, decrypted_plaintext, "Decrypted plaintext should match the original.")

    def test_elgamal_invalid_plaintext(self):
        self.description = "Test ElGamal Invalid plaintext."
        invalid_plaintext = self.p
        with self.assertRaises(ValueError):
            receiver.elgamal_encrypt(self.public_key, invalid_plaintext)

    def test_elgamal_invalid_ciphertext(self):
        self.description = "Test ElGamal Invalid Cyphertext."
        ciphertext = receiver.elgamal_encrypt(self.public_key, self.sample_plaintext)
        invalid_ciphertext = (ciphertext[0], ciphertext[1] + 1)
        with self.assertRaises(ValueError):
            sender.elgamal_decrypt(self.private_key, self.public_key, invalid_ciphertext)

    def test_elgamal_edge_case_plaintext(self):
        self.description = "Test ElGamal Maximum valid plaintext."
        plaintext = 0
        ciphertext = receiver.elgamal_encrypt(self.public_key, plaintext)
        decrypted_plaintext = sender.elgamal_decrypt(self.private_key, self.public_key, ciphertext)
        self.assertEqual(plaintext, decrypted_plaintext, "Decrypted plaintext should match zero plaintext.")

        plaintext = self.p - 1
        ciphertext = receiver.elgamal_encrypt(self.public_key, plaintext)
        decrypted_plaintext = sender.elgamal_decrypt(self.private_key, self.public_key, ciphertext)
        self.assertEqual(plaintext, decrypted_plaintext, "Decrypted plaintext should match the maximum valid plaintext.")




if __name__ == "__main__":
    unittest.main()