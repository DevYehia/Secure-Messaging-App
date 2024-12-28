from random import randint
import unittest
import sender
import receiver
from sympy import isprime


# ANSI Color Codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'

# Unit Test Cases
class UnitTestFunctions(unittest.TestCase):
    
    def setUp(self):
        self.AES_key = receiver.gen_aes_key()
        self.elgamal_public_key, self.elgamal_private_key = sender.elgamal_keygen()
        self.elgamal_p, self.elgamal_g, self.elgamal_y = self.elgamal_public_key
        self.RSA_private_key, self.RSA_public_key = sender.generate_rsa_keys()
        self.sample_plaintext = randint(1, self.elgamal_p - 1)
        self.RSA_message = b"Test message for RSA signing and verification."
        
        
    def tearDown(self):
        test_method = self._testMethodName
        result = self.defaultTestResult()
        test_outcome = [test for test in result.errors + result.failures if test[0] == self]
        if test_outcome:
            print(f"{Colors.RED}Test '{test_method}' FAILED: {self.description}{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}Test '{test_method}' PASSED: {self.description}{Colors.RESET}")
    
    def test_AES_encrypt_decrypt(self):
        self.description = "AES Encrypts and decrypts a message correctly."
        plaintext = "This is a test message"
        ciphertext = sender.aes_encrypt(self.AES_key, plaintext)
        decrypted_text = receiver.aes_decrypt(self.AES_key, ciphertext)
        self.assertEqual(plaintext, decrypted_text, "Decrypted text should match the original plaintext")
    
    def test_AES_invalid_key(self):
        self.description = "Fails to decrypt with an incorrect AES key."
        plaintext = "Another message"
        ciphertext = sender.aes_encrypt(self.AES_key, plaintext)
        wrong_key = receiver.get_random_bytes(16)
        with self.assertRaises(ValueError):
            receiver.aes_decrypt(wrong_key, ciphertext)
            
    def test_AES_invalid_ciphertext(self):
        self.description = "AES Fails to decrypt a corrupted ciphertext."
        plaintext = "Valid plaintext"
        ciphertext = sender.aes_encrypt(self.AES_key, plaintext)
        corrupted_ciphertext = ciphertext[:-4] + "abcd"
        with self.assertRaises(ValueError):
            receiver.aes_decrypt(self.AES_key, corrupted_ciphertext)
            
    def test_AES_empty_plaintext(self):
        self.description = "AES Handles empty plaintext correctly."
        plaintext = ""
        ciphertext = sender.aes_encrypt(self.AES_key, plaintext)
        decrypted_text = receiver.aes_decrypt(self.AES_key, ciphertext)
        self.assertEqual(plaintext, decrypted_text, "Decrypted text for empty input should also be empty")
    
    
    def test_AES_large_text(self):
        self.description = "AES Encrypts and decrypts large plaintext correctly."
        plaintext = "A" * 10000
        ciphertext = sender.aes_encrypt(self.AES_key, plaintext)
        decrypted_text = receiver.aes_decrypt(self.AES_key, ciphertext)
        self.assertEqual(plaintext, decrypted_text, "Decrypted text should match the original large plaintext")

    
    def test_elgamal_key_generation(self):
        self.description = "Test ElGamal key generation."
        p, g, y = self.elgamal_public_key
        x = self.elgamal_private_key
        self.assertTrue(isprime(p), "Generated p should be a prime number.")
        self.assertTrue(1 < g < p, "Generator g should be in the range (1, p).")
        self.assertTrue(1 <= x < p, "Private key x should be in the range (1, p).")
        self.assertEqual(pow(g, x, p), y, "Public key component y should match g^x mod p.")

    def test_elgamal_encrypt_decrypt(self):
        self.description = "Test ElGamal Encrypt and Decrypt."
        ciphertext = receiver.elgamal_encrypt(self.elgamal_public_key, self.sample_plaintext)
        decrypted_plaintext = sender.elgamal_decrypt(self.elgamal_private_key, self.elgamal_public_key, ciphertext)
        self.assertEqual(self.sample_plaintext, decrypted_plaintext, "Decrypted plaintext should match the original.")

    def test_elgamal_invalid_plaintext(self):
        self.description = "Test ElGamal Invalid plaintext."
        invalid_plaintext = self.elgamal_p
        with self.assertRaises(ValueError):
            receiver.elgamal_encrypt(self.elgamal_public_key, invalid_plaintext)

    def test_elgamal_edge_case_plaintext(self):
        self.description = "Test ElGamal Maximum valid plaintext."
        plaintext = 0
        ciphertext = receiver.elgamal_encrypt(self.elgamal_public_key, plaintext)
        decrypted_plaintext = sender.elgamal_decrypt(self.elgamal_private_key, self.elgamal_public_key, ciphertext)
        self.assertEqual(plaintext, decrypted_plaintext, "Decrypted plaintext should match zero plaintext.")

        plaintext = self.elgamal_p - 1
        ciphertext = receiver.elgamal_encrypt(self.elgamal_public_key, plaintext)
        decrypted_plaintext = sender.elgamal_decrypt(self.elgamal_private_key, self.elgamal_public_key, ciphertext)
        self.assertEqual(plaintext, decrypted_plaintext, "Decrypted plaintext should match the maximum valid plaintext.")
    
    def test_RSA_key_generation(self):
        self.description = "Test RSA key generation."
        private_key, public_key = sender.generate_rsa_keys()
        self.assertIsNotNone(private_key, "Private key should not be None.")
        self.assertIsNotNone(public_key, "Public key should not be None.")
        self.assertTrue(isinstance(private_key, bytes), "Private key should be in bytes format.")
        self.assertTrue(isinstance(public_key, bytes), "Public key should be in bytes format.")

    def test_RSA_sign_and_verify(self):
        self.description = "RSA Test signing a message and verifying it."
        signature = sender.rsa_sign(self.RSA_private_key, self.RSA_message)
        result = receiver.rsa_verify(self.RSA_public_key, self.RSA_message, signature)
        self.assertTrue(result, "Signature verification should succeed for a valid signature.")

    def test_RSA_invalid_signature(self):
        self.description = "RSA Test verifying an invalid signature fails."
        signature = sender.rsa_sign(self.RSA_private_key, self.RSA_message)
        modified_message = self.RSA_message + b"tampered"
        result = receiver.rsa_verify(self.RSA_public_key, modified_message, signature)
        self.assertFalse(result, "Signature verification should fail for an invalid signature.")

    def test_RSA_wrong_key_verification(self):
        self.description = "RSA Test verification with wrong public key fail."
        another_private_key, another_public_key = sender.generate_rsa_keys()
        signature = sender.rsa_sign(self.RSA_private_key, self.RSA_message)
        result = receiver.rsa_verify(another_public_key, self.RSA_message, signature)
        self.assertFalse(result, "Verification should fail with a mismatched public key.")

    def test_RSA_empty_message(self):
        self.description = "RSA Test signing and verifying an empty message."
        empty_message = b""
        signature = sender.rsa_sign(self.RSA_private_key, empty_message)
        result = receiver.rsa_verify(self.RSA_public_key, empty_message, signature)
        self.assertTrue(result, "Verification should succeed for an empty message.")

    def test_RSA_large_message(self):
        self.description = "RSA Test signing and verifying a large message."
        large_message = b"A" * 1024 * 1024
        signature = sender.rsa_sign(self.RSA_private_key, large_message)
        result = receiver.rsa_verify(self.RSA_public_key, large_message, signature)
        self.assertTrue(result, "Verification should succeed for a large message.")





if __name__ == "__main__":
    unittest.main()