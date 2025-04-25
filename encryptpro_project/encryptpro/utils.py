# encryptpro/utils.py
import random
import string
import os


def generate_appropriate_key(algorithm_name, text_byte_length=0):
    """Generates a suitable key based on the algorithm."""

    generated_key = ""

    try:
        if algorithm_name == "OTP":
            if text_byte_length <= 0:
                raise ValueError("Text length needed for OTP key generation.")
            # Use cryptographically secure random bytes
            key_bytes = os.urandom(text_byte_length)
            # Encode bytes to hex for reliable display/copy-paste
            generated_key = key_bytes.hex()

        elif algorithm_name == "Caesar" or algorithm_name == "Rail Fence":
            # Caesar shift usually 1-25, Rail Fence rails >= 2
            max_val = 25 if algorithm_name == "Caesar" else 10  # Example max rails
            min_val = 1 if algorithm_name == "Caesar" else 2
            generated_key = str(random.randint(min_val, max_val))

        elif algorithm_name == "Substitution":
            alphabet = list(string.ascii_lowercase)
            random.shuffle(alphabet)
            generated_key = "".join(alphabet)

        elif algorithm_name == "Playfair" or algorithm_name == "Transposition":
            # Simple random keyword suggestion
            words = ["SECRET", "KEYWORD", "CIPHER", "RANDOM", "SECURE", "PYTHON", "ENCRYPT", "CODE"]
            word_part = random.choice(words)
            num_part = str(random.randint(100,
                                          999)) if algorithm_name == "Transposition" else ""  # Transposition often uses longer keys
            generated_key = word_part + num_part

        elif algorithm_name == "ROT13":
            generated_key = ""  # No key needed

        else:
            raise ValueError(f"Unknown algorithm '{algorithm_name}' for key generation.")

        return generated_key

    except Exception as e:
        # Re-raise or handle specific errors if needed
        raise ValueError(f"Key generation failed for {algorithm_name}: {e}")