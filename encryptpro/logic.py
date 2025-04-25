# encryptpro/logic.py
import string
import math


class EncryptionLogic:
    # --- All methods from the previous EncryptionLogic class go here ---
    # (Caesar, ROT13, Playfair, Transposition, Substitution, OTP, Rail Fence)
    # ... (Keep the exact code from the previous example's EncryptionLogic class) ...

    def _prepare_playfair_key(self, key):
        key = key.upper().replace("J", "I")
        key_set = set()
        processed_key = ""
        for char in key:
            if char.isalpha() and char not in key_set:
                processed_key += char
                key_set.add(char)

        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No J
        for char in alphabet:
            if char not in key_set:
                processed_key += char

        matrix = [['' for _ in range(5)] for _ in range(5)]
        k = 0
        for r in range(5):
            for c in range(5):
                matrix[r][c] = processed_key[k]
                k += 1
        return matrix

    def _get_char_pos(self, matrix, char):
        for r in range(5):
            for c in range(5):
                if matrix[r][c] == char:
                    return r, c
        return -1, -1  # Should not happen with prepared text

    def _prepare_playfair_text(self, text):
        text = text.upper().replace("J", "I")
        processed_text = ""
        for char in text:
            if char.isalpha():
                processed_text += char

        # Insert 'X' between duplicate letters in digraphs
        i = 0
        final_text = ""
        while i < len(processed_text):
            final_text += processed_text[i]
            if i + 1 < len(processed_text):
                if processed_text[i] == processed_text[i + 1]:
                    final_text += 'X'
                else:
                    final_text += processed_text[i + 1]
                    i += 1
            i += 1

        # Pad with 'X' if length is odd
        if len(final_text) % 2 != 0:
            final_text += 'X'

        return final_text

    def playfair_cipher(self, text, key, encrypt=True):
        if not key:
            raise ValueError("Playfair requires a keyword.")

        matrix = self._prepare_playfair_key(key)
        # Decrypt needs uppercase input, ensure it for both cases before preparing
        text_upper = text.upper()
        prepared_text = self._prepare_playfair_text(text_upper)

        result = ""
        shift = 1 if encrypt else -1

        for i in range(0, len(prepared_text), 2):
            c1 = prepared_text[i]
            c2 = prepared_text[i + 1]

            r1, col1 = self._get_char_pos(matrix, c1)
            r2, col2 = self._get_char_pos(matrix, c2)

            if r1 == -1 or r2 == -1:  # Character not in matrix (shouldn't happen with prep)
                raise ValueError(f"Invalid character found in Playfair input: {c1 if r1 == -1 else c2}")

            if r1 == r2:  # Same row
                result += matrix[r1][(col1 + shift) % 5]
                result += matrix[r2][(col2 + shift) % 5]
            elif col1 == col2:  # Same column
                result += matrix[(r1 + shift) % 5][col1]
                result += matrix[(r2 + shift) % 5][col2]
            else:  # Rectangle
                result += matrix[r1][col2]
                result += matrix[r2][col1]

        # Attempt to restore original case during encryption if desired (more complex)
        # For simplicity, Playfair often returns full uppercase. We'll stick to that.
        return result

    def caesar_cipher(self, text, key, encrypt=True):
        try:
            shift = int(key)
        except ValueError:
            raise ValueError("Caesar key must be an integer.")

        if not encrypt:
            shift = -shift

        result = ""
        for char in text:
            if 'a' <= char <= 'z':
                result += chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
            else:
                result += char  # Keep non-alpha characters
        return result

    def rot13_cipher(self, text):
        # ROT13 is its own inverse and a special case of Caesar
        return self.caesar_cipher(text, 13, True)

    def substitution_cipher(self, text, key, encrypt=True):
        alphabet = string.ascii_lowercase
        if not key or len(key) != 26 or not all(c.lower() in string.ascii_lowercase for c in key) or len(
                set(key.lower())) != 26:
            raise ValueError("Substitution key must be a 26-letter unique permutation of the alphabet.")

        key_map = key.lower()

        # Create mapping dictionaries
        enc_map = {alphabet[i]: key_map[i] for i in range(26)}
        dec_map = {key_map[i]: alphabet[i] for i in range(26)}

        map_to_use = enc_map if encrypt else dec_map

        result = ""
        for char in text:
            lower_char = char.lower()
            if lower_char in map_to_use:
                mapped_char = map_to_use[lower_char]
                result += mapped_char.upper() if char.isupper() else mapped_char
            else:
                result += char  # Keep non-alpha chars
        return result

    def transposition_cipher(self, text, key, encrypt=True):
        if not key:
            raise ValueError("Transposition requires a keyword.")

        key_len = len(key)
        # Ensure unique key characters for simple sort order, or handle ties consistently
        # Adding index to handle duplicate chars in key
        key_order = sorted([(key[i], i) for i in range(key_len)])

        if encrypt:
            num_cols = key_len
            num_rows = math.ceil(len(text) / num_cols)
            padded_len = num_rows * num_cols
            # Use a less common padding character if possible, or remember padding length
            padding_char = '~'
            text += padding_char * (padded_len - len(text))

            grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
            k = 0
            for r in range(num_rows):
                for c in range(num_cols):
                    if k < len(text):  # Check bounds just in case
                        grid[r][c] = text[k]
                        k += 1

            ciphertext = ""
            for _, col_index in key_order:
                for r in range(num_rows):
                    ciphertext += grid[r][col_index]
            return ciphertext

        else:  # Decrypt
            num_cols = key_len
            text_len = len(text)
            num_rows = math.ceil(text_len / num_cols)

            if text_len % num_cols != 0:
                # Standard assumption: ciphertext length is correct for the grid size
                num_full_cols = text_len % num_cols
                num_short_rows = num_rows - 1
            else:
                num_full_cols = num_cols
                num_short_rows = num_rows  # All cols are full

            # Create an empty grid to place characters back
            grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]

            # Calculate number of chars per column based on key order and padding
            chars_in_col = {}
            num_placed = 0
            full_col_indices = sorted([idx for _, idx in key_order])[:num_full_cols]

            current_char_index = 0
            for char, col_index in key_order:
                col_len = num_rows if col_index in full_col_indices else num_short_rows
                for r in range(col_len):
                    if current_char_index < text_len:
                        grid[r][col_index] = text[current_char_index]
                        current_char_index += 1

            # Read the grid row by row
            plaintext = ""
            for r in range(num_rows):
                for c in range(num_cols):
                    if grid[r][c]:  # Avoid adding empty strings if logic was off
                        plaintext += grid[r][c]

            # Remove padding (assuming '~' was used)
            return plaintext.rstrip('~')

    def otp_cipher(self, text, key, encrypt=True):
        # Encode to handle potential multi-byte characters correctly
        try:
            text_bytes = text.encode('utf-8')
            key_bytes = key.encode('utf-8')
        except Exception as e:
            raise ValueError(f"Error encoding text or key to UTF-8: {e}")

        if len(text_bytes) != len(key_bytes):
            raise ValueError(
                f"OTP requires key byte length ({len(key_bytes)}) to equal text byte length ({len(text_bytes)}). Ensure compatible encoding.")

        result_bytes = bytes([b_text ^ b_key for b_text, b_key in zip(text_bytes, key_bytes)])

        # During decryption, the result might be original UTF-8 or binary
        # During encryption, the result is often binary junk
        if not encrypt:
            try:
                # Try decoding back to utf-8. If fails, it means the original was likely binary or different encoding.
                return result_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # Return as hex representation if not valid UTF-8. User needs context.
                print("Warning: OTP decryption result is not valid UTF-8, returning hex representation.")
                return result_bytes.hex()
        else:
            # Encrypted output is often not valid text, return hex
            return result_bytes.hex()

    def rail_fence_cipher(self, text, key, encrypt=True):
        try:
            rails = int(key)
        except ValueError:
            raise ValueError("Rail Fence key must be an integer (number of rails).")
        if rails < 2:
            raise ValueError("Rail Fence requires at least 2 rails.")

        text_len = len(text)
        if text_len == 0: return ""  # Handle empty input

        if encrypt:
            fence = [[] for _ in range(rails)]
            rail = 0
            direction = 1

            for char in text:
                fence[rail].append(char)
                rail += direction
                # Change direction at top/bottom rail
                if rail == rails - 1 or rail == 0:
                    # Need edge case for rails=2 where direction changes every step
                    if rails > 1: direction *= -1

            ciphertext = "".join("".join(row) for row in fence)
            return ciphertext

        else:  # Decrypt
            # Calculate fence pattern lengths
            cycle_len = 2 * rails - 2
            if cycle_len <= 0: cycle_len = 1  # Handle rails=1 case (though we check rails >= 2)

            fence_lengths = [0] * rails
            indices = [[] for _ in range(rails)]  # Store original indices for each rail

            rail = 0
            direction = 1
            for i in range(text_len):
                fence_lengths[rail] += 1
                indices[rail].append(i)
                rail += direction
                if rails > 1 and (rail == rails - 1 or rail == 0):
                    direction *= -1

            # Distribute ciphertext characters onto the rails
            fence = [['' for _ in range(length)] for length in fence_lengths]
            text_idx = 0
            for r in range(rails):
                for c in range(fence_lengths[r]):
                    fence[r][c] = text[text_idx]
                    text_idx += 1

            # Reconstruct plaintext using the indices
            plaintext_list = [''] * text_len
            rail_counters = [0] * rails
            for r in range(rails):
                for original_index in indices[r]:
                    plaintext_list[original_index] = fence[r][rail_counters[r]]
                    rail_counters[r] += 1

            return "".join(plaintext_list)