import random

class SimpleCipher:
    def __init__(self):
        # This is the substitution box (sbox) for changing numbers
        self.sbox = {
            0: 14, 1: 4, 2: 13, 3: 1, 4: 2, 5: 15, 6: 11, 7: 8,
            8: 3, 9: 10, 10: 6, 11: 12, 12: 5, 13: 9, 14: 0, 15: 7
        }
        
        # Reverse sbox for undoing the substitution
        self.reverse_sbox = {}
        for key, value in self.sbox.items():
            self.reverse_sbox[value] = key
        
        # This is how we shuffle bits around
        self.permute = {
            1: 1, 2: 5, 3: 9, 4: 13, 5: 2, 6: 6, 7: 10, 8: 14,
            9: 3, 10: 7, 11: 11, 12: 15, 13: 4, 14: 8, 15: 12, 16: 16
        }
        
        # Reverse permutation for undoing the shuffle
        self.reverse_permute = {}
        for key, value in self.permute.items():
            self.reverse_permute[value] = key
        
        # Make 5 random keys (each 16 bits)
        self.keys = []
        for i in range(5):
            new_key = random.randint(0, 65535)  # 16-bit number
            self.keys.append(new_key)
    
    def do_sbox(self, number, use_reverse=False):
        # Change 16-bit number using sbox
        result = 0
        if use_reverse:
            box = self.reverse_sbox
        else:
            box = self.sbox
        
        # Break number into four 4-bit pieces
        for i in range(4):
            piece = (number >> (i * 4)) & 15  # Get 4 bits
            new_piece = box[piece]  # Look up in sbox
            result = result | (new_piece << (i * 4))  # Put back
        
        return result
    
    def do_permute(self, number, use_reverse=False):
        # Shuffle bits in 16-bit number
        result = 0
        if use_reverse:
            perm = self.reverse_permute
        else:
            perm = self.permute
        
        # Move each bit to its new place
        for i in range(16):
            bit = (number >> i) & 1  # Get one bit
            new_place = perm[i + 1] - 1  # Find where it goes
            result = result | (bit << new_place)  # Put bit there
        
        return result
    
    def encrypt(self, text):
        # Turn plain text into secret text
        current = text
        
        # Do three rounds of mixing
        for i in range(3):
            current = current ^ self.keys[i]  # Mix with key
            current = self.do_sbox(current)  # Substitute
            current = self.do_permute(current)  # Shuffle
        
        # Do one more round without shuffling
        current = current ^ self.keys[3]
        current = self.do_sbox(current)
        
        # Mix with final key
        secret = current ^ self.keys[4]
        
        return secret
    
    def decrypt(self, secret):
        # Turn secret text back to plain text
        current = secret
        
        # Undo final key mix
        current = current ^ self.keys[4]
        
        # Undo last round
        current = self.do_sbox(current, use_reverse=True)
        current = current ^ self.keys[3]
        
        # Undo first three rounds
        for i in range(2, -1, -1):
            current = self.do_permute(current, use_reverse=True)
            current = self.do_sbox(current, use_reverse=True)
            current = current ^ self.keys[i]
        
        return current


class DifferentialCipherBreaker:
    def __init__(self, cipher):
        self.cipher = cipher
        self.diff_table = self.make_difference_distribution_table()
    
    def make_difference_distribution_table(self):
        # Create a difference distribution table for the S-box
        table = [[0] * 16 for _ in range(16)]
        
        for input_diff in range(16):
            for x in range(16):
                x_prime = x ^ input_diff
                y = self.cipher.sbox[x]
                y_prime = self.cipher.sbox[x_prime]
                output_diff = y ^ y_prime
                table[input_diff][output_diff] += 1
        
        return table
    
    def get_diff_probability(self, input_diff, output_diff):
        # Get the probability of a differential
        return self.diff_table[input_diff][output_diff] / 16.0
    
    def generate_chosen_plaintexts(self, input_diff, num_pairs):
        # Generate chosen plaintext pairs with the specified input difference
        plaintext_pairs = []
        ciphertext_pairs = []
        
        for _ in range(num_pairs):
            p1 = random.randint(0, 65535)
            p2 = p1 ^ input_diff
            c1 = self.cipher.encrypt(p1)
            c2 = self.cipher.encrypt(p2)
            
            plaintext_pairs.append((p1, p2))
            ciphertext_pairs.append((c1, c2))
        
        return plaintext_pairs, ciphertext_pairs
    
    def filter_ciphertext_pairs(self, ciphertext_pairs):
        # Filter out pairs that don't have zero differences in S41 and S43 positions
        # S41 affects bits 1-4 (positions 12-15 in 0-indexed from right)
        # S43 affects bits 9-12 (positions 4-7 in 0-indexed from right)
        filtered_pairs = []
        
        for c1, c2 in ciphertext_pairs:
            # Check if differences in S41 and S43 positions are zero
            s41_diff = ((c1 >> 12) & 0xF) ^ ((c2 >> 12) & 0xF)  # Bits 12-15
            s43_diff = ((c1 >> 4) & 0xF) ^ ((c2 >> 4) & 0xF)    # Bits 4-7
            
            if s41_diff == 0 and s43_diff == 0:
                filtered_pairs.append((c1, c2))
        
        return filtered_pairs
    
    def try_break_differential(self, num_pairs=5000):
        # Differential characteristic from the paper
        input_diff = 0x0B00  # [0000 1011 0000 0000] in binary
        
        # Expected output difference after round 3 (before last round)
        expected_u4_diff = 0x0606  # [0000 0110 0000 0110] in binary
        
        # Generate chosen plaintext pairs
        plain_pairs, cipher_pairs = self.generate_chosen_plaintexts(input_diff, num_pairs)
        
        # Filter ciphertext pairs - only keep those with zero difference in S41 and S43
        filtered_pairs = self.filter_ciphertext_pairs(cipher_pairs)
        
        print(f"After filtering, {len(filtered_pairs)} pairs remain")
        
        # Keep track of guesses for the target partial subkey
        guess_counts = {}
        
        # Target partial subkey covers S42 and S44 (bits 5-8 and 13-16 of K5)
        for guess in range(256):  # 8 bits for the two S-boxes
            # Extract the two 4-bit parts of the guess
            part1 = (guess >> 4) & 15  # For S42 (bits 5-8)
            part2 = guess & 15         # For S44 (bits 13-16)
            
            count = 0
            
            for c1, c2 in filtered_pairs:
                # Extract the relevant ciphertext bits for S42 and S44
                # S42 covers bits 5-8 (0-indexed: bits 8-11 from right)
                s42_c1 = (c1 >> 8) & 15
                s42_c2 = (c2 >> 8) & 15
                
                # S44 covers bits 13-16 (0-indexed: bits 0-3 from right)
                s44_c1 = c1 & 15
                s44_c2 = c2 & 15
                
                # Partially decrypt the last round for these S-boxes
                s42_in1 = s42_c1 ^ part1
                s42_in2 = s42_c2 ^ part1
                s44_in1 = s44_c1 ^ part2
                s44_in2 = s44_c2 ^ part2
                
                # Reverse through the S-boxes
                s42_out1 = self.cipher.reverse_sbox[s42_in1]
                s42_out2 = self.cipher.reverse_sbox[s42_in2]
                s44_out1 = self.cipher.reverse_sbox[s44_in1]
                s44_out2 = self.cipher.reverse_sbox[s44_in2]
                
                # Calculate the input differences to the last round
                s42_diff = s42_out1 ^ s42_out2
                s44_diff = s44_out1 ^ s44_out2
                
                # Combine to form the full U4 difference
                u4_diff = (s42_diff << 8) | s44_diff
                
                # Check if it matches the expected difference
                if u4_diff == expected_u4_diff:
                    count += 1
            
            guess_counts[guess] = count
        
        # Find the best guess
        best_guess = 0
        best_count = 0
        
        for guess, count in guess_counts.items():
            if count > best_count:
                best_count = count
                best_guess = guess
        
        # Calculate the probability for the best guess
        prob = best_count / len(filtered_pairs) if filtered_pairs else 0
        
        # Get the real key for comparison
        real_key = self.cipher.keys[4]
        real_part1 = (real_key >> 8) & 15  # Bits 5-8 of K5
        real_part2 = real_key & 15         # Bits 13-16 of K5
        real_combined = (real_part1 << 4) | real_part2
        
        return best_guess, prob, real_combined, guess_counts, len(filtered_pairs)


def main():
    # Start the cipher
    cipher = SimpleCipher()
    
    # Start the differential breaker
    breaker = DifferentialCipherBreaker(cipher)
    
    # Show the keys
    print("The real keys:")
    for i in range(5):
        print(f"Key {i+1}: {cipher.keys[i]:04X}")
    print()
    
    # Show the difference distribution table
    print("Difference Distribution Table:")
    print("ΔX\\ΔY", end="")
    for j in range(16):
        print(f" {j:X}", end=" ")
    print()
    
    for i in range(16):
        print(f"{i:X}    ", end="")
        for j in range(16):
            print(f" {breaker.diff_table[i][j]:2}", end="")
        print()
    print()
    
    # Show some important differentials
    print("Important differentials from the paper:")
    important_diffs = [
        (0xB, 0x2, 8/16),  # S12: ΔX=B → ΔY=2 with probability 8/16
        (0x4, 0x6, 6/16),  # S23: ΔX=4 → ΔY=6 with probability 6/16
        (0x2, 0x5, 6/16),  # S32: ΔX=2 → ΔY=5 with probability 6/16
        (0x2, 0x5, 6/16)   # S33: ΔX=2 → ΔY=5 with probability 6/16
    ]
    
    for i, (in_diff, out_diff, prob) in enumerate(important_diffs, 1):
        actual_prob = breaker.get_diff_probability(in_diff, out_diff)
        print(f"S-box {i}: ΔX={in_diff:X} → ΔY={out_diff:X}")
        print(f"  Paper probability: {prob:.4f}, Actual: {actual_prob:.4f}")
    print()
    
    # Try to break the cipher using differential cryptanalysis
    print("Trying differential cryptanalysis with 5000 chosen plaintext pairs...")
    best_guess, prob, real_key, counts, filtered_count = breaker.try_break_differential(5000)
    
    print(f"Best guess: {best_guess:02X}")
    print(f"Real key: {real_key:02X}")
    print(f"Probability: {prob:.6f} (expected: {27/1024:.6f})")
    print(f"Filtered pairs used: {filtered_count}")
    print()
    
    # Show some results
    print("Some guess results:")
    print("Guess  Count  Probability")
    for guess in range(0, 256, 16):
        if filtered_count > 0:
            probability = counts[guess] / filtered_count
        else:
            probability = 0
        print(f"  {guess:02X}   {counts[guess]:4}  {probability:.4f}")
    
    # Did we win?
    if best_guess == real_key:
        print("\nFound the right key using differential cryptanalysis!")
    else:
        print("\nWrong key.")


if __name__ == "__main__":
    main()