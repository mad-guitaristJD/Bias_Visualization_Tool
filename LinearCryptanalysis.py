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


class BreakCipher:
    # Try to break the cipher
    def __init__(self, cipher):
        self.cipher = cipher
        self.table = self.make_table()
    
    def make_table(self):
        # Make a table to show how sbox bits relate
        table = []
        for i in range(16):
            row = [0] * 16
            table.append(row)
        
        # Check every input and output pattern
        for input_pattern in range(16):
            for output_pattern in range(16):
                count = 0
                for x in range(16):
                    y = self.cipher.sbox[x]
                    
                    # Check input bits
                    input_sum = 0
                    for i in range(4):
                        if (input_pattern >> i) & 1:
                            input_sum = input_sum ^ ((x >> i) & 1)
                    
                    # Check output bits
                    output_sum = 0
                    for i in range(4):
                        if (output_pattern >> i) & 1:
                            output_sum = output_sum ^ ((y >> i) & 1)
                    
                    # Count matches
                    if input_sum == output_sum:
                        count = count + 1
                
                table[input_pattern][output_pattern] = count - 8
        
        return table
    
    def get_bias(self, input_pattern, output_pattern):
        # Get the bias from the table
        return self.table[input_pattern][output_pattern] / 16.0
    
    def find_good_patterns(self):
        # List some good patterns we know work
        patterns = [
            {'box': 1, 'in': 13, 'out': 4, 'bias': 0.25},
            {'box': 2, 'in': 4, 'out': 5, 'bias': -0.25},
            {'box': 3, 'in': 4, 'out': 5, 'bias': -0.25},
            {'box': 4, 'in': 4, 'out': 5, 'bias': -0.25}
        ]
        return patterns
    
    def try_break(self, num_texts=10000):
        # Make lots of text pairs
        plain_texts = []
        secret_texts = []
        for i in range(num_texts):
            plain = random.randint(0, 65535)
            secret = self.cipher.encrypt(plain)
            plain_texts.append(plain)
            secret_texts.append(secret)
        
        # Keep track of guesses
        guess_counts = {}
        
        # Try every possible key piece (0 to 255)
        for guess in range(256):
            part1 = (guess >> 4) & 15  # First 4 bits
            part2 = guess & 15         # Last 4 bits
            count = 0
            
            # Check each text pair
            for plain, secret in zip(plain_texts, secret_texts):
                # Undo parts of the last round
                box4_input = (secret >> 8) & 15
                box5_input = secret & 15
                
                box4_input = box4_input ^ part1
                box5_input = box5_input ^ part2
                
                box4_output = self.cipher.reverse_sbox[box4_input]
                box5_output = self.cipher.reverse_sbox[box5_input]
                
                # Put together some bits
                state = (box4_output << 8) | box5_output
                
                # Get certain bits
                bit6 = (state >> 10) & 1
                bit8 = (state >> 8) & 1
                bit14 = (state >> 2) & 1
                bit16 = state & 1
                
                # Get plaintext bits
                p5 = (plain >> 11) & 1
                p7 = (plain >> 9) & 1
                p8 = (plain >> 8) & 1
                
                # Check if pattern holds
                if bit6 ^ bit8 ^ bit14 ^ bit16 ^ p5 ^ p7 ^ p8 == 0:
                    count = count + 1
            
            guess_counts[guess] = count
        
        # Find best guess
        best_guess = 0
        best_diff = 0
        for guess, count in guess_counts.items():
            diff = abs(count - num_texts / 2)
            if diff > best_diff:
                best_diff = diff
                best_guess = guess
        
        best_bias = best_diff / num_texts
        
        # Get real key for checking
        real_key = self.cipher.keys[4]
        real_part1 = (real_key >> 8) & 15
        real_part2 = real_key & 15
        real_combined = (real_part1 << 4) | real_part2
        
        return best_guess, best_bias, real_combined, guess_counts


def main():
    # Start the cipher
    cipher = SimpleCipher()
    
    # Start the breaker
    breaker = BreakCipher(cipher)
    
    # Show the keys
    print("The real keys:")
    for i in range(5):
        print(f"Key {i+1}: {cipher.keys[i]:04X}")
    print()
    
    # Show the table
    print("Table of bit patterns:")
    print("In\\Out", end="")
    for j in range(16):
        print(f" {j:X}", end=" ")
    print()
    
    for i in range(16):
        print(f"{i:X}    ", end="")
        for j in range(16):
            print(f" {breaker.table[i][j]:2}", end="")
        print()
    print()
    
    # Show good patterns
    patterns = breaker.find_good_patterns()
    print("Good bit patterns:")
    for p in patterns:
        print(f"Box {p['box']}: Input {p['in']:X} -> Output {p['out']:X}, Bias: {p['bias']}")
    print()
    
    # Try to break the cipher
    print("Trying with 10,000 plaintexts and ciphertexts...")
    best_guess, best_bias, real_key, counts = breaker.try_break(10000)
    
    print(f"Best guess: {best_guess:02X}")
    print(f"Real key: {real_key:02X}")
    print(f"Bias: {best_bias:.6f} (should be around: {1/32:.6f})")
    print()
    
    # Show some results
    print("Some guess results:")
    print("Guess  Count  Bias")
    for guess in range(0, 256, 16):
        bias = abs(counts[guess] - 5000) / 10000
        print(f"  {guess:02X}   {counts[guess]:4}  {bias:.4f}")
    
    # Did we win?
    if best_guess == real_key:
        print("\nFound the right key.")
    else:
        print("\nWrong key.")


if __name__ == "__main__":
    main()
