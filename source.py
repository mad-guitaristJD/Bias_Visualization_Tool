import random
from collections import defaultdict

class BasicSPN:
    """
    Implementation of the Basic Substitution-Permutation Network (SPN) cipher
    as described in the tutorial paper.
    """
    
    def __init__(self):
        # S-box from Table 1 (hex: 0->E, 1->4, 2->D, 3->1, 4->2, 5->F, 6->B, 7->8,
        # 8->3, 9->A, A->6, B->C, C->5, D->9, E->0, F->7)
        self.sbox = {
            0x0: 0xE, 0x1: 0x4, 0x2: 0xD, 0x3: 0x1,
            0x4: 0x2, 0x5: 0xF, 0x6: 0xB, 0x7: 0x8,
            0x8: 0x3, 0x9: 0xA, 0xA: 0x6, 0xB: 0xC,
            0xC: 0x5, 0xD: 0x9, 0xE: 0x0, 0xF: 0x7
        }
        
        # Inverse S-box for decryption
        self.inv_sbox = {v: k for k, v in self.sbox.items()}
        
        # Permutation from Table 2
        # Maps bit position i to bit position permutation[i]
        self.permutation = {
            1: 1, 2: 5, 3: 9, 4: 13,
            5: 2, 6: 6, 7: 10, 8: 14,
            9: 3, 10: 7, 11: 11, 12: 15,
            13: 4, 14: 8, 15: 12, 16: 16
        }
        
        # Inverse permutation
        self.inv_permutation = {v: k for k, v in self.permutation.items()}
        
        # Generate random subkeys (K1 to K5)
        self.subkeys = [random.getrandbits(16) for _ in range(5)]
    
    def apply_sbox(self, data, inverse=False):
        """
        Apply S-box to 16-bit data (4 S-boxes in parallel)
        """
        result = 0
        sbox_to_use = self.inv_sbox if inverse else self.sbox
        
        for i in range(4):
            # Extract 4-bit chunk
            chunk = (data >> (4 * i)) & 0xF
            # Apply S-box
            substituted = sbox_to_use[chunk]
            # Place back
            result |= (substituted << (4 * i))
        
        return result
    
    def apply_permutation(self, data, inverse=False):
        """
        Apply bit permutation to 16-bit data
        """
        result = 0
        perm_to_use = self.inv_permutation if inverse else self.permutation
        
        for i in range(16):
            # Get the bit at position i+1 (1-indexed)
            bit = (data >> i) & 0x1
            # Find where this bit should go
            new_pos = perm_to_use[i+1] - 1  # Convert to 0-indexed
            # Set the bit in the result
            result |= (bit << new_pos)
        
        return result
    
    def encrypt(self, plaintext):
        """
        Encrypt a 16-bit plaintext using the SPN cipher
        """
        state = plaintext
        
        # Rounds 1-3: Substitution -> Permutation -> Key Mixing
        for i in range(3):
            # Key mixing
            state ^= self.subkeys[i]
            # Substitution
            state = self.apply_sbox(state)
            # Permutation
            state = self.apply_permutation(state)
        
        # Round 4: Substitution -> Key Mixing (no permutation in last round)
        state ^= self.subkeys[3]
        state = self.apply_sbox(state)
        
        # Final key mixing
        ciphertext = state ^ self.subkeys[4]
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        """
        Decrypt a 16-bit ciphertext using the SPN cipher
        """
        state = ciphertext
        
        # Reverse final key mixing
        state ^= self.subkeys[4]
        
        # Reverse round 4: Inverse Substitution -> Key Mixing
        state = self.apply_sbox(state, inverse=True)
        state ^= self.subkeys[3]
        
        # Rounds 3-1: Inverse Permutation -> Inverse Substitution -> Key Mixing
        for i in range(2, -1, -1):
            state = self.apply_permutation(state, inverse=True)
            state = self.apply_sbox(state, inverse=True)
            state ^= self.subkeys[i]
        
        return state


class LinearCryptanalysis:
    """
    Implementation of linear cryptanalysis on the Basic SPN cipher
    """
    
    def __init__(self, spn):
        self.spn = spn
        self.lat = self.generate_linear_approximation_table()
    
    def generate_linear_approximation_table(self):
        """
        Generate the Linear Approximation Table (LAT) for the S-box
        as described in Table 4 of the paper
        """
        lat = [[0 for _ in range(16)] for _ in range(16)]
        
        # For each input mask (a) and output mask (b)
        for a in range(16):  # Input mask (hex)
            for b in range(16):  # Output mask (hex)
                count = 0
                
                # Test all possible inputs
                for x in range(16):
                    # Apply S-box
                    y = self.spn.sbox[x]
                    
                    # Calculate input parity: a • x
                    input_parity = 0
                    for i in range(4):
                        if (a >> i) & 0x1:
                            input_parity ^= (x >> i) & 0x1
                    
                    # Calculate output parity: b • y
                    output_parity = 0
                    for i in range(4):
                        if (b >> i) & 0x1:
                            output_parity ^= (y >> i) & 0x1
                    
                    # Check if linear approximation holds
                    if input_parity == output_parity:
                        count += 1
                
                # Store count - 8 (bias * 16)
                lat[a][b] = count - 8
        
        return lat
    
    def get_linear_bias(self, input_mask, output_mask):
        """
        Get the linear bias for a given input and output mask
        """
        return self.lat[input_mask][output_mask] / 16.0
    
    def find_good_linear_approximation(self):
        """
        Find a good linear approximation for the cipher
        Based on the example in the paper (Figure 3)
        """
        # S-box approximations from the paper
        approximations = [
            # S12: X1⊕X3⊕X4 = Y2 with bias +1/4
            {'sbox': 1, 'input_mask': 0xD, 'output_mask': 0x4, 'bias': 0.25},
            # S22: X2 = Y2⊕Y4 with bias -1/4
            {'sbox': 2, 'input_mask': 0x4, 'output_mask': 0x5, 'bias': -0.25},
            # S32: X2 = Y2⊕Y4 with bias -1/4  
            {'sbox': 3, 'input_mask': 0x4, 'output_mask': 0x5, 'bias': -0.25},
            # S34: X2 = Y2⊕Y4 with bias -1/4
            {'sbox': 4, 'input_mask': 0x4, 'output_mask': 0x5, 'bias': -0.25}
        ]
        
        return approximations
    
    def perform_linear_attack(self, num_plaintexts=10000):
        """
        Perform the linear cryptanalysis attack
        """
        # Generate known plaintext-ciphertext pairs
        plaintexts = [random.getrandbits(16) for _ in range(num_plaintexts)]
        ciphertexts = [self.spn.encrypt(pt) for pt in plaintexts]
        
        # Target partial subkey bits (K5,5-8 and K5,13-16)
        target_bits = [(5, 8), (13, 16)]
        
        # Counters for each possible partial subkey value
        counts = defaultdict(int)
        
        # Try all possible values for the target partial subkey (256 possibilities)
        for candidate in range(256):
            # Extract the two parts of the candidate subkey
            part1 = (candidate >> 4) & 0xF  # K5,5-8
            part2 = candidate & 0xF          # K5,13-16
            
            count = 0
            
            # For each plaintext-ciphertext pair
            for pt, ct in zip(plaintexts, ciphertexts):
                # Partially decrypt the last round
                # Remove the effect of the candidate subkey
                partial_decrypt = ct
                
                # Apply candidate subkey to S42 and S44
                # Extract the relevant bits from ciphertext
                s42_input = (ct >> 8) & 0xF  # Bits 9-12 (0-indexed: 8-11)
                s44_input = ct & 0xF          # Bits 13-16 (0-indexed: 12-15)
                
                # Apply candidate subkey (parts 1 and 2)
                s42_input ^= part1
                s44_input ^= part2
                
                # Apply inverse S-box
                s42_output = self.spn.inv_sbox[s42_input]
                s44_output = self.spn.inv_sbox[s44_input]
                
                # Reconstruct U4 bits
                u4 = 0
                u4 |= (s42_output << 8)   # Bits 9-12 become U4,6-8
                u4 |= (s44_output)        # Bits 13-16 become U4,14-16
                
                # Extract the specific bits we need: U4,6, U4,8, U4,14, U4,16
                # Note: Bit positions are 1-indexed in the paper
                u4_6 = (u4 >> 10) & 0x1   # Bit 11 (0-indexed) = U4,6 (1-indexed)
                u4_8 = (u4 >> 8) & 0x1    # Bit 9 (0-indexed) = U4,8 (1-indexed)
                u4_14 = (u4 >> 2) & 0x1   # Bit 3 (0-indexed) = U4,14 (1-indexed)
                u4_16 = u4 & 0x1          # Bit 1 (0-indexed) = U4,16 (1-indexed)
                
                # Extract plaintext bits: P5, P7, P8
                p5 = (pt >> 11) & 0x1  # Bit 12 (0-indexed) = P5 (1-indexed)
                p7 = (pt >> 9) & 0x1   # Bit 10 (0-indexed) = P7 (1-indexed)
                p8 = (pt >> 8) & 0x1   # Bit 9 (0-indexed) = P8 (1-indexed)
                
                # Check if the linear approximation holds
                lhs = u4_6 ^ u4_8 ^ u4_14 ^ u4_16 ^ p5 ^ p7 ^ p8
                if lhs == 0:
                    count += 1
            
            counts[candidate] = count
        
        # Find the candidate with the maximum bias
        best_candidate = max(counts, key=lambda k: abs(counts[k] - num_plaintexts/2))
        best_bias = abs(counts[best_candidate] - num_plaintexts/2) / num_plaintexts
        
        # Extract the actual subkey bits for comparison
        actual_k5 = self.spn.subkeys[4]
        actual_part1 = (actual_k5 >> 8) & 0xF  # K5,5-8 (bits 9-12, 0-indexed)
        actual_part2 = actual_k5 & 0xF          # K5,13-16 (bits 13-16, 0-indexed)
        actual_combined = (actual_part1 << 4) | actual_part2
        
        return best_candidate, best_bias, actual_combined, counts


def main():
    # Initialize the SPN cipher
    spn = BasicSPN()
    
    # Initialize linear cryptanalysis
    lc = LinearCryptanalysis(spn)
    
    # Print the actual subkeys for reference
    print("Actual Subkeys:")
    for i, key in enumerate(spn.subkeys):
        print(f"K{i+1}: {key:04X}")
    print()
    
    # Generate and print the Linear Approximation Table
    print("Linear Approximation Table (LAT):")
    print("Input\\Output", end="")
    for j in range(16):
        print(f"{j:4X}", end="")
    print()
    
    for i in range(16):
        print(f"{i:4X}     ", end="")
        for j in range(16):
            print(f"{lc.lat[i][j]:4}", end="")
        print()
    print()
    
    # Find a good linear approximation
    approximations = lc.find_good_linear_approximation()
    print("Good Linear Approximations:")
    for approx in approximations:
        print(f"S{approx['sbox']}: Input Mask {approx['input_mask']:X} -> "
              f"Output Mask {approx['output_mask']:X}, Bias: {approx['bias']}")
    print()
    
    # Perform the linear attack
    print("Performing linear attack with 10,000 plaintexts...")
    best_candidate, best_bias, actual_combined, counts = lc.perform_linear_attack(10000)
    
    print(f"Best candidate: {best_candidate:02X}")
    print(f"Actual subkey:  {actual_combined:02X}")
    print(f"Bias: {best_bias:.6f} (expected: {1/32:.6f})")
    print()
    
    # Show some of the count results (like Table 5 in the paper)
    print("Partial results (counts for some candidate subkeys):")
    print("Candidate  Count   Bias")
    for candidate in sorted(counts.keys()):
        if candidate % 16 == 0:  # Show every 16th candidate
            bias = abs(counts[candidate] - 5000) / 10000
            print(f"  {candidate:02X}      {counts[candidate]:4}   {bias:.4f}")

    # Test if the attack was successful
    if best_candidate == actual_combined:
        print("\n✓ Attack successful! Correct subkey found.")
    else:
        print("\n✗ Attack failed. Incorrect subkey found.")


if __name__ == "__main__":
    main()