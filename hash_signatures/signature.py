import string
import random
import hashlib


# return the hash of a string
def SHA(s: string) -> string:
    return hashlib.sha256(s.encode()).hexdigest()


# transfer a hex string to integer
def toDigit(s: string) -> int:
    return int(s, 16)


# generate 2^d (si^{-1}, si) pairs based on seed r
def KeyPairGen(d: int, r: int) -> dict:
    pairs = {}
    random.seed(r)
    for i in range(1 << d):
        cur = random.randbytes(32).hex()
        while cur in pairs:
            cur = random.randbytes(32).hex()
        pairs[cur] = SHA(cur)
    return pairs


class MTSignature:
    def __init__(self, d, k):
        self.d = d
        self.k = k
        self.treenodes = [None] * (d + 1)
        for i in range(d + 1):
            self.treenodes[i] = [None] * (1 << i)
        self.sk = [None] * (1 << d)
        self.pk = None  # same as self.treenodes[0][0]

    # Populate the fields self.treenodes, self.sk and self.pk. Returns self.pk.
    def KeyGen(self, seed: int) -> string:
        # generate preimage pairs
        pairs_dict = KeyPairGen(self.d, seed)
        pairs_items = list(pairs_dict.items())

        # convert pairs to secret key format and leaves
        leaves = []
        for i in range(1 << self.d):
            preimage, image = pairs_items[i]
            # store preimage as secret key
            self.sk[i] = preimage
            # store image as leaf
            leaves.append(image)

        # store leaves at bottom level of tree
        self.treenodes[self.d] = leaves

        # build tree
        for level in range(self.d - 1, -1, -1):
            for i in range(1 << level):
                left = self.treenodes[level + 1][2 * i]
                right = self.treenodes[level + 1][2 * i + 1]
                # Compute parent node hash
                index = format(i, "b").zfill(256)
                parent = hashlib.sha256(f"{index}{left}{right}".encode()).hexdigest()
                self.treenodes[level][i] = parent

        # set public key as root
        self.pk = self.treenodes[0][0]
        return self.pk

    # Returns the path SPj for the index j
    # The order in SPj follows from the leaf to the root.
    def Path(self, j: int) -> string:
        if not (0 <= j < 2**self.d):
            raise ValueError("j is out of bounds.")
        # Initialize the path list
        sibling_path = []
        # start from the leaf node at index j
        index = j
        for level in range(self.d, 0, -1):  # Traverse up to the root
            # find sibling index
            if index % 2 == 0:
                sibling = index + 1
            else:
                sibling = index - 1
            # check if sibling index is within range
            if sibling < len(self.treenodes[level]):
                sibling_hash = self.treenodes[level][sibling]
                sibling_path.append(sibling_hash)

            # move up the tree
            index = index // 2
        # return the concatenated sibling path
        return "".join(sibling_path)

    # Returns the signature. The format of the signature is as follows: ([sigma], [SP]).
    # The first is a sequence of sigma values and the second is a list of sibling paths.
    # Each sibling path is in turn a d-length list of tree node values.
    # All values are 64 bytes. Final signature is a single string obtained by concatentating all values.
    def Sign(self, msg: string) -> string:
        sigma_values = []
        sibling_paths = []
        # compute k leaf indices zj
        for j in range(1, self.k + 1):
            j_binary = format(j, "b").zfill(256)
            concatenated_value = j_binary + msg
            hashed_value = hashlib.sha256(concatenated_value.encode()).hexdigest()
            zj = int(hashed_value, 16) % (2**self.d)
            # get sigma value for zj
            sigma_values.append(self.sk[zj])
            # get sibling path
            sibling_paths.append(self.Path(zj))

        # concatenate for signature
        signature = "".join(sigma_values) + "".join(sibling_paths)

        return signature


# #chatgpt did this part
# def load_messages():
#     try:
#         with open("messages.txt", "r", encoding="utf-8") as file:
#             messages = [line.strip() for line in file if line.strip()]
#     except FileNotFoundError:
#         print("Error: messages.txt not found.")
#         return []

#     random.shuffle(messages)  # Shuffle for randomness
#     return messages

# def leaf_index(jint: int, message: str, dval: int) -> int:
#     """Computes leaf index for a given message using SHA-256."""
#     j_256 = format(jint, 'b').zfill(256)  # Convert j to 256-bit binary
#     h = hashlib.sha256((j_256 + message).encode()).hexdigest()
#     return int(h, 16) % (1 << dval)  # Convert hash to integer and mod 2^d

# def find_message_collision():
#     d = 10
#     k = 2
#     r = 2023

#     messages = load_messages()
#     if len(messages) < 2:
#         print("Not enough messages for testing.")
#         return None

#     print(f"Total messages loaded: {len(messages)}")

#     # Initialize Merkle Tree Signature
#     mts = MTSignature(d, k)
#     mts.KeyGen(r)

#     # Select a random original message
#     base_message = random.choice(messages)

#     # Compute leaf indices for m_orig
#     z1_orig = leaf_index(1, base_message, d)
#     z2_orig = leaf_index(2, base_message, d)
#     target_pair = (z1_orig, z2_orig)

#     seen_pairs = {}  # Store leaf index pairs to detect collisions
#     messages_tried = 0

#     for message in messages:
#         messages_tried += 1
#         if messages_tried % 1000 == 0:
#             print(f"Messages tried: {messages_tried}")

#         if message == base_message:
#             continue

#         # Compute leaf indices for this message
#         z1_try = leaf_index(1, message, d)
#         z2_try = leaf_index(2, message, d)
#         current_pair = (z1_try, z2_try)

#         # Check if this pair has been seen before
#         if current_pair in seen_pairs:
#             colliding_message = seen_pairs[current_pair]
#             if colliding_message != message:
#                 print(f"\n Found collision after {messages_tried} tries!")
#                 print("\nOriginal Message:", colliding_message)
#                 print("\nForged Message:", message)

#                 # Save to forgery.txt
#                 with open("forgery.txt", "w", encoding="utf-8") as f:
#                     f.write(f"Original Message: {colliding_message}\n")
#                     f.write(f"Forged Message: {message}\n")

#                 return (colliding_message, message)

#         # Store the current message by its leaf pair
#         seen_pairs[current_pair] = message

#     print(f"No collision found after trying {messages_tried} messages.")
#     return None

# if __name__ == "__main__":
#     forged_pair = find_message_collision()
