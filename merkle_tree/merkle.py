from typing import Optional, List
from hashlib import sha256

def verify(obj: str, proof: str, commitment: str) -> bool:
    
    if len(obj) == 64 and all(c in '0123456789abcdef' for c in obj.lower()):
        start_hash = obj  #obj is already a hex-encoded hash
    else:
        #hash the start string
        start_hash = sha256(obj.encode()).hexdigest()
    
    if not proof:
        return start_hash == commitment
    proof_to_list = proof.split(':')
    for hash_in_proof in proof_to_list:
        if len(hash_in_proof) != 64 or any(ch not in '0123456789abcdef' for ch in hash_in_proof.lower()):
            return False
        if start_hash < hash_in_proof:
            combined_hash = start_hash + hash_in_proof
        else:
            combined_hash = hash_in_proof + start_hash
        start_hash = sha256((combined_hash).encode()).hexdigest()
    print(start_hash, commitment)

    if start_hash == commitment:
        return True
    else:
        return False
    

class Prover:
    def __init__(self):
        self.tree=[]

    # Build a merkle tree and return the commitment
    def build_merkle_tree(self, objects: List[str]) -> str:
        self.objects = objects
        leaves = []
        for obj in (self.objects):
            hased_leaf = sha256(obj.encode('utf-8')).hexdigest()
            leaves.append(hased_leaf)
        self.tree = [leaves]
        while len(leaves) > 1:
            parents = []
            #if odd number of nodes, duplicate the last
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            for i in range(0, len(leaves), 2):
                if i+1 < len(leaves):
                    concatenated_pair = leaves[i] + leaves[i+1]
                    hashed_pair = sha256(concatenated_pair.encode()).hexdigest()
                    parents.append(hashed_pair)
                else:
                    parents.append(leaves[i])
            self.tree.append(parents)
            leaves = parents
        return self.tree[-1][0]
        
    def get_leaf(self, index: int) -> Optional[str]:
        if 0 <= index < len(self.tree[0]):
            return self.tree[0][index]
        return None
        
    def generate_proof(self, index: int) -> Optional[str]:
        proof=[]
        level=0
        while level < len(self.tree)-1:
            if index%2 == 0:
                sibling=index+1
            else:
                sibling=index-1
            if 0 <= sibling<len(self.tree[level]):
                proof.append(self.tree[level][sibling])
            level+=1
            index=index//2
        proof_str=":".join(proof)
        print(len(proof))
        return proof_str
        