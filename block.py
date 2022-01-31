import datetime
import hashlib
import random
import ecdsa
import base58
from ecdsa import SECP256k1

def hash_list(tx):
    hash_lst = []
    for i in tx:
        hash_lst.append(hashlib.sha256(str(i).encode()).hexdigest())
    return hash_lst

def construct_merkle(tx):
    if len(tx) == 1:
        return tx[0]
    if len(tx) == 2:
        tx_str = ""
        for transaction in tx:
            tx_str += transaction
        return hashlib.sha256(tx_str.encode()).hexdigest()
    else:
        tx_lst = []
        for i in range(len(tx)//2):
            tx_lst.append(hashlib.sha256((tx[2*i]+tx[2*i+1]).encode()).hexdigest())
        if len(tx)%2 == 1:
            tx_lst.append(tx[-1])
        return(construct_merkle(tx_lst))

def compress_pubkey(key):
    # Removes y-coordinate and prefixes '0x02' if even or '0x03' if odd, as one of each exists for every x-coordinate.
    if (ord(key[-1:]) % 2 == 0):
        pubkey_compressed = b'\x02'
    else:
        pubkey_compressed = b'\x03'
    pubkey_compressed = pubkey_compressed + key[:32]
    return pubkey_compressed
    

def generate_wallet():
    # Randomly generate private & public keys for ECDSA algorithm using the SECP256k1 curve, which bitcoin uses
    sk = ecdsa.SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key

    """ Work out WIF (Wallet Import Format) of private key. This is a much shorter & readable way of displaying the key.
    WIF is calculated from the private key by prefixing a '0x80' byte to signify it is intended for the bitcoin network,
    then hashing twice to calculate a checksum and appending the first 4 bytes of the checksum to the end. A '0x00' byte
    is also inserted between the key and checksum in this case, to signify the corresponding public key is stored in 
    compressed format. This allows us to verify the private key is correct & hasnt been corrupted or tampered with. The
    result is then encoded in base 58 check, an encoding developed to be human readable by removing characters like O & 0
    and I & l which often get confused, and also including an additional checksum step for security. """
    wif_checksum = hashlib.sha256(hashlib.sha256(b"\x80" + sk.to_string()).digest()).digest()[:4]
    wif = base58.b58encode(b"\x80" + sk.to_string() + b"\x00" + wif_checksum).decode('utf-8')

    """ The public key is compressed in a number of ways. The y-coordinate is dropped and the x-coordinate is then prefixed
    by '0x02' or '0x03' to show which of the 2 possible y values are used. The address is calculated from this by hashing
    using sha256 and ripemd160 before being prefixed with a '0x00' byte to signify the bitcoin version. A checksum is then
    calculated by hashing twice and the first 4 bytes are appended to the address before being encoded in base 58."""
    pubkey = compress_pubkey(vk.to_string())
    addr = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    addr_checksum = hashlib.sha256(hashlib.sha256(b"\x00" + addr).digest()).digest()[:4]
    addr = base58.b58encode(b"\x00" + addr + addr_checksum).decode('utf-8')

    return(wif, addr, sk.to_string().hex(), pubkey.hex())

def load_wallet(wif):

    # Find address and private & public keys from WIF. Checks if public key is compressed, depending on length of WIF key.
    priv_key = base58.b58decode(wif)
    if len(priv_key) == 38:
        sk = ecdsa.SigningKey.from_string(base58.b58decode(wif)[1:-5], curve=SECP256k1)
        compressed = True
    else:
        sk = ecdsa.SigningKey.from_string(base58.b58decode(wif)[1:-4], curve=SECP256k1)
        compressed = False
    vk = sk.verifying_key

    # Address calculated in same way as in generate_wallet()
    if compressed:
        pub_key = compress_pubkey(vk.to_string())
    else: # If key is not compressed, prefix with '0x04' to signify this.
        pub_key = b'\x04' + vk.to_string()
    addr = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).digest()
    addr_checksum = hashlib.sha256(hashlib.sha256(b"\x00" + addr).digest()).digest()[:4]
    addr = base58.b58encode(b"\x00" + addr + addr_checksum).decode('utf-8')

    return(addr, sk.to_string().hex(), pub_key.hex())


class Wallet:
    def __init__(self, id, privkey=False):
        self.id = id
        if privkey:
            self.wif = privkey
            self.addr, self.priv_key, self.pub_key = load_wallet(privkey)
        else:
            self.wif, self.addr, self.priv_key, self.pub_key = generate_wallet()
    
    def display_info(self):
        print("Wallet ID: " + self.id)
        print("WIF Private Key: " + self.wif)
        print("Address: " + self.addr)
        print("Private key: " + self.priv_key)
        print("Public key: " + self.pub_key)



class Block:
    def __init__(self, block_id, previous_block_hash, difficulty, tx, timestamp):
        self.block_id = block_id
        self.previous_block_hash = previous_block_hash
        self.difficulty = difficulty
        self.timestamp = timestamp
        self.tx = tx
        self.merkle_root = construct_merkle(hash_list(tx))
        self.nonce = self.mine_block()
        self.header = [self.block_id, self.previous_block_hash, self.nonce, self.timestamp, self.merkle_root]
        self.hash = self.get_hash(self.nonce)

    def get_hash(self, nonce):
        header = str(self.block_id) + str(self.previous_block_hash) + str(self.difficulty)\
             +  str(nonce) + str(self.timestamp) + str(self.merkle_root)
        return hashlib.sha256(header.encode()).hexdigest()
    
    def mine_block(self):
        nonce = random.randint(0, 4294967296)
        while self.get_hash(nonce)[:self.difficulty] != "0"*self.difficulty:
            nonce = random.randint(0, 4294967296)
        return nonce

    @staticmethod
    def create_genesis_block(tx):
        return Block("0", "0", "0", tx, datetime.datetime.now())

block_chain = [Block.create_genesis_block(["000320"])]
genesis_hash = block_chain[0].hash
print("The genesis block has been created.")
print("Hash: %s" %genesis_hash)
block_chain.append(Block())


A = Wallet("A", "KyPxc6bEDTc9gLFaeh5yLpPqReMey12HcUNTLCWfUsmntWrkMNez")
A.display_info()