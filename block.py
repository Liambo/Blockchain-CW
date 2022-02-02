import datetime
import time
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
    return(wif, addr, sk, vk)


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
    return(addr, sk, vk)


def test_difficulty(tx):
    results = [[] for _ in range(10)]
    attempts = [[] for _ in range(10)]
    for diff in range(10):
        for iter in range(10):
            block = Block(1, '223fc19076ef413010f4077c7b5ee1b4ff9f91a1efa88cff582a97f75dcac481', diff+1, tx)
            results[diff].append(block.dur)
            attempts[diff].append(block.attempts)
            print('done test {} of 10 for difficulty {}'.format(iter+1, diff+1))
        print('times for difficulty {}: {}'.format(diff+1, results[diff]))
        print('attempts for diffictuly {}: {}'.format(diff+1, attempts[diff]))


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
        print("Private key: " + self.priv_key.to_string().hex())
        print("Public key: " + self.pub_key.to_string().hex())
    
    def construct_tx(self, blockchain, unconfirmed_tx, input_txids, input_indexs, outputs, amounts):
        if len(input_txids) == 0 or len(outputs) == 0: # Various error checks...
            print('Error: Input or output lists empty')
            return
        if len(input_txids) != len(input_indexs):
            print('Error: Length of txid and index lists unequal')
            return
        if len(outputs) != len(amounts):
            print('Error: Length of output keys not equal to length of amounts')
            return
        if len(input_txids) > 15 or len(outputs) > 15:
            print('Error: Can only have up to 15 inputs or outputs')
            return
        tx = '0'*(2 - len(hex(len(input_txids))[2:])) + hex(len(input_txids))[2:] # Start tx with no. of inputs. Ensures this is 2 digits long.
        input_sum = 0
        confirmed = True
        for i in range(len(input_txids)): # Loops through all txs and check for various errors
            if not confirmed: # If the previous TXID was never found in the blockchain...
                print('Error: TXID '+ input_txids[i-1] + ' not found')
                return
            confirmed = False
            for block in blockchain:
                for j in range(len(block.tx)): # Loop through all txs in every block on the chain
                    if input_txids[i] == hashlib.sha256(block.tx[j].encode()).hexdigest(): # If TXID found
                        confirmed = True
                        input_no = int('0x' + block.tx[j][:2], 16) # No. of inputs in found transaction
                        output_start = 4 + input_no * 194 + input_indexs[i] * 136 # Index of where relevant output will start
                        output_amount = int('0x' + block.tx[j][output_start:output_start+8], 16) # Amount being redeemed in output
                        input_sum += output_amount
                        scriptsig = self.priv_key.sign(block.tx[j].encode()).hex() # Generate unlocking script for this output
                        vout = '0'*(2 - len(hex(input_indexs[i])[2:])) + hex(input_indexs[i])[2:] # Ensure output index is of correct length
                        tx += input_txids[i] + vout + scriptsig # Append all to transaction
                        break
                if confirmed:
                    break
            if not confirmed: # If tx not found on blockchain, check pool of unconfirmed txs
                for checking_tx in unconfirmed_tx:
                    if input_txids[i] == hashlib.sha256(checking_tx.encode()).hexdigest(): # If TXID found
                        confirmed = True
                        input_no = int('0x' + checking_tx[:2], 16) # No. of inputs in found transaction
                        output_start = 4 + input_no * 194 + input_indexs[i] * 136 # Index of where relevant output will start
                        output_amount = int('0x' + checking_tx[output_start:output_start+8], 16) # Amount being redeemed in output
                        input_sum += output_amount
                        scriptsig = self.priv_key.sign(checking_tx.encode()).hex() # Generate unlocking script for this output
                        vout = '0'*(2 - len(hex(input_indexs[i])[2:])) + hex(input_indexs[i])[2:] # Ensure output index is of correct length
                        tx += input_txids[i] + vout + scriptsig # Append all to transaction
                        break
        if not confirmed: # Checking if last TXID was actually found
            print('Error: TXID '+ input_txids[i-1] + ' not found')
            return
        if input_sum < sum(amounts): # Check if input sum smaller than output
            print('Error: Sum of outputs larger than inputs')
            return
        if input_sum > sum(amounts):
            tx += '0'*(2 - len(hex(len(outputs))[2:])) + hex(len(outputs)+1)[2:] # Add number of outputs to transaction, accounting for 'change' output if inputs > outputs
        else:   
            tx += '0'*(2 - len(hex(len(outputs))[2:])) + hex(len(outputs))[2:] # Add number of outputs to transaction
        for i in range(len(outputs)): # For every output add amount (8 digits) and pubkey (128 digits)
            amount = '0'*(8 - len(hex(amounts[i])[2:])) + hex(amounts[i])[2:]
            tx += amount + outputs[i]
        if input_sum > sum(amounts): # If input sum larger than output sum, return change to owner
            amount = '0'*(8 - len(hex(input_sum-sum(amounts))[2:])) + hex(input_sum-sum(amounts))[2:]
            tx += amount + self.pub_key.to_string().hex()
        return tx


class Block:
    def __init__(self, block_id, previous_block_hash, difficulty, tx):
        self.block_id = block_id
        self.previous_block_hash = previous_block_hash
        self.difficulty = difficulty
        self.timestamp = datetime.datetime.now()
        self.tx = tx
        self.valid_tx = self.validate_tx()
        if self.valid_tx != True:
            print(self.valid_tx)
        self.merkle_root = construct_merkle(hash_list(tx))
        self.nonce, self.dur, self.attempts = self.mine_block()
        self.header = [self.block_id, self.previous_block_hash, self.nonce, self.timestamp, self.merkle_root]
        self.hash = self.get_hash(self.nonce)

    def get_hash(self, nonce):
        header = str(self.block_id) + str(self.previous_block_hash) + str(self.difficulty)\
             +  str(nonce) + str(self.timestamp) + str(self.merkle_root)
        return hashlib.sha256(header.encode()).hexdigest()
    
    def mine_block(self):
        start = time.time()
        attempts = 1
        nonce = random.randint(0, 4294967296)
        while self.get_hash(nonce)[:self.difficulty] != "0"*self.difficulty:
            attempts += 1
            nonce = random.randint(0, 4294967296)
        dur = time.time() - start
        return nonce, dur, attempts
    
    def display_info(self):
        print('Block ID: '+self.block_id)
        print('Hash: '+self.hash)
        print('Previous block hash: '+self.previous_block_hash)
        print('Difficulty: '+str(self.difficulty))
        print('Timestamp: '+str(self.timestamp))
        print('Merkle root: '+self.merkle_root)
        print('Nonce: '+str(self.nonce))
        print('Transaction list: '+str(self.tx))
        print('Transaction IDs:'+str(hash_list(self.tx)))

    def validate_tx(self):
        global block_chain
        for tx in self.tx: # Loop through all transactions to validate
            input_sum = 0
            output_sum = 0
            inputs = int("0x" + tx[:2], 16) # Get no. of inputs from current transaction
            inputs_length = inputs*194+2 # Total length of inputs in tx
            for i in range(inputs): # Loop to do verifications for every input (check input not already redeemed & check signatures)
                txid_verified = False
                txid = tx[2+194*i:66+194*i] # TXID currently being checked
                txvout = tx[66+194*i:68+194*i]
                txid_occurences = 0 # Counts no. of times TXID is found in blockchain & transaction pool. If there is no double spend attempt, should only occur once.
                output = int("0x" + tx[66+194*i:68+194*i], 16) # Relevant position in output of previous transaction
                scriptsig = bytes.fromhex(tx[68+194*i:196+194*i]) # Scriptsig of input to be verified
                for block in reversed(block_chain + [self]): # Loop through current block & blockchain to check prev. transactions. This is done in reverse to be faster on long blockchains, since recent transactions are more likely to be spent first, whereas older ones may already be spent.
                    for validate_tx in reversed(block.tx): # We loop through transactions in reverse order so if we verify the transaction we can break, rather than having to check remaining transactions for double spend.
                        validate_inputs = int("0x" + validate_tx[:2], 16) # No. of inputs in tx being checked
                        output_start = 4+validate_inputs*194 + output*136 # Start of our relevant output
                        if txid == hashlib.sha256(validate_tx.encode()).hexdigest(): # If there is a match...
                            input_sum += int("0x" + validate_tx[output_start:output_start+8], 16) # Add amount to input sum
                            pubkey = bytes.fromhex(validate_tx[output_start+8:output_start+136]) # Get pubkey from output
                            vk = ecdsa.VerifyingKey.from_string(pubkey, curve=SECP256k1)
                            try:
                                vk.verify(scriptsig, validate_tx.encode()) # Verify pubkey against scriptsig. Returns BadSignatureError if invalid signature.
                                txid_verified = True
                                break
                            except ecdsa.keys.BadSignatureError:
                                return('Error: Invalid scriptsig in transaction: '+tx)
                        for j in range(validate_inputs): # Check all inputs of tx to check for double spend attempts
                            validate_txid = validate_tx[2+194*j:66+194*j]
                            validate_txvout = validate_tx[66+194*j:68+194*j]
                            if validate_txid == txid and validate_txvout == txvout: # If the transaction ID and output matches the ID and output of the transaction currently being verified...
                                txid_occurences += 1 # We add 1 ot occurences. The first 1 will probably be us checking against the transaction being verified, but any subsequent matches would indicate a double spend attempt.
                    if txid_verified: # If tx has been verified, we know it is also not a double spend attempt as previous attempts to spend the output would have ben found after the original output in the blockchain.
                        break
                if txid_occurences > 1: # If the txid was found in the input of more than 1 transaction, we know it was a double spend attempt (we count our own transaction once)
                    return('Error: Double spend attempt in transaction: '+tx)
            outputs =  int("0x" + tx[inputs_length:inputs_length+2], 16)
            for i in range(outputs): # Sum up all outputs, check if equal to inputs
                output_amount = int("0x" + tx[inputs_length+2+i*136:inputs_length+10+i*136], 16)
                output_sum += output_amount
            if input_sum != output_sum and inputs != 0:
                return('Error: Transaction inputs & outputs don\'t sum for transaction: '+tx)
        return True

    @staticmethod
    def create_genesis_block(tx):
        return Block("0", "0", 0, tx)


testing = False # Set to true if testing block mining times.
block_chain = [Block.create_genesis_block(["0001000f4240b0cd4e655af53f1c865782864e15aa5d414b8fa1fa2537e90903661f345a02ea309e2c6f488480a6a4fd89c182b834c8ec1b78e2a33751d7fb05dd2bf6fb7f71"])]
genesis_hash = block_chain[0].hash # Creation of genesis block. Coinbase transaction sends 1,000,000 coins to A.
print("The genesis block has been created.")
block_chain[0].display_info()
A = Wallet("A", "L2WNfN7uaW58U2STZ52d2QzKreokSYJbj93j5e7NTbUGiRshBJ2f")
A.display_info() # Creating wallet for A.
B = Wallet("B", "KwR7ekm6VmQJt7rHv3LXTdpSRiQJ3BdM2Ac97QyJ6YeeZNNpSdD9")
B.display_info() # Creating wallet for B.
C = Wallet("C", "L2ywvanKbTZ2x17uXtjKsLFJpaMgMJWJLASpLJqEQPH8yTQVtZq6")
C.display_info() # Creating wallet for C.
unconfirmed_tx = [] # Unconfirmed transaction pool. This should be reset after mining each block in actual use.
tx1 = A.construct_tx(block_chain, unconfirmed_tx, ['45d7e470fcbd2c9dfd7086178044a58f0bc31bbc00bc581ac77f23a261c0cdc6'], [0], ['064eabd846cc09740d00f27dc149ad6a376fa275df5de265e6b94111915e29023e08fc9c1d07a86d77090871b3ac77ad507fcd9a41a636c61990549123aaea48'], [50000])
unconfirmed_tx.append(tx1) # Creation of first transaction: A sends 50,000 coins to B.
tx2 = A.construct_tx(block_chain, unconfirmed_tx, [hashlib.sha256(tx1.encode()).hexdigest()], [1], ['064eabd846cc09740d00f27dc149ad6a376fa275df5de265e6b94111915e29023e08fc9c1d07a86d77090871b3ac77ad507fcd9a41a636c61990549123aaea48', '710b5fbb17bb0fcbe8547193337927ac77c633b4dbf02313b5e13b720786bf332e03875ca2ac00896c856c180322204310fb15ea7dd778adc75e1755de9f5816'], [20000, 10000])
unconfirmed_tx.append(tx2) # Creation of second transaction: A sends 20,000 coins to B and 10,000 coins to C. Input is from output of first transaction.
tx3 = B.construct_tx(block_chain, unconfirmed_tx, [hashlib.sha256(tx1.encode()).hexdigest()], [0], ['b0cd4e655af53f1c865782864e15aa5d414b8fa1fa2537e90903661f345a02ea309e2c6f488480a6a4fd89c182b834c8ec1b78e2a33751d7fb05dd2bf6fb7f71'], [30000])
unconfirmed_tx.append(tx3) # Creation of third transaction: B sends 30,000 coins to A. Input is from output of first transaction.
if testing: # Loop to test mining times: Generates block 10 times for difficulty 1-10.
    results = test_difficulty(unconfirmed_tx)
    print(results)
block_chain.append(Block(1, '223fc19076ef413010f4077c7b5ee1b4ff9f91a1efa88cff582a97f75dcac481', 3, unconfirmed_tx)) # Generates block with trasactions 1-3 and appends to blockchain.
print('Successfully added block to blockchain')