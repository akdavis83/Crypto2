from flask import Flask, jsonify, request
import bitcoin, hashlib, binascii, base58
import eth_keys, binascii
import json
from eth_keys import keys
import eth_utils

app =Flask(__name__)


@app.route('/crypto2/eth_sign', methods=["POST"])
def eth_sign():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["skey", "msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    privKey = keys.PrivateKey(binascii.unhexlify(values["skey"]))
    msg = values["msg"].encode('utf-8')
    signature = privKey.sign_msg(msg)
    print('Msg:', msg)
    print('Msg hash:', binascii.hexlify(eth_utils.keccak(msg)))
    print('Signature: [v = {0}, r = {1}, s = {2}]'.format(
    hex(signature.v), hex(signature.r), hex(signature.s)))
    print('Signature (130 hex digits):', signature)

    response = {"signature": signature.hex(),
                "msg": msg.decode('utf-8')}

    return json.dumps(response), 201

@app.route('/crypto2/eth_sign_to_addr', methods=["POST"])
def eth_sign_to_addr():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["signature", 'msg']
    if not all(k in values for k in required):
        return "Missing values", 400
    
   
    received_signature= eth_keys.keys.Signature(binascii.unhexlify((values['signature'])[2:]))
    signerPubKey= received_signature.recover_public_key_from_msg(values['msg'].encode('utf-8'))
    signerAddress= signerPubKey.to_checksum_address()
    
    print('Signer address:', signerAddress)

    print()
	
    response = {"address": signerAddress}

    return json.dumps(response), 201

@app.route('/crypto2/eth_sign_verify', methods=["POST"])
def eth_sign_verify():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["address", "signature", "msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    msg = values["msg"].encode('utf-8')
    signature = eth_keys.keys.Signature(binascii.unhexlify(values["signature"][2:]))
    signerRecoveredPubKey = signature.recover_public_key_from_msg(msg)
    signerRecoveredAddress = signerRecoveredPubKey.to_checksum_address()
    print('Signer public key (128 hex digits):', signerRecoveredPubKey)
    print('Signer address:', signerRecoveredAddress)
    print('Signature valid?:', signerRecoveredAddress == values["address"])
	
    response = {"valid": signerRecoveredAddress == values["address"] }
	
    return json.dumps(response), 201

@app.route('/crypto2/btc_skey_to_addr', methods=["POST"])
def btc_skey_to_addr():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["skey"]
    if not all(k in values for k in required):
        return "Missing values", 400

    def private_key_to_public_key(privKeyHex: str) -> (int, int):
        privateKey = int(privKeyHex, 16)
        return bitcoin.fast_multiply(bitcoin.G, privateKey)

    def pubkey_to_address(pubKey: str, magic_byte = 0) -> str:
        pubKeyBytes = binascii.unhexlify(pubKey)
        sha256val = hashlib.sha256(pubKeyBytes).digest()
        ripemd160val = hashlib.new('ripemd160', sha256val).digest()
        return bitcoin.bin_to_b58check(ripemd160val, magic_byte)

    private_key= base58.b58decode(values["skey"])
    private_key_hex= binascii.hexlify(private_key)[2:-8]
    address= bitcoin.privtoaddr(private_key_hex)

    print("Private key (hex):", private_key_hex)

    public_key = private_key_to_public_key(private_key_hex)
    print("Public key (x,y) coordinates:", public_key)

    compressed_public_key = bitcoin.compress(public_key)
    print("Public key (hex compressed):", compressed_public_key)

    # address = pubkey_to_address(compressed_public_key)
    print("Compressed Bitcoin address (base58check):", address)
    
    response = {"address": address}
    
    return json.dumps(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

