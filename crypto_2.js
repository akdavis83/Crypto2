'use strict';

const express = require('express');
const bodyParser = require('body-parser')
const bitcoinjs = require('bitcoinjs-lib');
var eth_Crypto = require('eth-crypto');
const { ec } = require('elliptic');
const sha3 = require('js-sha3');
const httpPort = 5000;

// Function to check if an object contains all required keys
function containsAll(body, requiredKeys) {
    return requiredKeys.every(key => Object.prototype.hasOwnProperty.call(body, key));
}

// Initialize the Express.js server
const initHttpServer = () => {
    const app = express();
    app.use(bodyParser.json());

    // Ethereum signing endpoint
    app.post('/crypto2/eth_sign', (req, res) => {
        try {
            const values = req.body;
            if (Object.keys(values).length === 0) {
                return res.status(400).send('Missing Body');
            }

            const required = ["skey", "msg"];
            if (!containsAll(values, required)) {
                return res.status(400).send('Missing values');
            }

            const msg = values.msg;
            const msgHash = sha3.keccak256(msg);
            const signature = ec.sign(msgHash, values.skey, "hex", { canonical: true });
            console.log(`Msg: ${msg}`);
            console.log(`Msg hash: ${msgHash}`);
            console.log("Signature:", signature);

            res.send({ signature: signature, msg: msg });
        } catch (error) {
            console.error(error);
            res.status(500).send('Internal Server Error');
        }
    });

    // Ethereum signing to address endpoint
    app.post('/crypto2/eth_sign_to_addr', (req, res) => {
        try {
            const values = req.body;
            if (Object.keys(values).length === 0) {
                return res.status(400).send('Missing Body');
            }

            const required = ["signature", "msg"];
            if (!containsAll(values, required)) {
                return res.status(400).send('Missing values');
            }

            // const privateKey = values.skey;
            const privKey = keyPair.getPrivate("hex");
            const pubKey = keyPair.getPublic();
            const pubKeyCompressed = '0' + (pubKey.y % 2).toString() + pubKey.x.toString('hex').padStart(64, '0');
            const address = eth_Crypto.publicKeyToAddress(pubKey);
            console.log(`Private key (64 hex digits): ${privKey}`);
            console.log(`Public key (plain, 128 hex digits): ${pubKey.toString('hex')}`);
            console.log(`Public key (compressed, 66 hex digits): ${pubKeyCompressed}`);
            console.log(`Signer address: ${address}`);

            res.send({ address: pubKey.encodeCompressed('hex') });
        } catch (error) {
            console.error(error);
            res.status(500).send('Internal Server Error');
        }
    });

    // Ethereum signature verification endpoint
    app.post('/crypto2/eth_sign_verify', (req, res) => {
        try {
            const values = req.body;
            if (Object.keys(values).length === 0) {
                return res.status(400).send('Missing Body');
            }

            const required = ["address", "msg", "signature"];
            if (!containsAll(values, required)) {
                return res.status(400).send('Missing values');
            }

            const hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
            const pubKeyRecovered = ec.recoverPubKey(hexToDecimal(values.msg), values.signature, values.signature.recoveryParam, "hex");
            console.log("Recovered pubKey:", pubKeyRecovered.encodeCompressed("hex"));

            const validSig = ec.verify(values.msg, values.signature, pubKeyRecovered);
            console.log("Signature valid?", validSig);

            res.send({ valid: validSig });
        } catch (error) {
            console.error(error);
            res.status(500).send('Internal Server Error');
        }
    });

   // Bitcoin private key to address endpoint
app.post('/crypto2/btc_skey_to_addr', (req, res) => {
    try {
        const values = req.body;
        if (Object.keys(values).length === 0) {
            return res.status(400).send('Missing Body');
        }

        const required = ["skey"];
        if (!containsAll(values, required)) {
            return res.status(400).send('Missing values');
        }

        function privateKeyToPublicKey(privKeyHex) {
            const privateKey = bitcoinjs.ECPair.fromPrivateKey(Buffer.from(privKeyHex, 'hex'));
            return privateKey.getPublicKey().encodeCompressed('hex');
        }

        function publicKeyToAddress(pubKey, magicByte = 0x00) {
            const pubKeyBuffer = Buffer.from(pubKey, 'hex');
            const hash = bitcoinjs.crypto.hash160(pubKeyBuffer);
            const address = bitcoinjs.address.toBase58Check(hash, magicByte);
            return address;
        }

        const privKeyHex = values.skey;
        const pubKey = privateKeyToPublicKey(privKeyHex);
        const address = publicKeyToAddress(pubKey);

        res.send({ address: address });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
        }
        initHttpServer();
    });
    app.listen(httpPort, () => console.log("Listening on http port: " + httpPort));
}
