# -*- coding: utf-8 -*-
import cbor2
from binascii import hexlify
from shared.constants import COSE_KEY, ENCODING_SCHEMA
from base45 import b45encode
from cose.messages import Sign1Message, CoseMessage
from cose.algorithms import EdDSA
from cose.headers import Algorithm, KID
from cose.keys.cosekey import CoseKey

class Encoder():
    def __init__(self, schema=ENCODING_SCHEMA):
        self.schema = schema
        
    """
    Preliminar report with overall data
    """
    def sign_cbor_data(self, payload):
        msg = Sign1Message(
            phdr = {Algorithm: EdDSA},
            uhdr = {KID: b'kid2'},
            payload = cbor2.dumps(payload))
        print(msg)
        
        cose_key = COSE_KEY
        cose_key = CoseKey.from_dict(cose_key)
        print(cose_key)
        msg.key = cose_key
        # encode function performs the signing automatically
        encoded = msg.encode()
        print(hexlify(encoded))
        # decode and verify the signature
        decoded = CoseMessage.decode(encoded)
        print(decoded)
        decoded.key = cose_key
        print(decoded.verify_signature())
        print(cbor2.loads(decoded.payload))
        return encoded

    """
    Preliminar report with overall data
    """
    def base45_encode(self, bytes):
        return 