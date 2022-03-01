# -*- coding: utf-8 -*-
import cbor2
from binascii import hexlify, unhexlify
from shared.constants import ENCODING_SCHEMA
from base45 import b45encode
from cose.messages import Sign1Message
from cose.algorithms import EdDSA
from cose.keys.curves import Ed25519
from cose.headers import Algorithm, KID
from cose.keys.keyparam import KpKty, OKPKpD, OKPKpX, KpKeyOps, OKPKpCurve
from cose.keys.keyops import SignOp, VerifyOp
from cose.keys.cosekey import CoseKey
from cose.keys.keytype import KtyOKP
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
        
        cose_key = {
            KpKty: KtyOKP,
            OKPKpCurve: Ed25519,
            KpKeyOps: [SignOp, VerifyOp],
            OKPKpD: unhexlify(b'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
            OKPKpX: unhexlify(b'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')}

        cose_key = CoseKey.from_dict(cose_key)
        print(cose_key)
        msg.key = cose_key
        # encode function performs the signing automatically
        encoded = msg.encode()
        print(hexlify(encoded))
        return encoded

    """
    Preliminar report with overall data
    """
    def base45_encode(self, bytes):
        return 