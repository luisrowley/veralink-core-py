# -*- coding: utf-8 -*-
import cbor2
from shared.constants import ENCODING_SCHEMA
from base45 import b45encode
from cose.messages import Sign1Message
from cose.algorithms import Es256
from cose.headers import Algorithm, KID
class Encoder():
    def __init__(self, schema=ENCODING_SCHEMA):
        self.schema = schema
        
    """
    Preliminar report with overall data
    """
    def sign_cbor_data(self, payload):
        msg = Sign1Message(
            phdr = {Algorithm: Es256},
            uhdr = {KID: b'\x18\xc1L\x06\xedQ\x94('},
            payload = cbor2.dumps(payload))
        cose_key = None
        msg.key = cose_key
        print(msg)
        return msg

    """
    Preliminar report with overall data
    """
    def base45_encode(self, bytes):
        return 