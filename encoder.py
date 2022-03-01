# -*- coding: utf-8 -*-
import cbor2
from shared.constants import COSE_KEY, ENCODING_SCHEMA
from base45 import b45encode
from cose.messages import Sign1Message
from cose.algorithms import EdDSA
from cose.headers import Algorithm, KID

class Encoder():
    def __init__(self, schema=ENCODING_SCHEMA):
        self.schema = schema

    """
    Signature function for CBOR structured payload
    """
    def sign_cbor_data(self, payload):
        # message to be signed where:
        #   phdr = protected headers
        #   phdr = unprotected headers
        msg = Sign1Message(
            phdr = {Algorithm: EdDSA},
            uhdr = {KID: b'kid2'},
            payload = cbor2.dumps(payload))

        # cose key from dict
        cose_key = COSE_KEY
        msg.key = cose_key

        # encode function for signing automatically
        encoded = msg.encode()
        return encoded

    """
    Base45 converter for compressed data payload
    """
    def base45_encode(self, bytes):
        return 