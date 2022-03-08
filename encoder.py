# -*- coding: utf-8 -*-
import zlib
import cbor2
from shared.constants import ENCODING_SCHEMA
from base45 import b45encode
from cose.messages import Sign1Message
from cose.algorithms import EdDSA
from cose.headers import Algorithm, KID

class Encoder():
    def __init__(self, cose_key, schema=ENCODING_SCHEMA):
        self.schema = schema
        self.key = cose_key

    def sign_cbor_data(self, payload):
        """
        Signature function for CBOR structured payload
        """
        msg = Sign1Message(
            phdr = {Algorithm: EdDSA},
            uhdr = {KID: b'kid2'},
            payload = cbor2.dumps(payload))

        # cose key from dict
        msg.key = self.key

        # encode function for signing automatically
        signed_data = msg.encode()
        return signed_data

    @classmethod
    def zlib_compress(cls, signed_data):
        """
        Data compression with zlib
        """
        compressed = zlib.compress(signed_data)
        return compressed

    @classmethod
    def base45_encode(cls, bytes):
        """
        Base45 converter for bytes data payload
        """
        return b45encode(bytes)
