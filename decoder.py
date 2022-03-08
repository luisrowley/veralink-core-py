# -*- coding: utf-8 -*-
from shared.constants import ENCODING_SCHEMA
from cose.messages import CoseMessage
from base45 import b45decode
import cbor2
import zlib

class Decoder():
    def __init__(self, cose_key, schema=ENCODING_SCHEMA):
        self.schema = schema
        self.key = cose_key

    def cbor_decode(self, signed_data):
        """
        Decode CBOR signed payload function
            @returns deserialized object from bytestring
        """
        decoded = CoseMessage.decode(signed_data)
        decoded.key = self.key
        if not decoded.verify_signature():
            raise Exception("Error Code []: CBOR decode")
        else:
            return cbor2.loads(decoded.payload)
    
    @classmethod
    def base45_decode(cls, base_string):
        """
        Decode base45 operation
        """
        return b45decode(base_string)
    
    @classmethod
    def zlib_decompress(cls, compressed_data):
        """
        Data compression with zlib
        """
        decompressed = zlib.decompress(compressed_data)
        return decompressed
