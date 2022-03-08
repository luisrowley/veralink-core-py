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
        
    """
    Decode CBOR signed payload function
        @returns deserialized object from bytestring
    """
    def cbor_decode(self, signed_data):
        decoded = CoseMessage.decode(signed_data)
        decoded.key = self.key
        if not decoded.verify_signature():
            raise Exception("Error Code []: CBOR decode")
        else:
            return cbor2.loads(decoded.payload)
    
    """
    Decode base45 operation
    """
    def base45_decode(self, base_string):
        return b45decode(base_string)
    
    """
    Data compression with zlib
    """
    def zlib_decompress(self, compressed_data):
        decompressed = zlib.decompress(compressed_data)
        return decompressed
