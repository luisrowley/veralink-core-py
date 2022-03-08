# -*- coding: utf-8 -*-
from base64 import decode
import os, sys

p = os.path.abspath('.')
sys.path.insert(1, p)

from shared.constants import CBOR_PAYLOAD
from lib.assembler import Assembler
from lib.keygen import Keygen
from encoder import Encoder
from decoder import Decoder

# random key generation
cose_key = Keygen.generate_random_key()

def encode_data(cbor_payload):
    # essential instance
    encoder = Encoder(cose_key)
    # signed payload
    signed_data = encoder.sign_cbor_data(cbor_payload)
    # compressed payload
    compressed_data = encoder.zlib_compress(signed_data)
    # base45 encode
    b45_data = encoder.base45_encode(compressed_data)
    # return encoded data
    return b45_data

def decode_data(b45_payload):
    # essential instance
    decoder = Decoder(cose_key)
    # base45 decode
    compressed_data = decoder.base45_decode(b45_payload)
    # decompressed payload
    decompressed_data = decoder.zlib_decompress(compressed_data)
    # cbor payload
    decoded_cbor = decoder.cbor_decode(decompressed_data)
    # return decoded data
    return decoded_cbor

if __name__ == "__main__":
    # encoding stage
    encoded = encode_data(CBOR_PAYLOAD)
    # decoding stage
    decoded = decode_data(encoded)
    # print result
    print(Assembler.prettify(decoded))
