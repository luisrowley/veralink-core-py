# -*- coding: utf-8 -*-
import os, sys

p = os.path.abspath('.')
sys.path.insert(1, p)

from shared.constants import CBOR_PAYLOAD
from lib.keygen import Keygen
from encoder import Encoder
from decoder import Decoder

if __name__ == "__main__":
    cose_key = Keygen.generate_random_key()
    encoder = Encoder(cose_key)
    decoder = Decoder(cose_key)
    signed_data = encoder.sign_cbor_data(CBOR_PAYLOAD)

    print(decoder.cbor_decode(signed_data))