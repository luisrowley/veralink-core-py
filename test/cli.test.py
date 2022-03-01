# -*- coding: utf-8 -*-
import os, sys

p = os.path.abspath('.')
sys.path.insert(1, p)

from shared.constants import CBOR_PAYLOAD
from encoder import Encoder

if __name__ == "__main__":
    encoder = Encoder()
    encoder.sign_cbor_data(CBOR_PAYLOAD)