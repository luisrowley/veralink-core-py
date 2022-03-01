# -*- coding: utf-8 -*-
import os, sys

p = os.path.abspath('.')
sys.path.insert(1, p)

from shared.constants import CBOR_PAYLOAD, COSE_KEY
from encoder import Encoder
from decoder import Decoder
from cose.messages import CoseMessage
from binascii import hexlify
import cbor2

if __name__ == "__main__":
    encoder = Encoder()
    decoder = Decoder()
    signed_data = encoder.sign_cbor_data(CBOR_PAYLOAD)
    print('signed', hexlify(signed_data))
    # decode and verify the signature
    cose_key = COSE_KEY
    decoded = CoseMessage.decode(signed_data)
    print('decoded', decoded)
    decoded.key = cose_key
    print(decoded.verify_signature())
    print(cbor2.loads(decoded.payload))