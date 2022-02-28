# -*- coding: utf-8 -*-
import os, sys

p = os.path.abspath('.')
sys.path.insert(1, p)

from decoder import Decoder

if __name__ == "__main__":
    decoder = Decoder()
    payload = sys.argv[1][4:]
    decoder.base45_decode(payload)