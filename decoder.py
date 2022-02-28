# -*- coding: utf-8 -*-
from shared.constants import ENCODING_SCHEMA
from base45 import b45decode

class Decoder():
    def __init__(self, schema=ENCODING_SCHEMA):
        self.schema = schema
        
    """
    Preliminar report with overall data
    """
    def base45_decode(self, base_string):
        print(b45decode(base_string))
        return b45decode(base_string)
