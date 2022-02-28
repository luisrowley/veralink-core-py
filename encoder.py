# -*- coding: utf-8 -*-

from shared.constants import ENCODING_SCHEMA
from base45 import b45encode

class Encoder():
    def __init__(self, schema=ENCODING_SCHEMA):
        self.schema = schema
        
    """
    Preliminar report with overall data
    """
    def base45_encode(self, bytes):
        return 