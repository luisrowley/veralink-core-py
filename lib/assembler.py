import json
import cbor2

class Assembler():
    def __init__(self, schema='ENCODING_SCHEMA'):
        self.schema = schema
    
    def prettify(cbor):
        return json.dumps(cbor, indent=2)