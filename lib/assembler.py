import json

class Assembler():
    def __init__(self, schema='ENCODING_SCHEMA'):
        self.schema = schema
    
    def prettify(cbor_data):
        return json.dumps(cbor_data, indent=2)
