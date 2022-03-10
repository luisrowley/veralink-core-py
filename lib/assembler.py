import json
import cbor2
class Assembler():
    def __init__(self, schema='ENCODING_SCHEMA'):
        self.schema = schema
    
    def cbor_to_json(cbor_data):
        return json.dumps(cbor_data, indent=2)

    def obj_to_bytestring(obj):
        return cbor2.dumps(obj)
    
    def bytestring_to_obj(bytes):
        return cbor2.loads(bytes)