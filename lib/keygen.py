from binascii import unhexlify
from copy import deepcopy
from cose.keys import OKPKey, EC2Key
from cose.keys import CoseKey
from cose.keys.keyparam import KpKty, EC2KpD, EC2KpX, KpKeyOps, KpAlg, OKPKpD, EC2KpCurve, EC2KpY, KpKid, OKPKpCurve
from cose.keys.keytype import KtyEC2, KtyOKP
from cose.keys.curves import P256, Ed25519
from cose.keys.keyops import DeriveKeyOp
from cose.algorithms import EdDSA
from shared.constants import KeyCurves
import secrets

class Keygen():
    @classmethod
    def generate_random_OKPKey(cls, curve=KeyCurves.ED25519):
        return OKPKey.generate_key(crv=curve)
    
    @classmethod
    def generate_random_EC2Key(cls, curve=KeyCurves.P521):
        return EC2Key.generate_key(crv=curve)
    
    @classmethod
    def sender_OKPKey_pair(cls) -> OKPKey:
        private_key = secrets.token_bytes(32)
        public_key = secrets.token_bytes(32)
        sender_key = OKPKey(crv='ED25519', d=private_key, x=public_key, optional_params={'ALG': 'EDDSA'})
        return sender_key

    @classmethod
    def sender_EC2Key_pair(cls) -> CoseKey:
        _key = {
            KpKty: KtyEC2,
            KpKid: b"peregrin.took@tuckborough.example",
            KpKeyOps: [DeriveKeyOp],
            EC2KpCurve: P256,
            EC2KpX: secrets.token_bytes(32),
            EC2KpY: secrets.token_bytes(32),
            EC2KpD: secrets.token_bytes(32)
        }
        sender_key = CoseKey.from_dict(_key)
        return sender_key
    
    @classmethod
    def get_sender_public_EC2Key(cls, sender_key: CoseKey) -> CoseKey:
        sender_public_key = deepcopy(sender_key)
        del sender_public_key[KpKeyOps]
        del sender_public_key[EC2KpD]
        return sender_public_key

    @classmethod
    def get_recipient_public_EC2Key(cls) -> CoseKey:
        _key = {
            KpKty: KtyEC2,
            KpKid: b"meriadoc.brandybuck@buckland.example",
            KpKeyOps: [DeriveKeyOp],
            EC2KpCurve: P256,
            EC2KpX: secrets.token_bytes(32),
            EC2KpY: secrets.token_bytes(32)
        }
        return CoseKey.from_dict(_key)
    
    @classmethod
    def recipient_EC2Key_pair(cls, pub_key) -> CoseKey:
        _key = {
            KpKty: KtyEC2,
            KpKid: b"meriadoc.brandybuck@buckland.example",
            KpKeyOps: [DeriveKeyOp],
            EC2KpCurve: P256,
            EC2KpX: pub_key[EC2KpX],
            EC2KpY: pub_key[EC2KpY],
            EC2KpD: secrets.token_bytes(32)
        }
        return CoseKey.from_dict(_key)
