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
            EC2KpX: unhexlify(b'98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280'),
            EC2KpY: unhexlify(b'f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb'),
            EC2KpD: unhexlify(b'02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3')
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
            EC2KpX: unhexlify(b'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d'),
            EC2KpY: unhexlify(b'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c')
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
            EC2KpD: unhexlify(b'aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf')
        }
        return CoseKey.from_dict(_key)
