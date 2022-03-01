from typing import Final
from cose.keys.keyparam import KpKty, OKPKpD, OKPKpX, KpKeyOps, OKPKpCurve
from cose.keys.keyops import SignOp, VerifyOp
from cose.keys.keytype import KtyOKP
from cose.keys.cosekey import CoseKey
from binascii import unhexlify

ENCODING_SCHEMA: Final = 'base45'
# COSE_KEY: Final = CoseKey.from_dict({
#     KpKty: KtyOKP,
#     OKPKpCurve: Ed25519,
#     KpKeyOps: [SignOp, VerifyOp],
#     OKPKpD: unhexlify(b'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
#     OKPKpX: unhexlify(b'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
# })


CBOR_PAYLOAD = {
  "cn": "Wexton Inc",
  "sn": 1684671300,
  "co": "ES"
}
