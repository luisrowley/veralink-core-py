from typing import Final
from enum import Enum

ENCODING_SCHEMA: Final = 'base45'
PROTOCOL_PREFIX: Final = ''

CBOR_PAYLOAD = {
  "cn": "Wexton Inc",
  "sn": 1684671300,
  "co": "ES"
}

class KeyCurves(str, Enum):
  ED25519 = 'ED25519'
  P521 = 'P_521'