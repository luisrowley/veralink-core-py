# -*- coding: utf-8 -*-
import zlib
import cbor2
from shared.constants import ENCODING_SCHEMA
from base45 import b45encode
from binascii import unhexlify, hexlify
from cose.messages import Sign1Message, EncMessage
from cose.algorithms import EdDSA, EcdhEsHKDF256, A128GCM
from cose.headers import Algorithm, KID, EphemeralKey, StaticKey, IV
from cose.messages.recipient import DirectKeyAgreement

class Encoder():
    def __init__(self, cose_key, schema=ENCODING_SCHEMA):
        self.schema = schema
        # parameter for private key
        self.priv_key = cose_key

    def sign_cbor_data(self, payload):
        """
        Signature function for CBOR structured payload
        """
        msg = Sign1Message(
            phdr = {Algorithm: EdDSA},
            uhdr = {KID: b'kid2'},
            payload = cbor2.dumps(payload))

        # cose key from dict
        msg.key = self.priv_key

        # encode function for signing automatically
        signed_data = msg.encode()
        return signed_data

    def get_DKA_recipient(self, sender_pub_key, receiver_pub_key):
        """
        Generate a DirectKeyAgreement recipient using public keys
        """
        recipient = DirectKeyAgreement(
            phdr = {Algorithm: EcdhEsHKDF256},
            uhdr = {EphemeralKey: sender_pub_key}
        )
        recipient.key = self.priv_key
        recipient.local_attrs = {StaticKey: receiver_pub_key}
        return recipient
    
    def encrypt_message(self, recipient, payload):
        """
        Encrypt message function for a given recepient
        """
        msg = EncMessage(
            phdr = {Algorithm: A128GCM},
            uhdr = {IV: unhexlify(b'C9CF4DF2FE6C632BF7886413')},
            payload = payload,
            recipients = [recipient])

        # encode message with above params
        enc_message = msg.encode()
        # convert message to bytestring
        enc_bytestring = hexlify(enc_message)
        return enc_bytestring

    @classmethod
    def zlib_compress(cls, signed_data):
        """
        Data compression with zlib
        """
        compressed = zlib.compress(signed_data)
        return compressed

    @classmethod
    def base45_encode(cls, bytes):
        """
        Base45 converter for bytes data payload
        """
        return b45encode(bytes)
