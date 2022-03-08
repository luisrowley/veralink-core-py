from cose.keys import OKPKey

class Keygen():
    @classmethod
    def generate_random_key(cls, curve='ED25519'):
        return OKPKey.generate_key(crv=curve)