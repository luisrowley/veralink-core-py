from cose.keys import OKPKey

class Keygen():
       
    def generate_random_key(curve='ED25519'):
        return OKPKey.generate_key(crv=curve)