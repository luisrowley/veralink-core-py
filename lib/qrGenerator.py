import qrcode

from shared.constants import PROTOCOL_PREFIX

class QrGenerator():
    def __init__(self):
        self.prefix = PROTOCOL_PREFIX
        self.qr = qrcode.QRCode(version = None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size = 10,
            border = 4)
    
    def create(self, b45_payload):
        data = b45_payload.decode("utf-8")
        self.qr.add_data("{}{}".format(self.prefix, data))
        self.qr.make(fit=True)
        img = self.qr.make_image(fill_color="black", back_color="white")
        img.save('final_qr.png')