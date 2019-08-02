import fingerprint


class MacFingerprint(fingerprint.Fingerprint):

    def __init__(self, os):
        super(MacFingerprint, self).__init__(os)

    def fingerprint_mac(self):
        pass