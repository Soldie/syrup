import fingerprint


class UnixFingerprint(fingerprint.Fingerprint):

    def __init__(self, os):
        super(UnixFingerprint, self).__init__(os)

    def fingerprint_unix(self):
        pass
