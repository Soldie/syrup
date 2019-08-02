import fingerprint


class WindowsFingerprint(fingerprint.Fingerprint):

    def __init__(self, os):
        super(WindowsFingerprint, self).__init__(os)

    def windows_fingerprint(self):
        pass
