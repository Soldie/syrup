from fingerprint.docker import DockerFingerprint


def main():
    print DockerFingerprint("unix").fingerprint_docker()