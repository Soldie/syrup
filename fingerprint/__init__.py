import os
import shlex
import ctypes
import subprocess


class CommonFingerprint(object):

    def __init__(self, os):
        self.os = os

    @staticmethod
    def send_command(command):
        if not type(command) == list:
            command = shlex.split(command)
        try:
            proc = subprocess.check_output(command, bufsize=9000)
        except Exception as e:
            print (e)
            proc = None
        return proc

    def get_users(self):
        if self.os.lower() == "windows":
            command = shlex.split("cmd.exe /r net user")
        elif self.os.lower() == "mac":
            command = shlex.split("ls -l /Users/")
        else:
            command = shlex.split("cat /etc/passwd")
        self.send_command(command)

    @staticmethod
    def get_is_root():
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        return is_admin

    def get_useful(self):
        available = []
        useful_commands = [
            "nc --version", "netcat --version", "ssh --version", "curl --version", "wget --version",
            "gcc --version", "g++ --version", "docker --version", "sudo", "find --version", "putty --version",
            "vstool --version", "git --version"
        ]
        for command in useful_commands:
            try:
                if self.os.lower() == "windows":
                    command = shlex.split("cmd.exe /r {}".format(command))
                else:
                    command = shlex.split(command)
                results = self.send_command(command)
                print results
                if results is not None:
                    available.append(command[0])
            except Exception:
                pass
        return available
