import os
import shlex
import ctypes
import subprocess


class Fingerprint(object):

    def __init__(self, os):
        self.os = os

    @staticmethod
    def send_command(command):
        if not type(command) == list:
            command = shlex.split(command)
        try:
            proc = subprocess.check_output(command, bufsize=9000)
        except:
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
            "nc", "netcat", "ssh", "curl", "wget", "gcc", "g++",
            "bash", "sh", "zsh", "docker", "sudo", "find", "putty",
            "vstool"
        ]
        for command in useful_commands:
            if self.os.lower() == "windows":
                command = shlex.split("cmd.exe /r {}".format(command))
            else:
                command = shlex.split(command)
            results = self.send_command(command)
            if results is not None:
                available.append("".join(command))
        return available
