import re
import urllib

import fingerprint


class DockerFingerprint(fingerprint.Fingerprint):

    def __init__(self, system):
        self.file = "/proc/self/cgroup"
        self.ip_file = "/etc/hosts"
        self.curl_exists = True if "curl" in self.get_useful() else False
        super(DockerFingerprint, self).__init__(system)

    def verify_is_docker(self):
        searcher = re.compile(r'docker(-.*.scope)?', re.I)
        with open(self.file) as data:
            if searcher.search(data.read()) is not None:
                return True
        return False

    def get_container_id(self):
        container_id = set()
        long_and_short = []
        with open(self.file) as data:
            data = data.read()
            for item in data.split("\n"):
                container_id.add(item.split("/docker/")[-1])
        for item in container_id:
            long_id = item
            short_id = item[0:12]
            long_and_short.append((long_id, short_id))
        return long_and_short

    def check_for_api(self):
        ip = self.send_command("hostname -i")
        if ip is None:
            with open(self.ip_file) as hostname_data:
                ip = hostname_data.read().split("\n")[-1]
        if self.curl_exists:
            results = self.send_command("curl http://{}:4243/containers/$HOSTNAME/json".format(ip))
        else:
            results = urllib.urlopen("http://{}:4243/containers/$HOSTNAME/json".format(ip))
        if results:
            return True
        return False

    def fingerprint_docker(self):
        is_docker = self.verify_is_docker()
        if is_docker:
            container_info = self.get_container_id()
            has_api = self.check_for_api()
            user_results = self.get_is_root()
            available_commands = self.get_useful()
            available_users = self.get_users()
        else:
            container_info = None
            has_api = False
            user_results = None
            available_commands = None
            available_users = None
        return container_info, has_api, user_results, available_users, available_commands
