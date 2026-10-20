import shlex
import subprocess as sp


class Runner:
    def __init__(self, host):
        self.host = host

    def ping(self):
        return sp.run("ping -c 1 " + self.host, shell=True)

    def ping_quoted(self):
        return sp.run("ping -c 1 " + shlex.quote(self.host), shell=True)
