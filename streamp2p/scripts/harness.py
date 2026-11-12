import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, os.environ.get("STREAMP2P_BIN", "bin/streamp2p"))
KEY = "chave-de-teste"
SLOW = float(os.environ.get("STREAMP2P_SLOW", "1"))
_next = [31000 + (os.getpid() % 300) * 25]
SANITIZER_PATTERN = re.compile(r"ERROR: AddressSanitizer|ERROR: LeakSanitizer|runtime error:|WARNING: ThreadSanitizer|SUMMARY: .*Sanitizer")
SANITIZER_REPORTS = []
PROCESSES_SCANNED = [0]


def scan(name, text):
    PROCESSES_SCANNED[0] += 1
    for line in text.splitlines():
        if SANITIZER_PATTERN.search(line):
            SANITIZER_REPORTS.append("%s: %s" % (name, line.strip()[:160]))


def next_port():
    while True:
        _next[0] += 1
        s = socket.socket()
        try:
            s.bind(("0.0.0.0", _next[0]))
            return _next[0]
        except OSError:
            pass
        finally:
            s.close()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def ipv6_available():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


class Proc:
    def __init__(self, args, workdir, name, key=KEY, env=None):
        self.name = name
        self.out_path = os.path.join(workdir, name + ".out")
        self.err_path = os.path.join(workdir, name + ".err")
        self.out = open(self.out_path, "w+")
        self.err = open(self.err_path, "w+")
        environment = dict(os.environ)
        if key is not None:
            environment["STREAMP2P_KEY"] = key
        if env:
            environment.update(env)
        self.p = subprocess.Popen([BIN] + [str(a) for a in args], stdout=self.out, stderr=self.err, env=environment)
        self.started = time.time()

    def text(self):
        self.out.flush()
        with open(self.out_path, errors="replace") as f:
            return f.read()

    def err_text(self):
        with open(self.err_path, errors="replace") as f:
            return f.read()

    def wait_for(self, pattern, timeout=10):
        end = time.time() + timeout * SLOW
        while time.time() < end:
            m = re.search(pattern, self.text())
            if m:
                return m
            if self.p.poll() is not None and not re.search(pattern, self.text()):
                return None
            time.sleep(0.02)
        return None

    def alive(self):
        return self.p.poll() is None

    def wait_exit(self, timeout=60):
        try:
            return self.p.wait(timeout=timeout * SLOW)
        except subprocess.TimeoutExpired:
            return None

    def kill(self):
        if self.alive():
            self.p.kill()
        self.p.wait()

    def term(self, timeout=15):
        if self.alive():
            self.p.send_signal(signal.SIGTERM)
        try:
            return self.p.wait(timeout=timeout * SLOW)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
            return None

    def freeze(self):
        self.p.send_signal(signal.SIGSTOP)

    def thaw(self):
        self.p.send_signal(signal.SIGCONT)

    def json_line(self, tag):
        m = re.search(r"^%s (\{.*\})$" % tag, self.text(), re.M) or re.search(r"^%s (\{.*\})$" % tag, self.err_text(), re.M)
        return json.loads(m.group(1)) if m else None

    def result(self):
        return self.json_line("RESULT")

    def stats(self):
        return self.json_line("STATS")


class Net:
    def __init__(self, ttl=3000, key=KEY, ipv6=False, tport=None):
        self.dir = tempfile.mkdtemp(prefix="streamp2p-it-")
        self.key = key
        self.host = "[::1]" if ipv6 else "127.0.0.1"
        self.web_host = "[::1]" if ipv6 else "127.0.0.1"
        self.tport = tport or next_port()
        self.wport = next_port()
        self.ttl = ttl
        self.procs = []
        self.tracker = None
        self.start_tracker()
        self.counter = 0

    def start_tracker(self):
        self.tracker = Proc(["tracker", "-p", self.tport, "-w", self.wport, "-t", self.ttl], self.dir, "tracker%d" % len(self.procs), key=self.key)
        self.procs.append(self.tracker)
        assert self.tracker.wait_for(r"tracker pronto", 10), "tracker nao subiu: " + self.tracker.err_text()
        return self.tracker

    @property
    def tracker_addr(self):
        return "%s:%d" % (self.host, self.tport)

    def make_file(self, name, size, seed=1):
        path = os.path.join(self.dir, name)
        subprocess.run([BIN, "gen", "-o", path, "-s", str(size), "-S", str(seed)], check=True)
        return path, sha256_file(path)

    def seed(self, path, name, ident, extra=(), key=None, wait=True):
        d = os.path.join(self.dir, "store-" + ident)
        args = ["seed", "-t", self.tracker_addr, "-f", path, "-n", name, "-d", d, "-i", ident] + list(extra)
        p = Proc(args, self.dir, "seed-" + ident + "-%d" % len(self.procs), key=key if key is not None else self.key)
        self.procs.append(p)
        if wait:
            assert p.wait_for(r"seed pronto", 10), "seed nao subiu: " + p.err_text()
            assert self.wait_peer(ident, 10), "seed nao apareceu no tracker: " + p.err_text()
        return p

    def get_proc(self, name, ident, extra=(), key=None, store=None):
        d = store or os.path.join(self.dir, "store-" + ident)
        args = ["get", "-t", self.tracker_addr, "-n", name, "-d", d, "-i", ident] + list(extra)
        p = Proc(args, self.dir, "get-" + ident + "-%d" % len(self.procs), key=key if key is not None else self.key)
        self.procs.append(p)
        return p

    def get(self, name, ident, extra=(), timeout=90, key=None, store=None):
        p = self.get_proc(name, ident, extra, key, store)
        rc = p.wait_exit(timeout)
        if rc is None:
            p.kill()
        return rc, p.result(), p

    def status(self):
        url = "http://%s:%d/api/status" % (self.web_host, self.wport)
        with urllib.request.urlopen(url, timeout=3) as r:
            return json.loads(r.read().decode())

    def try_status(self):
        try:
            return self.status()
        except Exception:
            return None

    def peer_ids(self):
        s = self.try_status()
        return [p["id"] for p in s["peers"]] if s else []

    def wait_peer(self, ident, timeout=10, present=True):
        end = time.time() + timeout * SLOW
        while time.time() < end:
            if (ident in self.peer_ids()) == present:
                return True
            time.sleep(0.05)
        return False

    def wait_holders(self, content_name, holders, timeout=10):
        end = time.time() + timeout * SLOW
        while time.time() < end:
            s = self.try_status()
            if s:
                for c in s["contents"]:
                    if c["name"] == content_name and c["holders"] >= holders:
                        return True
            time.sleep(0.05)
        return False

    def close(self):
        for p in self.procs:
            try:
                p.p.send_signal(signal.SIGCONT)
            except Exception:
                pass
            p.kill()
        for p in self.procs:
            scan(p.name, p.err_text())
        shutil.rmtree(self.dir, ignore_errors=True)
