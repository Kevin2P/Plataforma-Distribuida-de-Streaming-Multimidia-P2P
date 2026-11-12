import hashlib
import hmac
import os
import socket
import struct
import threading
import time

FRAGMENT = 1200


def hm(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


def s16(text):
    raw = text.encode()
    return struct.pack(">H", len(raw)) + raw


def blob(raw):
    return struct.pack(">I", len(raw)) + raw


class Reader:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def take(self, n):
        if self.p + n > len(self.d):
            raise ValueError("truncado")
        out = self.d[self.p:self.p + n]
        self.p += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack(">H", self.take(2))[0]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def str(self):
        return self.take(self.u16()).decode()

    def blob(self):
        return self.take(self.u32())

    def done(self):
        return self.p == len(self.d)


class Closed(Exception):
    pass


class Channel:
    def __init__(self, sock, key):
        self.s = sock
        self.key = key
        self.ks = None
        self.client = True
        self.sent = 0
        self.received = 0

    def recvn(self, n):
        out = b""
        while len(out) < n:
            part = self.s.recv(n - len(out))
            if not part:
                raise Closed()
            out += part
        return out

    def frame_bytes(self, mtype, payload, with_mac):
        header = b"SP" + bytes([1, mtype]) + struct.pack(">I", len(payload))
        data = header + payload
        if with_mac:
            data += hm(self.ks, bytes([0 if self.client else 1]), struct.pack(">Q", self.sent), header, payload)
            self.sent += 1
        return data

    def send(self, mtype, payload=b"", with_mac=True):
        self.s.sendall(self.frame_bytes(mtype, payload, with_mac))

    def recv(self, with_mac=True):
        header = self.recvn(8)
        if header[:2] != b"SP" or header[2] != 1:
            raise ValueError("cabecalho invalido")
        payload = self.recvn(struct.unpack(">I", header[4:])[0])
        if with_mac:
            tag = self.recvn(32)
            want = hm(self.ks, bytes([1 if self.client else 0]), struct.pack(">Q", self.received), header, payload)
            if not hmac.compare_digest(tag, want):
                raise ValueError("MAC invalido")
            self.received += 1
        return header[3], payload

    def client_handshake(self, ident, role):
        nc = os.urandom(16)
        self.send(1, nc + s16(ident) + bytes([role]), False)
        mtype, p = self.recv(False)
        if mtype != 2:
            raise ValueError("esperava CHALLENGE, veio %d" % mtype)
        ns, ps = p[:16], p[16:48]
        if not hmac.compare_digest(ps, hm(self.key, b"SPv1-server", nc, ns, ident.encode())):
            raise ValueError("prova do servidor nao confere")
        self.send(3, hm(self.key, b"SPv1-client", ns, nc, ident.encode()), False)
        self.ks = hm(self.key, b"SPv1-session", nc, ns, ident.encode())
        mtype, _ = self.recv(True)
        if mtype != 4:
            raise ValueError("esperava AUTH_OK")

    def server_handshake(self):
        self.client = False
        mtype, p = self.recv(False)
        r = Reader(p)
        nc = r.take(16)
        ident = r.str()
        role = r.u8()
        ns = os.urandom(16)
        self.send(2, ns + hm(self.key, b"SPv1-server", nc, ns, ident.encode()), False)
        mtype, p = self.recv(False)
        if mtype != 3 or not hmac.compare_digest(p, hm(self.key, b"SPv1-client", ns, nc, ident.encode())):
            raise ValueError("prova do cliente nao confere")
        self.ks = hm(self.key, b"SPv1-session", nc, ns, ident.encode())
        self.send(4)
        return ident, role


def connect(host, port, key):
    s = socket.create_connection((host, port), 3)
    s.settimeout(3)
    return Channel(s, key)


def parse_manifest(r):
    start = r.p
    name = r.str()
    size, chunk, bitrate, n = r.u64(), r.u32(), r.u32(), r.u32()
    hashes = [r.take(32) for _ in range(n)]
    raw = r.d[start:r.p]
    return dict(name=name, size=size, chunk=chunk, bitrate=bitrate, hashes=hashes, raw=raw, id=hashlib.sha256(b"SPM1" + raw).digest())


def build_manifest(name, data, chunk, bitrate):
    hashes = [hashlib.sha256(data[i:i + chunk]).digest() for i in range(0, len(data), chunk)]
    raw = s16(name) + struct.pack(">QIII", len(data), chunk, bitrate, len(hashes)) + b"".join(hashes)
    return raw, hashlib.sha256(b"SPM1" + raw).digest(), len(hashes)


def bitmap(n, have):
    bits = bytearray((n + 7) // 8)
    for i in have:
        bits[i // 8] |= 1 << (i % 8)
    return bytes(bits)


def parse_list(payload):
    r = Reader(payload)
    out = []
    for _ in range(r.u16()):
        cid = r.take(32)
        name = r.str()
        size, chunk, bitrate, chunks, seeders, holders = r.u64(), r.u32(), r.u32(), r.u32(), r.u32(), r.u32()
        out.append(dict(id=cid, name=name, size=size, chunk=chunk, bitrate=bitrate, chunks=chunks, seeders=seeders, holders=holders))
    if not r.done():
        raise ValueError("bytes sobrando no LIST_REPLY")
    return out


def parse_lookup(payload):
    r = Reader(payload)
    m = parse_manifest(r)
    peers = []
    for _ in range(r.u16()):
        ident, host = r.str(), r.str()
        tcp, udp = r.u16(), r.u16()
        peers.append(dict(id=ident, host=host, tcp=tcp, udp=udp, bitmap=r.blob()))
    if not r.done():
        raise ValueError("bytes sobrando no LOOKUP_REPLY")
    return m, peers


def udp_seal(ku, mtype, reqid, body):
    d = b"SU" + bytes([1, mtype]) + struct.pack(">Q", reqid) + body
    return d + hm(ku, d)[:16]


def udp_open(ku, d):
    if len(d) < 28 or d[:2] != b"SU" or d[2] != 1 or not hmac.compare_digest(d[-16:], hm(ku, d[:-16])[:16]):
        return None
    return d[3], struct.unpack(">Q", d[4:12])[0], d[12:-16]


class PySeed:
    def __init__(self, tracker_host, tracker_port, key, ident, name, data, chunk, have=None):
        self.key = key
        self.data = data
        self.chunk = chunk
        self.manifest, self.cid, self.n = build_manifest(name, data, chunk, 0)
        self.have = list(range(self.n)) if have is None else have
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        self.stop = False
        self.served = 0
        self.log = []
        self.ctl = connect(tracker_host, tracker_port, key)
        self.ctl.client_handshake(ident, 0)
        self.ctl.send(10, struct.pack(">HH", self.listener.getsockname()[1], 9))
        mtype, p = self.ctl.recv()
        self.register_ok = (mtype, struct.unpack(">II", p) if len(p) == 8 else None)
        self.unknown_first = self.heartbeat()
        self.ctl.send(12, self.manifest + blob(bitmap(self.n, self.have)))
        self.publish_reply = self.ctl.recv()[0]
        self.unknown_second = self.heartbeat()
        self.threads = [threading.Thread(target=self.beat, daemon=True), threading.Thread(target=self.accept, daemon=True)]
        for t in self.threads:
            t.start()

    def heartbeat(self):
        self.ctl.send(14, struct.pack(">QQH", self.served, 0, 1) + self.cid + blob(bitmap(self.n, self.have)))
        mtype, p = self.ctl.recv()
        r = Reader(p)
        return mtype, [r.take(32) for _ in range(r.u16())]

    def beat(self):
        while not self.stop:
            time.sleep(0.15)
            try:
                self.heartbeat()
            except Exception as e:
                self.log.append("heartbeat: %r" % e)
                return

    def accept(self):
        while not self.stop:
            try:
                c, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        c.settimeout(5)
        ch = Channel(c, self.key)
        try:
            ident, role = ch.server_handshake()
            self.log.append("sessao de dados de %s papel %d" % (ident, role))
            while not self.stop:
                mtype, p = ch.recv()
                if mtype != 30:
                    return
                cid, idx = p[:32], struct.unpack(">I", p[32:36])[0]
                if cid != self.cid or idx not in self.have:
                    ch.send(32, bytes([1]))
                    continue
                part = self.data[idx * self.chunk:(idx + 1) * self.chunk]
                ch.send(31, struct.pack(">I", idx) + blob(part))
                self.served += len(part)
        except (Closed, socket.timeout, OSError, ValueError):
            pass
        finally:
            c.close()

    def close(self):
        self.stop = True
        try:
            self.ctl.send(20)
        except Exception:
            pass
        self.ctl.s.close()
        self.listener.close()
