"""Fuzzing autenticado e testes de carga contra processos reais.

O lixo que a suite de integracao envia as portas morre na verificacao do MAC. Aqui o fuzzer
conhece a chave: os quadros levam MAC valido e conteudo malformado, o que exercita os
decodificadores e as regras do protocolo depois do handshake. Tambem abre conexoes lentas e
centenas de sessoes simultaneas, satura o painel e poe seeders maliciosos contra o leecher.

Uso: python3 scripts/fuzz.py [secao ...]
Secoes: tracker seeder leecher lentas multidao painel
Variaveis: STREAMP2P_BIN e STREAMP2P_SLOW, como em run_tests.py, e FUZZ_SEED (semente).
"""
import hashlib
import os
import random
import selectors
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import conformance as cf
from harness import BIN, KEY, PROCESSES_SCANNED, SANITIZER_REPORTS, SLOW, Net, scan, sha256_file

KB = KEY.encode()
SEED = int(os.environ.get("FUZZ_SEED", "20261111"))
RNG = random.Random(SEED)
MIB = 1 << 20
passed = failed = 0


def section(title):
    print("\n=== %s ===" % title, flush=True)


def check(ok, what):
    global passed, failed
    if ok:
        passed += 1
        print("  ok   " + what, flush=True)
    else:
        failed += 1
        print("  FALHOU " + what, flush=True)


def listed(names):
    return "" if not names else " [falharam: %s]" % ", ".join(names)


def wait_until(fn, timeout):
    end = time.time() + timeout * SLOW
    while time.time() < end:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(0.05)
    return False


def rbytes(n):
    return RNG.getrandbits(8 * n).to_bytes(n, "big") if n > 0 else b""


def proc_status(pid):
    out = {}
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            k, _, v = line.partition(":")
            if k in ("VmRSS", "Threads"):
                out[k] = int(v.split()[0])
    out["fds"] = len(os.listdir("/proc/%d/fd" % pid))
    return out


def run_list(net):
    env = dict(os.environ, STREAMP2P_KEY=KEY)
    r = subprocess.run([BIN, "list", "-t", net.tracker_addr], capture_output=True, text=True, env=env, timeout=30 * SLOW)
    scan("list", r.stderr)
    return r


def content(net, name):
    s = net.try_status()
    return [c for c in s["contents"] if c["name"] == name] if s else []


def holders(net, name):
    c = content(net, name)
    return c[0]["holders"] if len(c) == 1 else -1


_ids = [0]


def fresh_id(prefix="fz"):
    _ids[0] += 1
    return "%s%d" % (prefix, _ids[0])


def session(port, ident=None, role=0, register=True):
    ch = cf.connect("127.0.0.1", port, KB)
    ch.s.settimeout(5 * SLOW)
    ch.client_handshake(ident or fresh_id(), role)
    if register:
        ch.send(10, struct.pack(">HH", 9, 9))
        if ch.recv()[0] != 11:
            raise RuntimeError("REGISTER recusado")
    return ch


def outcome(ch, timeout=3.0):
    """Le quadros com MAC ate o servidor fechar. Devolve (fechou, tipos recebidos)."""
    types = []
    end = time.time() + timeout * SLOW
    try:
        while True:
            left = end - time.time()
            if left <= 0:
                return False, types
            ch.s.settimeout(left)
            types.append(ch.recv()[0])
    except (cf.Closed, ConnectionResetError, BrokenPipeError):
        return True, types
    except socket.timeout:
        return False, types
    except (OSError, ValueError) as e:
        types.append(repr(e))
        return False, types
    finally:
        ch.s.close()


def rejected(ch, mtype, payload, raw=None):
    """Envia um quadro com MAC valido (ou bytes crus) e confere que a resposta e, no maximo, um ERROR seguido do fim da conexao."""
    try:
        if raw is not None:
            ch.s.sendall(raw)
        else:
            ch.send(mtype, payload)
    except OSError:
        pass
    closed, types = outcome(ch)
    return closed and all(t == 5 for t in types)


def man(name=b"fz", size=100000, chunk=16384, bitrate=0, n=None, nh=None):
    """Manifesto cru, com qualquer campo fora das regras."""
    if n is None:
        n = -(-size // chunk)
    if nh is None:
        nh = n
    return struct.pack(">H", len(name)) + name + struct.pack(">QIII", size, chunk, bitrate, n) + rbytes(32 * nh)


EDGE = [0, 1, 0x7F, 0x80, 0xFF, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, MIB, MIB + 1, 4 * MIB]


def mutate(base):
    b = bytearray(base)
    op = RNG.randrange(7)
    if op == 0 and b:
        for _ in range(RNG.randint(1, 8)):
            i = RNG.randrange(len(b))
            b[i] ^= 1 << RNG.randrange(8)
    elif op == 1:
        del b[RNG.randrange(len(b) + 1):]
    elif op == 2:
        b += rbytes(RNG.randint(1, 64))
    elif op == 3 and len(b) >= 4:
        i = RNG.randrange(len(b) - 3)
        b[i:i + 4] = struct.pack(">I", RNG.choice(EDGE) & 0xFFFFFFFF)
    elif op == 4 and len(b) >= 2:
        i = RNG.randrange(len(b) - 1)
        b[i:i + 2] = struct.pack(">H", RNG.choice(EDGE) & 0xFFFF)
    elif op == 5:
        b = bytearray(rbytes(RNG.randint(0, 300)))
    elif b:
        i = RNG.randrange(len(b))
        j = RNG.randrange(i, len(b) + 1)
        b[j:j] = b[i:j]
    return bytes(b)


def random_frames(port, bases, count, role=0, register=True):
    """Envia quadros mutados com MAC valido; reabre a sessao sempre que o servidor a encerra."""
    reopened = 0
    ch = session(port, role=role, register=register)
    for _ in range(count):
        mtype, base = RNG.choice(bases)
        if RNG.random() < 0.1:
            mtype = RNG.randrange(256)
        try:
            ch.send(mtype, mutate(base))
            ch.s.settimeout(3 * SLOW)
            if ch.recv()[0] != 5:
                continue
        except Exception:
            pass
        ch.s.close()
        ch = session(port, role=role, register=register)
        reopened += 1
    ch.s.close()
    return reopened


def t_tracker():
    section("tracker: quadros com MAC valido e conteudo malformado")
    net = Net(ttl=10000)
    try:
        path, digest = net.make_file("v.bin", 256 * 1024, seed=21)
        net.seed(path, "legitimo", "s1")
        tp = net.tport
        ch = session(tp)
        ch.send(12, man(b"fz-ok") + cf.blob(b"\x7f"))
        replies = [ch.recv()[0]]
        for mtype, payload in ((16, b""), (18, bytes(32)), (16, b"")):
            ch.send(mtype, payload)
            replies.append(ch.recv()[0])
        ch.s.close()
        check(replies == [13, 17, 5, 17], "controle: PUBLISH, LIST e LOOKUP bem-formados sao aceitos; LOOKUP de conteudo desconhecido recebe ERROR e a sessao continua")

        cases = {
            "REGISTER vazio": (10, b"", False),
            "REGISTER com 3 bytes": (10, b"\x00\x09\x00", False),
            "REGISTER com 5 bytes": (10, b"\x00\x09\x00\x09\x00", False),
            "segundo REGISTER": (10, struct.pack(">HH", 9, 9), True),
        }
        fails = [k for k, (t, p, reg) in cases.items() if not rejected(session(tp, register=reg), t, p)]
        check(not fails, "REGISTER malformado ou repetido (%d variantes): ERROR e conexao encerrada%s" % (len(cases), listed(fails)))

        pub = {
            "manifesto truncado": (man(b"t1") + cf.blob(b"\x7f"))[:-10],
            "n incoerente com o tamanho": man(b"t2", n=8) + cf.blob(b"\xff"),
            "chunk de 1023 bytes": man(b"t3", chunk=1023) + cf.blob(bytes(13)),
            "chunk acima de 1 MiB": man(b"t4", chunk=MIB + 1) + cf.blob(b"\x01"),
            "tamanho zero": man(b"t5", size=0, n=0) + cf.blob(b""),
            "taxa acima de 1 Gbit/s": man(b"t6", bitrate=1000001) + cf.blob(b"\x7f"),
            "n = 2^32-1 com 3 hashes": man(b"t7", n=0xFFFFFFFF, nh=3),
            "bitmap com comprimento 2^32-1": man(b"t8") + struct.pack(">I", 0xFFFFFFFF) + b"\x7f",
            "bitmap de tamanho errado": man(b"t9") + cf.blob(b"\x7f\x00"),
            "byte sobrando": man(b"t10") + cf.blob(b"\x7f") + b"\x00",
            "comprimento do nome alem do fim": struct.pack(">H", 500) + b"abc",
            "nome vazio": man(b"") + cf.blob(b"\x7f"),
            "nome de 65 bytes": man(b"n" * 65) + cf.blob(b"\x7f"),
            "nome com controle C0": man(b"a\x01b") + cf.blob(b"\x7f"),
            "nome com controle C1 (U+0085)": man(b"a\xc2\x85b") + cf.blob(b"\x7f"),
            "nome com UTF-8 cortado": man(b"a\xc3") + cf.blob(b"\x7f"),
            "nome com codificacao longa demais": man(b"\xe0\x80\xaf") + cf.blob(b"\x7f"),
            "nome com surrogate": man(b"\xed\xa0\x80") + cf.blob(b"\x7f"),
            "nome acima de U+10FFFF": man(b"\xf4\x90\x80\x80") + cf.blob(b"\x7f"),
        }
        fails = [k for k, p in pub.items() if not rejected(session(tp), 12, p)]
        check(not fails, "PUBLISH malformado (%d variantes, entre elas UTF-8 invalido no nome): ERROR e conexao encerrada%s" % (len(pub), listed(fails)))

        hb = {
            "257 anuncios": struct.pack(">QQH", 0, 0, 257) + (bytes(32) + cf.blob(b"")) * 257,
            "anuncio truncado": struct.pack(">QQH", 0, 0, 1) + bytes(32),
            "bitmap com comprimento 2^32-1": struct.pack(">QQH", 0, 0, 1) + bytes(32) + struct.pack(">I", 0xFFFFFFFF),
            "bitmap acima do limite": struct.pack(">QQH", 0, 0, 1) + bytes(32) + cf.blob(bytes(MIB // 8 + 2)),
            "byte sobrando": struct.pack(">QQH", 0, 0, 0) + b"\x00",
            "contadores truncados": bytes(10),
        }
        fails = [k for k, p in hb.items() if not rejected(session(tp), 14, p)]
        check(not fails, "HEARTBEAT malformado (%d variantes): ERROR e conexao encerrada%s" % (len(hb), listed(fails)))

        other = {
            "LOOKUP com 31 bytes": (18, bytes(31)),
            "LOOKUP com 33 bytes": (18, bytes(33)),
            "LIST com payload": (16, b"\x00"),
            "HELLO depois do handshake": (1, bytes(16) + cf.s16("x") + b"\x00"),
            "AUTH depois do handshake": (3, bytes(32)),
            "ERROR vindo do peer": (5, cf.s16("x")),
            "REGISTER_OK vindo do peer": (11, struct.pack(">II", 1, 1)),
            "LIST_REPLY vindo do peer": (17, struct.pack(">H", 0)),
            "CHUNK_REQ na porta de controle": (30, bytes(36)),
            "tipo 0": (0, b""),
            "tipo 99": (99, b"abc"),
            "tipo 255": (255, b""),
        }
        fails = [k for k, (t, p) in other.items() if not rejected(session(tp), t, p)]
        raws = {
            "payload anunciado acima de 4 MiB": b"SP\x01\x10" + struct.pack(">I", 4 * MIB + 1),
            "versao 2 no cabecalho": b"SP\x02\x10" + struct.pack(">I", 0) + bytes(32),
        }
        fails += [k for k, r in raws.items() if not rejected(session(tp), 0, b"", raw=r)]
        check(not fails, "LOOKUP de tamanho errado, LIST com payload, tipos fora de lugar ou desconhecidos, versao 2 e quadro acima de 4 MiB (%d casos): conexao encerrada%s" % (len(other) + len(raws), listed(fails)))

        holder = session(tp)
        mraw = man(b"fz-bits")
        holder.send(12, mraw + cf.blob(b"\xff"))
        r1 = holder.recv()[0]
        asker = session(tp)
        asker.send(18, hashlib.sha256(b"SPM1" + mraw).digest())
        mt, p = asker.recv()
        bitmaps = [x["bitmap"] for x in cf.parse_lookup(p)[1]] if mt == 19 else None
        holder.s.close()
        asker.s.close()
        check(r1 == 13 and bitmaps == [b"\x7f"], "bit ligado alem do ultimo chunk: o tracker o zera e nao o repassa a outros peers")

        cid = cf.build_manifest("legitimo", open(path, "rb").read(), 16384, 2000)[1]
        bases = [(10, struct.pack(">HH", 9, 9)), (12, man(b"fz-r") + cf.blob(b"\x7f")), (14, struct.pack(">QQH", 1, 2, 1) + cid + cf.blob(b"\xff\xff")), (18, cid), (16, b""), (20, b"")]
        count = 400
        reopened = random_frames(tp, bases, count)
        check(net.tracker.alive() and net.try_status() is not None, "o tracker sobrevive a %d quadros aleatorios com MAC valido (%d sessoes reabertas) e o painel responde" % (count, reopened))
        clean = wait_until(lambda: [c["name"] for c in net.status()["contents"]] == ["legitimo"] and [x["id"] for x in net.status()["peers"]] == ["s1"], 8)
        check(clean, "fechadas as sessoes do fuzzer, o tracker volta a ter so o seeder e o conteudo legitimos")
        out = os.path.join(net.dir, "out.bin")
        rc, res, _ = net.get("legitimo", "l1", ["-N", "-T", 30, "-o", out])
        check(rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "depois de tudo isso, um leecher legitimo baixa o conteudo intacto")
    finally:
        net.close()


def t_seeder():
    section("seeder: quadros e datagramas com MAC valido e conteudo malformado")
    net = Net(ttl=10000)
    try:
        path, digest = net.make_file("p.bin", 64 * 1024, seed=22)
        data = open(path, "rb").read()
        s = net.seed(path, "pequeno", "s1", ["-c", "1024"])
        ports = s.wait_for(r"tcp=(\d+) udp=(\d+)", 5)
        dport, uport = int(ports.group(1)), int(ports.group(2))
        cid = cf.build_manifest("pequeno", data, 1024, 2000)[1]

        ch = session(dport, role=1, register=False)
        got = []
        for req in (cid + struct.pack(">I", 5), cid + struct.pack(">I", 64), cid + struct.pack(">I", 0xFFFFFFFF), bytes(32) + struct.pack(">I", 0), cid + struct.pack(">I", 63)):
            ch.send(30, req)
            got.append(ch.recv())
        ch.s.close()
        r = cf.Reader(got[0][1])
        check(got[0][0] == 31 and r.u32() == 5 and r.blob() == data[5 * 1024:6 * 1024] and r.done(), "controle: CHUNK_REQ bem-formado recebe o chunk certo")
        check(got[1:4] == [(32, b"\x01")] * 3 and got[4][0] == 31, "indice n, indice 2^32-1 e conteudo desconhecido recebem CHUNK_ERR 1, e a sessao continua")

        cases = {
            "CHUNK_REQ vazio": (30, b""),
            "CHUNK_REQ com 35 bytes": (30, cid + b"\x00\x00\x05"),
            "CHUNK_REQ com 37 bytes": (30, cid + struct.pack(">I", 5) + b"\x00"),
            "CHUNK_DATA vindo do leecher": (31, struct.pack(">I", 0) + cf.blob(b"x")),
            "CHUNK_ERR vindo do leecher": (32, b"\x01"),
            "REGISTER na porta de dados": (10, struct.pack(">HH", 9, 9)),
            "HELLO depois do handshake": (1, bytes(16) + cf.s16("x") + b"\x01"),
            "tipo 0": (0, b""),
            "tipo 255": (255, b"zz"),
        }
        fails = [k for k, (t, p) in cases.items() if not rejected(session(dport, role=1, register=False), t, p)]
        raws = {"payload anunciado acima de 4 MiB": b"SP\x01\x1e" + struct.pack(">I", 4 * MIB + 1), "versao 2 no cabecalho": b"SP\x02\x1e" + struct.pack(">I", 0) + bytes(32)}
        fails += [k for k, rw in raws.items() if not rejected(session(dport, role=1, register=False), 0, b"", raw=rw)]
        check(not fails, "%d quadros malformados, fora de lugar ou acima do limite: o seeder encerra a conexao%s" % (len(cases) + len(raws), listed(fails)))
        count = 300
        reopened = random_frames(dport, [(30, cid + struct.pack(">I", 7)), (30, cid + struct.pack(">I", 63))], count, role=1, register=False)
        check(s.alive(), "o seeder sobrevive a %d quadros aleatorios com MAC valido na porta de dados (%d sessoes reabertas)" % (count, reopened))

        ku = cf.hm(KB, b"SPv1-udp")
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", 0))
        dest = ("127.0.0.1", uport)

        def exchange(dgrams, wait):
            for d in dgrams:
                u.sendto(d, dest)
            out = []
            end = time.time() + wait * SLOW
            while True:
                left = end - time.time()
                if left <= 0:
                    return out
                u.settimeout(left)
                try:
                    out.append(u.recv(4096))
                except socket.timeout:
                    return out

        def sealed(t, rid, body, version=1):
            d = b"SU" + bytes([version, t]) + struct.pack(">Q", rid) + body
            return d + cf.hm(ku, d)[:16]

        rep = [cf.udp_open(ku, d) for d in exchange([sealed(1, 1001, cid + struct.pack(">I", 3))], 0.5)]
        frag = [x for x in rep if x and x[0] == 2 and x[1] == 1001]
        body = frag[0][2] if frag else b""
        u.sendto(sealed(3, 1001, b"\x01\x01"), dest)
        check(len(body) == 1032 and struct.unpack(">HHI", body[:8]) == (0, 1, 1024) and body[8:] == data[3072:4096], "controle: REQ por UDP bem-formado recebe o fragmento certo")
        junk = {
            "REQ vazio": sealed(1, 2001, b""),
            "REQ com 35 bytes": sealed(1, 2002, cid + b"\x00\x00\x03"),
            "REQ com 37 bytes": sealed(1, 2003, cid + struct.pack(">I", 3) + b"\x00"),
            "ACK que anuncia 255 bytes de bitmap e traz 1": sealed(3, 2004, b"\xff\x01"),
            "ACK de reqid desconhecido": sealed(3, 2005, b"\x01\x01"),
            "DATA enviado ao seeder": sealed(2, 2006, struct.pack(">HHI", 0, 1, 10) + bytes(10)),
            "ERR enviado ao seeder": sealed(4, 2007, b"\x01"),
            "tipo 0": sealed(0, 2008, b"x"),
            "tipo 255": sealed(255, 2009, b""),
            "versao 2": sealed(1, 2010, cid + struct.pack(">I", 3), version=2),
            "MAC cortado": sealed(1, 2011, cid + struct.pack(">I", 3))[:-1],
            "so o cabecalho": b"SU\x01\x01" + bytes(8),
        }
        replies = exchange(list(junk.values()), 1.0)
        check(replies == [] and s.alive(), "%d datagramas malformados ou fora de lugar, com MAC valido, sao descartados em silencio" % len(junk))
        bases = [(1, cid + struct.pack(">I", 9)), (3, b"\x01\x01"), (2, struct.pack(">HHI", 0, 1, 1024) + bytes(1024)), (4, b"\x01")]
        for i in range(400):
            t, b = RNG.choice(bases)
            if RNG.random() < 0.1:
                t = RNG.randrange(256)
            u.sendto(sealed(t, 3000 + i, mutate(b)), dest)
        replies = exchange([], 1.0)
        check(s.alive() and all(cf.udp_open(ku, d) for d in replies), "o seeder sobrevive a 400 datagramas aleatorios com MAC valido, e tudo o que ele responde tem MAC valido")
        u.close()

        good = []
        for m in ("tcp", "udp"):
            out = os.path.join(net.dir, "o-%s.bin" % m)
            rc, res, _ = net.get("pequeno", "l-" + m, ["-m", m, "-N", "-T", 40, "-o", out])
            good.append(rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest)
        check(all(good), "depois do fuzzing, leechers legitimos baixam o conteudo intacto por TCP e por UDP")

        u2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u2.bind(("127.0.0.1", 0))
        u2.setblocking(False)
        seen, busy = set(), set()

        def drain():
            while True:
                try:
                    o = cf.udp_open(ku, u2.recv(4096))
                except (BlockingIOError, socket.timeout):
                    return
                if o and o[0] == 2:
                    seen.add(o[1])
                elif o and o[0] == 4 and o[2] == b"\x02":
                    busy.add(o[1])

        for i in range(700):
            u2.sendto(sealed(1, 900000 + i, cid + struct.pack(">I", i % 64)), dest)
            time.sleep(0.001 * SLOW)
            drain()
        end = time.time() + 1.0 * SLOW
        while time.time() < end:
            drain()
            time.sleep(0.02)
        u2.close()
        check(len(busy) > 0 and len(seen) <= 512, "700 REQs por UDP sem nenhum ACK: o seeder abre no maximo 512 transferencias (%d) e responde ERR 2, ocupado, as demais (%d)" % (len(seen), len(busy)))
        out = os.path.join(net.dir, "o-tcp2.bin")
        rc, res, _ = net.get("pequeno", "l-tcp2", ["-N", "-T", 40, "-o", out])
        check(rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "com a tabela de transferencias UDP cheia, o seeder continua servindo por TCP")
    finally:
        net.close()


VIOLATIONS = {"indice", "blob", "tipo", "errcurto", "mac", "gigante"}


class EvilTcp(cf.PySeed):
    """Seeder com a chave que responde aos pedidos de chunk de um jeito errado."""

    def __init__(self, net, ident, name, data, chunk, mode):
        self.mode = mode
        self.requests = 0
        self.tolerated = 0
        super().__init__("127.0.0.1", net.tport, KB, ident, name, data, chunk)

    def serve(self, c):
        c.settimeout(30)
        ch = cf.Channel(c, self.key)
        violated = False
        try:
            ch.server_handshake()
            while not self.stop:
                mtype, p = ch.recv()
                if mtype != 30 or len(p) != 36:
                    return
                if violated:
                    self.tolerated += 1
                self.requests += 1
                idx = struct.unpack(">I", p[32:36])[0]
                part = self.data[idx * self.chunk:(idx + 1) * self.chunk]
                good = struct.pack(">I", idx) + cf.blob(part)
                m = self.mode
                if m == "corrompe":
                    bad = bytearray(part)
                    bad[len(bad) // 2] ^= 0x5A
                    ch.send(31, struct.pack(">I", idx) + cf.blob(bytes(bad)))
                elif m == "excesso":
                    ch.send(31, struct.pack(">I", idx) + cf.blob(part + b"\x00"))
                elif m == "indice":
                    ch.send(31, struct.pack(">I", idx + 1) + cf.blob(part))
                elif m == "blob":
                    ch.send(31, struct.pack(">I", idx) + cf.blob(bytes(MIB + 1)))
                elif m == "tipo":
                    ch.send(13)
                elif m == "errcurto":
                    ch.send(32)
                elif m == "mac":
                    raw = bytearray(ch.frame_bytes(31, good, True))
                    raw[-1] ^= 1
                    c.sendall(bytes(raw))
                elif m == "gigante":
                    c.sendall(b"SP\x01\x1f" + struct.pack(">I", 4 * MIB + 1))
                elif m == "gotejando":
                    for b in ch.frame_bytes(31, good, True):
                        if self.stop:
                            return
                        c.sendall(bytes([b]))
                        time.sleep(0.25)
                violated = m in VIOLATIONS
        except (cf.Closed, socket.timeout, OSError, ValueError):
            pass
        finally:
            c.close()


class EvilUdp:
    """Seeder UDP com a chave que responde aos REQs com datagramas incoerentes."""

    def __init__(self, net, ident, name, data, chunk, mode):
        self.mode, self.data, self.chunk = mode, data, chunk
        self.requests = self.repeats = 0
        self.seen = set()
        self.stop = False
        self.manifest, self.cid, self.n = cf.build_manifest(name, data, chunk, 0)
        self.bits = cf.bitmap(self.n, range(self.n))
        self.ku = cf.hm(KB, b"SPv1-udp")
        self.u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.u.bind(("127.0.0.1", 0))
        self.u.settimeout(0.2)
        self.ctl = cf.connect("127.0.0.1", net.tport, KB)
        self.ctl.client_handshake(ident, 0)
        self.ctl.send(10, struct.pack(">HH", 9, self.u.getsockname()[1]))
        self.ctl.recv()
        self.ctl.send(12, self.manifest + cf.blob(self.bits))
        self.ctl.recv()
        for target in (self.beat, self.loop):
            threading.Thread(target=target, daemon=True).start()

    def beat(self):
        while not self.stop:
            time.sleep(0.15)
            try:
                self.ctl.send(14, struct.pack(">QQH", 0, 0, 1) + self.cid + cf.blob(self.bits))
                self.ctl.recv()
            except Exception:
                return

    def loop(self):
        while not self.stop:
            try:
                d, addr = self.u.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            o = cf.udp_open(self.ku, d)
            if not o or o[0] != 1 or len(o[2]) != 36:
                continue
            self.requests += 1
            if o[1] in self.seen:
                self.repeats += 1
            self.seen.add(o[1])
            for dg in self.reply(o[1], struct.unpack(">I", o[2][32:36])[0]):
                self.u.sendto(dg, addr)

    def reply(self, reqid, idx):
        part = self.data[idx * self.chunk:(idx + 1) * self.chunk]
        m = self.mode
        if m == "errlongo":
            return [cf.udp_seal(self.ku, 4, reqid, b"\x01\x00")]
        if m == "lixo":
            part = os.urandom(len(part))
        if m == "clen":
            part = part + b"\x00"
        total = -(-len(part) // 1200)
        out = []
        for fi in range(total):
            piece = part[fi * 1200:(fi + 1) * 1200]
            f_i, f_t = (total + fi if m == "frag" else fi), (total + 1 if m == "total" else total)
            if m == "tam":
                piece = piece[:-1]
            dg = cf.udp_seal(self.ku, 2, reqid + 1 if m == "reqid" else reqid, struct.pack(">HHI", f_i, f_t, len(part)) + piece)
            if m == "mac":
                dg = dg[:-1] + bytes([dg[-1] ^ 1])
            out.append(dg)
        return out

    def close(self):
        self.stop = True
        try:
            self.ctl.send(20)
        except Exception:
            pass
        self.ctl.s.close()
        self.u.close()


def timed_get(net, name, ident, extra, timeout):
    t0 = time.time()
    rc, res, p = net.get(name, ident, extra, timeout=timeout)
    return rc, res, time.time() - t0


def t_leecher():
    section("leecher: seeders maliciosos, com a chave, no mesmo conteudo de um seeder honesto")
    net = Net(ttl=10000)
    evil = []
    try:
        size, chunk = 256 * 1024, 16384
        path, digest = net.make_file("alvo.bin", size, seed=23)
        data = open(path, "rb").read()
        net.seed(path, "alvo", "honesto", ["-b", "0", "-r", "2000"])
        base = {}
        for m in ("tcp", "udp"):
            rc, res, dt = timed_get(net, "alvo", "ref-" + m, ["-m", m, "-N", "-T", 60, "-o", os.path.join(net.dir, "ref-%s.bin" % m)], 90)
            base[m] = dt if rc == 0 and res and res["ok"] else float("nan")

        modes = ["corrompe", "excesso", "indice", "blob", "tipo", "errcurto", "mac", "gigante", "mudo", "gotejando"]
        evil = [EvilTcp(net, "mal-" + m, "alvo", data, chunk, m) for m in modes]
        swarm = wait_until(lambda: holders(net, "alvo") == len(modes) + 1, 10)
        out = os.path.join(net.dir, "tcp.bin")
        rc, res, dt = timed_get(net, "alvo", "vitima", ["-N", "-T", 600, "-o", out], 660)
        check(swarm and rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "TCP: com %d seeders maliciosos e 1 honesto no mesmo conteudo, o download conclui e o arquivo e identico (%.1f s; so com o honesto, %.1f s)" % (len(modes), dt, base["tcp"]))
        idle = [e.mode for e in evil if e.requests == 0]
        check(not idle, "cada um dos %d comportamentos maliciosos foi exercitado (recebeu pedidos de chunk)%s" % (len(modes), listed(idle)))
        check(bool(res) and res["bytes_by_peer"] == {"honesto": size} and res["hash_failures"] >= 1, "nenhum byte dos maliciosos foi aceito: tudo veio do honesto, e %d chunks adulterados foram descartados pelo hash" % (res["hash_failures"] if res else 0))
        kept = [e.mode for e in evil if e.mode in VIOLATIONS and e.tolerated > 0]
        check(not kept, "depois de cada resposta que viola o protocolo (indice errado, blob acima de 1 MiB, tipo errado, CHUNK_ERR malformado, MAC invalido, quadro acima de 4 MiB), o leecher encerra a conexao%s" % listed(kept))
        for e in evil:
            e.close()
        evil = []
        wait_until(lambda: holders(net, "alvo") == 1, 5)

        umodes = ["lixo", "clen", "total", "frag", "tam", "reqid", "mac", "errlongo"]
        runs, idle, credited, loud, times = [], [], [], [], []
        hash_failures = 0
        for m in umodes:
            e = EvilUdp(net, "mu-" + m, "alvo", data, chunk, m)
            evil = [e]
            together = wait_until(lambda: holders(net, "alvo") == 2, 10)
            out = os.path.join(net.dir, "udp-%s.bin" % m)
            rc, res, dt = timed_get(net, "alvo", "vu-" + m, ["-m", "udp", "-N", "-T", 120, "-o", out], 150)
            times.append(dt)
            runs.append(together and rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest)
            if e.requests == 0:
                idle.append(m)
            if not res or res["bytes_by_peer"] != {"honesto": size}:
                credited.append(m)
            if m != "lixo" and e.repeats == 0:
                loud.append(m)
            hash_failures += res["hash_failures"] if res else 0
            e.close()
            evil = []
            wait_until(lambda: holders(net, "alvo") == 1, 5)
        check(all(runs), "UDP: com cada um dos %d seeders maliciosos ao lado do honesto, o download conclui e o arquivo e identico (de %.1f a %.1f s; so com o honesto, %.1f s)" % (len(umodes), min(times), max(times), base["udp"]))
        check(not idle and not credited and hash_failures >= 1, "UDP: todos os maliciosos foram exercitados, nenhum byte deles foi aceito e os fragmentos de lixo foram descartados pelo hash%s" % listed(idle + credited))
        check(not loud, "datagramas incoerentes (clen, total, indice de fragmento, tamanho, reqid, MAC, ERR de tamanho errado) sao descartados em silencio: o leecher segue reenviando o REQ%s" % listed(loud))
    finally:
        for e in evil:
            e.close()
        net.close()


SLOW_KINDS = ("silenciosa", "meio cabecalho", "corpo incompleto", "gotejando", "sem AUTH")


def slow_attack(port, per_kind, limit, during=None):
    """Abre conexoes lentas de 5 tipos e mede quando o servidor fecha cada uma."""
    conns = []
    for kind in SLOW_KINDS:
        for i in range(per_kind):
            s = socket.create_connection(("127.0.0.1", port), 5 * SLOW)
            t0 = time.time()
            hello = cf.Channel(None, KB).frame_bytes(1, os.urandom(16) + cf.s16("lento%d" % i) + b"\x00", False)
            first = {"silenciosa": b"", "meio cabecalho": hello[:4], "corpo incompleto": hello[:12], "gotejando": hello[:1], "sem AUTH": hello}[kind]
            if first:
                s.sendall(first)
            s.setblocking(False)
            conns.append({"kind": kind, "s": s, "t0": t0, "closed": None, "pos": len(first), "hello": hello})
    if during:
        during()
    sel = selectors.DefaultSelector()
    for c in conns:
        sel.register(c["s"], selectors.EVENT_READ, c)
    next_drip = time.time() + 0.4
    end = time.time() + limit + 1.0
    while time.time() < end and any(c["closed"] is None for c in conns):
        for key, _ in sel.select(0.05):
            c = key.data
            try:
                data = c["s"].recv(4096)
            except BlockingIOError:
                continue
            except OSError:
                data = b""
            if not data:
                c["closed"] = time.time() - c["t0"]
                sel.unregister(c["s"])
        now = time.time()
        if now >= next_drip:
            next_drip = now + 0.4
            for c in conns:
                if c["kind"] == "gotejando" and c["closed"] is None and c["pos"] < len(c["hello"]):
                    try:
                        c["s"].send(c["hello"][c["pos"]:c["pos"] + 1])
                        c["pos"] += 1
                    except OSError:
                        pass
    sel.close()
    for c in conns:
        c["s"].close()
    return conns


def worst_by_kind(conns):
    parts = []
    for k in SLOW_KINDS:
        times = [c["closed"] for c in conns if c["kind"] == k]
        parts.append("%s %s" % (k, "aberta" if None in times else "%.1f s" % max(times)))
    return ", ".join(parts)


def t_slow():
    section("conexoes lentas: prazo de 3 s por etapa do handshake")
    net = Net(ttl=10000)
    try:
        path, digest = net.make_file("v.bin", 256 * 1024, seed=24)
        s = net.seed(path, "v", "s1")
        dport = int(s.wait_for(r"tcp=(\d+) udp=(\d+)", 5).group(1))
        limit = 3.0 + 0.6 * SLOW
        listing = {}

        def during():
            t0 = time.time()
            r = run_list(net)
            listing["ok"] = r.returncode == 0
            listing["dt"] = time.time() - t0

        conns = slow_attack(net.tport, 60, limit, during)
        late = [c for c in conns if c["closed"] is None or c["closed"] > limit]
        check(not late, "300 conexoes lentas contra o tracker: todas encerradas em ate %.1f s, %d ainda abertas ou atrasadas (pior caso: %s)" % (limit, len(late), worst_by_kind(conns)))
        check(listing.get("ok", False) and listing["dt"] < 2.0 * SLOW, "durante esse ataque, o comando list e atendido normalmente (%.2f s)" % listing.get("dt", 0.0))

        pid = net.tracker.p.pid
        rss0 = proc_status(pid)["VmRSS"]
        socks = []
        for _ in range(200):
            c = socket.create_connection(("127.0.0.1", net.tport), 5 * SLOW)
            c.sendall(b"SP\x01\x01" + struct.pack(">I", 4 * MIB))
            c.setblocking(False)
            socks.append(c)
        t0 = time.time()
        peak, closed = rss0, set()
        while time.time() - t0 < 1.0 + 0.5 * SLOW and len(closed) < len(socks):
            for i, c in enumerate(socks):
                if i in closed:
                    continue
                try:
                    if c.recv(4096) == b"":
                        closed.add(i)
                except BlockingIOError:
                    pass
                except OSError:
                    closed.add(i)
            peak = max(peak, proc_status(pid)["VmRSS"])
            time.sleep(0.05)
        for c in socks:
            c.close()
        grow = (peak - rss0) / 1024.0
        check(len(closed) == len(socks) and grow < 100, "200 HELLO que anunciam payload de 4 MiB: o tracker fecha %d em ate %.1f s sem reservar a memoria (pico de RSS +%.0f MiB)" % (len(closed), 1.0 + 0.5 * SLOW, grow))

        conns = slow_attack(dport, 60, limit)
        late = [c for c in conns if c["closed"] is None or c["closed"] > limit]
        out = os.path.join(net.dir, "o.bin")
        rc, res, _ = net.get("v", "l1", ["-N", "-T", 30, "-o", out])
        check(not late and rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "300 conexoes lentas contra a porta de dados do seeder: todas encerradas em ate %.1f s (pior caso: %s), e depois ele serve um download" % (limit, worst_by_kind(conns)))
    finally:
        net.close()


def t_crowd():
    section("multidao: 300 peers autenticados ao mesmo tempo")
    net = Net(ttl=60000)
    try:
        pid = net.tracker.p.pid
        time.sleep(0.3)
        base = proc_status(pid)
        data = bytes(range(256)) * 80
        mraw, cid, n = cf.build_manifest("multidao", data, 1024, 0)
        total = 300
        chans = [None] * total
        errors = []

        def join(first):
            for i in range(first, total, 30):
                try:
                    ch = session(net.tport, "m%03d" % i)
                    ch.send(12, mraw + cf.blob(cf.bitmap(n, range(n))))
                    if ch.recv()[0] != 13:
                        raise RuntimeError("PUBLISH recusado")
                    chans[i] = ch
                except Exception as e:
                    errors.append("m%03d: %r" % (i, e))

        t0 = time.time()
        workers = [threading.Thread(target=join, args=(k,)) for k in range(30)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        dt = time.time() - t0
        st = net.try_status() or {"peers": [], "contents": []}
        c = [x for x in st["contents"] if x["name"] == "multidao"]
        check(not errors and len(st["peers"]) == total and len(c) == 1 and c[0]["holders"] == total, "300 sessoes autenticadas abertas ao mesmo tempo, todas registradas e publicando o mesmo conteudo (%.1f s), e o tracker lista todas%s" % (dt, (": " + errors[0]) if errors else ""))
        ids = []
        if chans[0]:
            chans[0].send(18, cid)
            mt, p = chans[0].recv()
            ids = [x["id"] for x in cf.parse_lookup(p)[1]] if mt == 19 else []
        check(len(ids) == total - 1 and len(set(ids)) == total - 1 and "m000" not in ids, "LOOKUP devolve os outros 299 peers, sem repeticao e sem o proprio")
        for i, ch in enumerate(chans):
            if ch is None:
                continue
            try:
                if i % 2 == 0:
                    ch.send(20)
            except OSError:
                pass
            ch.s.close()
        empty = wait_until(lambda: not net.status()["peers"] and not net.status()["contents"], 10)
        check(empty, "quando eles saem (metade com BYE, metade so fechando a conexao), o tracker fica sem peers e remove o conteudo")
        settled = wait_until(lambda: proc_status(pid)["fds"] <= base["fds"] + 2 and proc_status(pid)["Threads"] <= base["Threads"] + 2, 10)
        now = proc_status(pid)
        check(settled, "descritores e threads do tracker voltam ao nivel inicial (descritores %d -> %d, threads %d -> %d)" % (base["fds"], now["fds"], base["Threads"], now["Threads"]))
    finally:
        net.close()


def t_panel():
    section("painel web: saturacao por pedidos incompletos (limitacao documentada)")
    net = Net()
    try:
        url = "http://127.0.0.1:%d/api/status" % net.wport

        def probe():
            try:
                with urllib.request.urlopen(url, timeout=1.0 * SLOW) as r:
                    return r.status == 200
            except Exception:
                return False

        before = probe()
        hold = []
        for _ in range(32):
            c = socket.create_connection(("127.0.0.1", net.wport), 2 * SLOW)
            c.sendall(b"GET /api/status HTTP/1.1\r\nHost: x\r\n")
            hold.append(c)
        t_sat = time.time()
        time.sleep(0.3)
        down = not probe()
        r = run_list(net)
        back = None
        while time.time() - t_sat < 6 * SLOW:
            if probe():
                back = time.time() - t_sat
                break
            time.sleep(0.05)
        for c in hold:
            c.close()
        check(before and down, "32 pedidos HTTP incompletos ocupam todas as vagas do painel, que passa a recusar conexoes")
        check(r.returncode == 0, "durante a saturacao do painel, o plano de controle segue atendendo (list funciona)")
        check(back is not None and back <= 2.0 + 0.5 * SLOW, "o painel volta sozinho em %.1f s, quando vence o prazo de 2 s dos pedidos incompletos" % (back or -1))
    finally:
        net.close()


SECTIONS = [("tracker", t_tracker), ("seeder", t_seeder), ("leecher", t_leecher), ("lentas", t_slow), ("multidao", t_crowd), ("painel", t_panel)]

if __name__ == "__main__":
    if not os.path.exists(BIN):
        print("binario nao encontrado: %s (rode make)" % BIN)
        sys.exit(2)
    print("semente do fuzzer: %d (FUZZ_SEED)" % SEED)
    wanted = sys.argv[1:]
    for name, fn in SECTIONS:
        if wanted and name not in wanted:
            continue
        start = time.time()
        try:
            fn()
        except Exception as e:
            failed += 1
            print("  FALHOU excecao na secao '%s': %r" % (name, e), flush=True)
        print("  (%s: %.1f s)" % (name, time.time() - start), flush=True)
    section("relatorios de sanitizadores e erros de execucao nos processos")
    check(not SANITIZER_REPORTS, "nenhum relatorio de sanitizador (ASan, UBSan ou TSan) no stderr dos %d processos executados" % PROCESSES_SCANNED[0])
    for line in SANITIZER_REPORTS[:5]:
        print("      " + line)
    print("\nresultado: %d passaram, %d falharam" % (passed, failed))
    if failed == 0:
        print("TODOS OS TESTES PASSARAM")
    sys.exit(0 if failed == 0 else 1)
