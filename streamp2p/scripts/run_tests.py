import hashlib
import json
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import BIN, KEY, PROCESSES_SCANNED, SANITIZER_REPORTS, Net, ipv6_available, scan, sha256_file

passed = failed = skipped = 0


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


def skip(what):
    global skipped
    skipped += 1
    print("  pulado " + what, flush=True)


MIB = 1 << 20


def t_transfer():
    section("transferencia fim a fim em TCP e UDP, com verificacao independente do arquivo")
    net = Net()
    try:
        path, digest = net.make_file("video.bin", 4 * MIB, seed=7)
        net.seed(path, "video", "seed1", ["-b", "4000"])
        for m in ("tcp", "udp"):
            out = os.path.join(net.dir, "out-%s.bin" % m)
            rc, res, _ = net.get("video", "leech-" + m, ["-m", m, "-N", "-o", out, "-T", 60])
            check(rc == 0 and bool(res) and res["ok"], "download via %s conclui com sucesso" % m.upper())
            check(os.path.exists(out) and sha256_file(out) == digest, "o arquivo baixado via %s tem o mesmo SHA-256 do original (calculado pelo Python)" % m.upper())
            check(bool(res) and res["hash_failures"] == 0 and sum(res["bytes_by_peer"].values()) == 4 * MIB, "via %s: nenhuma falha de integridade e todos os bytes vieram do seeder" % m.upper())
    finally:
        net.close()


def t_sizes():
    section("tamanhos irregulares: ultimo chunk parcial, chunk maximo e conteudo grande")
    net = Net()
    try:
        for size, chunk in ((1, 1024), (1025, 1024), (100003, 5000), (3 * MIB, MIB)):
            path, digest = net.make_file("f%d.bin" % size, size, seed=size % 97 + 1)
            name = "s%d" % size
            net.seed(path, name, "sd%d" % size, ["-c", chunk])
            for m in ("tcp", "udp"):
                out = os.path.join(net.dir, "o%d-%s.bin" % (size, m))
                rc, res, _ = net.get(name, "g%s%d" % (m, size), ["-m", m, "-N", "-o", out, "-T", 60])
                check(rc == 0 and bool(res) and res["ok"] and os.path.getsize(out) == size and sha256_file(out) == digest, "%s: arquivo de %d bytes com chunks de %d bytes chega identico" % (m.upper(), size, chunk))
        path, digest = net.make_file("big.bin", 64 * MIB, seed=3)
        net.seed(path, "big", "sbig")
        out = os.path.join(net.dir, "big-out.bin")
        g = net.get_proc("big", "gbig", ["-N", "-o", out, "-T", 90, "-L", 20])
        check(g.wait_for(r"RESULT", 60) is not None and g.result()["ok"] and sha256_file(out) == digest, "conteudo de 64 MiB (4096 chunks) chega identico")
        c = [x for x in net.status()["contents"] if x["name"] == "big"][0]
        check(c["chunks"] == 4096 and len(c["availability"]) == 1024 and min(c["availability"]) >= 1, "o painel resume 4096 chunks em 1024 faixas, todos com copia")
        g.term()
    finally:
        net.close()


def t_conformance():
    section("conformidade: implementador independente em Python, escrito a partir de docs/PROTOCOL.md")
    import conformance as cf
    key = KEY.encode()
    net = Net(ttl=20000)
    loc = "127.0.0.1"
    try:
        path, _ = net.make_file("video.bin", 100003, seed=41)
        data = open(path, "rb").read()
        seed = net.seed(path, "video", "cseed", ["-c", 5000, "-b", 1234])
        ports = seed.wait_for(r"tcp=(\d+) udp=(\d+)", 5)
        tcp_port, udp_port = int(ports.group(1)), int(ports.group(2))

        ch = cf.connect(loc, net.tport, key)
        ok = True
        try:
            ch.client_handshake("pyclient", 0)
        except Exception:
            ok = False
        check(ok, "handshake do cliente Python com o tracker: as provas e o AUTH_OK com MAC conferem")
        ch.send(10, struct.pack(">HH", 1111, 2222))
        mtype, p = ch.recv()
        check(mtype == 11 and struct.unpack(">II", p) == (net.ttl // 3, net.ttl), "REGISTER_OK traz o intervalo de heartbeat e o TTL")
        ch.send(16)
        mtype, p = ch.recv()
        e = [x for x in cf.parse_list(p) if x["name"] == "video"]
        check(mtype == 17 and len(e) == 1 and (e[0]["size"], e[0]["chunk"], e[0]["bitrate"], e[0]["chunks"], e[0]["seeders"]) == (100003, 5000, 1234, 21, 1), "LIST_REPLY decodificado campo a campo confere com o conteudo publicado")
        ch.send(18, e[0]["id"])
        mtype, p = ch.recv()
        m, peers = cf.parse_lookup(p)
        want_raw, want_id, _ = cf.build_manifest("video", data, 5000, 1234)
        check(mtype == 19 and m["raw"] == want_raw and m["id"] == want_id == e[0]["id"], "o manifesto recebido e identico, byte a byte, ao montado em Python a partir do arquivo; o id e SHA-256('SPM1' || manifesto)")
        pe = [x for x in peers if x["id"] == "cseed"]
        check(len(pe) == 1 and (pe[0]["host"], pe[0]["tcp"], pe[0]["udp"]) == (loc, tcp_port, udp_port) and pe[0]["bitmap"] == cf.bitmap(21, range(21)), "LOOKUP_REPLY lista o seeder com endereco, portas e bitmap completo (bit menos significativo primeiro)")
        ch.send(18, b"\x00" * 32)
        mtype, _ = ch.recv()
        ch.send(16)
        mtype2, _ = ch.recv()
        check(mtype == 5 and mtype2 == 17, "LOOKUP de conteudo desconhecido recebe ERROR e a sessao continua")

        dc = cf.connect(loc, tcp_port, key)
        dc.client_handshake("pyclient", 1)
        dc.send(30, m["id"] + struct.pack(">I", 20))
        mtype, p = dc.recv()
        r = cf.Reader(p)
        idx, body = r.u32(), r.blob()
        check(mtype == 31 and idx == 20 and body == data[100000:] and r.done() and hashlib.sha256(body).digest() == m["hashes"][20], "CHUNK_DATA do ultimo chunk (3 bytes) por TCP confere com o arquivo e com o hash do manifesto")
        dc.send(30, m["id"] + struct.pack(">I", 21))
        mtype, p = dc.recv()
        check(mtype == 32 and p == b"\x01", "CHUNK_REQ de indice inexistente recebe CHUNK_ERR com codigo 1")

        bad = cf.connect(loc, net.tport, key)
        bad.client_handshake("pyrole", 1)
        bad2 = cf.connect(loc, tcp_port, key)
        bad2.client_handshake("pyrole", 0)
        check(bad.recv()[0] == 5 and bad2.recv()[0] == 5, "papel errado e recusado com ERROR nos dois servidores")
        nr = cf.connect(loc, net.tport, key)
        nr.client_handshake("pynoreg", 0)
        nr.send(16)
        check(nr.recv()[0] == 5, "mensagem antes do REGISTER recebe ERROR")

        def closes(channel):
            try:
                channel.recv()
            except cf.Closed:
                return True
            except Exception:
                return False
            return False

        t = cf.connect(loc, net.tport, key)
        t.client_handshake("pytamper", 0)
        t.send(10, struct.pack(">HH", 1, 2))
        t.recv()
        raw = bytearray(t.frame_bytes(16, b"", True))
        raw[-1] ^= 1
        t.s.sendall(bytes(raw))
        check(closes(t), "quadro com um bit do MAC alterado: o tracker encerra a conexao")
        rp = cf.connect(loc, net.tport, key)
        rp.client_handshake("pyreplay", 0)
        rp.send(10, struct.pack(">HH", 1, 2))
        rp.recv()
        frame = rp.frame_bytes(16, b"", True)
        rp.s.sendall(frame)
        first = rp.recv()[0]
        rp.s.sendall(frame)
        check(first == 17 and closes(rp), "quadro repetido com o mesmo contador: aceito uma vez e, na repeticao, a conexao e encerrada")
        wrong = False
        try:
            cf.connect(loc, net.tport, b"outra-chave").client_handshake("pywrong", 0)
        except ValueError:
            wrong = True
        check(wrong, "com chave errada, a prova do servidor nao confere para o cliente Python")

        ku = cf.hm(key, b"SPv1-udp")
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(1.0)
        reqid = 0x1122334455667788
        u.sendto(cf.udp_seal(ku, 1, reqid, m["id"] + struct.pack(">I", 3)), (loc, udp_port))
        frags, total, clen, copies0 = {}, 0, 0, 0
        end = time.time() + 4
        while time.time() < end:
            try:
                d, _ = u.recvfrom(2048)
            except socket.timeout:
                break
            o = cf.udp_open(ku, d)
            if not o or o[0] != 2 or o[1] != reqid:
                continue
            r = cf.Reader(o[2])
            fi, total, clen = r.u16(), r.u16(), r.u32()
            frags[fi] = o[2][8:]
            copies0 += 1 if fi == 0 else 0
            have = list(frags) if copies0 >= 2 else [i for i in frags if i != 0]
            u.sendto(cf.udp_seal(ku, 3, reqid, bytes([(total + 7) // 8]) + cf.bitmap(total, have)), (loc, udp_port))
            if copies0 >= 2 and len(frags) == total:
                break
        whole = b"".join(frags.get(i, b"") for i in range(total))
        check(total == 5 and clen == 5000 and whole == data[15000:20000] and len(frags.get(4, b"")) == 200, "UDP: os 5 fragmentos DATA, com MAC de 16 bytes valido, remontam o chunk de 5000 bytes")
        check(copies0 >= 2, "UDP: o fragmento deixado fora do ACK e retransmitido pelo peer")
        for _ in range(2):
            u.sendto(cf.udp_seal(ku, 3, reqid, bytes([1]) + cf.bitmap(5, range(5))), (loc, udp_port))
        u.sendto(cf.udp_seal(ku, 1, reqid + 1, m["id"] + struct.pack(">I", 999)), (loc, udp_port))
        o = cf.udp_open(ku, u.recvfrom(2048)[0])
        check(o is not None and o[0] == 4 and o[1] == reqid + 1 and o[2] == b"\x01", "UDP: REQ de chunk inexistente recebe ERR com codigo 1")
        forged = bytearray(cf.udp_seal(ku, 1, reqid + 2, m["id"] + struct.pack(">I", 0)))
        forged[20] ^= 1
        u.sendto(bytes(forged), (loc, udp_port))
        u.settimeout(0.4)
        silent = False
        try:
            u.recvfrom(2048)
        except socket.timeout:
            silent = True
        check(silent, "UDP: datagrama com MAC invalido e descartado em silencio")
        u.close()

        rnd = random.Random(7)
        pdata = bytes(rnd.getrandbits(8) for _ in range(100000))
        ps = cf.PySeed(loc, net.tport, key, "pyseed", "pycontent", pdata, 16384)
        check(ps.register_ok == (11, (net.ttl // 3, net.ttl)) and ps.unknown_first == (15, [ps.cid]) and ps.publish_reply == 13 and ps.unknown_second == (15, []), "seeder Python: o HEARTBEAT de conteudo desconhecido devolve o id; depois do PUBLISH, a lista vem vazia")
        net.wait_holders("pycontent", 1)
        st = [c for c in net.status()["contents"] if c["name"] == "pycontent"]
        check(len(st) == 1 and st[0]["seeders"] == 1 and st[0]["chunks"] == 7 and st[0]["id"] == ps.cid.hex(), "o tracker aceita o manifesto montado em Python e conta o peer como seeder completo")
        out = os.path.join(net.dir, "from-python.bin")
        rc, res, _ = net.get("pycontent", "cppleech", ["-m", "tcp", "-N", "-o", out, "-T", 30])
        check(rc == 0 and bool(res) and res["ok"] and open(out, "rb").read() == pdata and res["bytes_by_peer"] == {"pyseed": 100000}, "o leecher em C++ baixa o conteudo inteiro do seeder Python e o arquivo e identico")
        ps.close()
        pdata2 = bytes(rnd.getrandbits(8) for _ in range(100000))
        ps2 = cf.PySeed(loc, net.tport, key, "pypart", "pypartial", pdata2, 16384, have=[0, 2, 5])
        ch.send(18, ps2.cid)
        mtype, p = ch.recv()
        m2, peers2 = cf.parse_lookup(p)
        check(mtype == 19 and [(x["id"], x["bitmap"]) for x in peers2] == [("pypart", bytes([0b00100101]))], "bitmap parcial anunciado em Python (chunks 0, 2 e 5) volta identico na consulta de outro peer")
        ps2.close()
    finally:
        net.close()


def result_from(path):
    with open(path, errors="replace") as f:
        text = f.read()
    scan(os.path.basename(path), text)
    m = re.search(r"^RESULT (\{.*\})$", text, re.M)
    return json.loads(m.group(1)) if m else None


def t_list():
    section("catalogo: lista de conteudos disponiveis")
    net = Net()
    try:
        r = run_cli(["list", "-t", net.tracker_addr])
        check(r.returncode == 0 and "nenhum conteudo disponivel" in r.stdout, "com o tracker vazio, list informa que nao ha conteudos")
        path, _ = net.make_file("video.bin", MIB, seed=61)
        s = net.seed(path, "meu video", "s1", ["-b", "1500"])
        cid = s.wait_for(r"conteudo ([0-9a-f]{64}) ", 5).group(1)
        r = run_cli(["list", "-t", net.tracker_addr])
        rows = [line.split() for line in r.stdout.splitlines() if line.startswith("meu video")]
        check(r.returncode == 0 and len(rows) == 1 and rows[0][-6:] == ["1048576", "64", "1500", "1", "1", cid], "list mostra nome, tamanho, chunks, taxa, seeders, peers e o id completo do conteudo publicado")
        out = os.path.join(net.dir, "by-id.bin")
        byid = subprocess.run([BIN, "get", "-t", net.tracker_addr, "-I", cid, "-i", "byid", "-d", os.path.join(net.dir, "st-byid"), "-N", "-o", out, "-T", "30"],
                              capture_output=True, text=True, env=dict(os.environ, STREAMP2P_KEY=KEY), timeout=60)
        scan("byid", byid.stderr)
        rc = byid.returncode
        check(rc == 0 and sha256_file(out) == sha256_file(path), "o id mostrado por list serve para pedir o conteudo com get -I")
        r = run_cli(["list", "-t", net.tracker_addr], key="outra-chave")
        r2 = run_cli(["list", "-t", "127.0.0.1:1"])
        check(r.returncode == 2 and r.stderr.strip() != "" and r2.returncode == 2, "list com chave errada ou tracker inacessivel sai com codigo 2 e mensagem")
        time.sleep(0.5)
        check(net.peer_ids() == ["s1"], "o cliente de listagem nao fica registrado no tracker")
    finally:
        net.close()


def t_stream():
    section("streaming: entrega em ordem e no ritmo da reproducao, inclusive para um decodificador real")
    net = Net()
    env = dict(os.environ, STREAMP2P_KEY=KEY)
    try:
        size = 2 * MIB
        path, digest = net.make_file("clip.bin", size, seed=51)
        data = open(path, "rb").read()
        net.seed(path, "clip", "s1", ["-b", "4000"])
        duration = size * 8 / 4000 / 1000
        out = os.path.join(net.dir, "play.stream")
        g = net.get_proc("clip", "v1", ["-B", "3", "-s", out, "-T", 60])
        time.sleep(duration / 2)
        partial = os.path.getsize(out) if os.path.exists(out) else 0
        rc = g.wait_exit(60)
        res = g.result()
        check(rc == 0 and bool(res) and res["ok"] and res["streamed_bytes"] == size and sha256_file(out) == digest, "com -s ARQUIVO o conteudo e entregue inteiro e em ordem")
        check(0.2 * size < partial < 0.8 * size, "na metade do tempo do video, %d%% do conteudo tinha sido entregue: a saida segue o ritmo da reproducao" % round(100 * partial / size))
        errp = os.path.join(net.dir, "v2.err")
        with open(errp, "w") as ef:
            p2 = subprocess.run([BIN, "get", "-t", net.tracker_addr, "-n", "clip", "-i", "v2", "-d", os.path.join(net.dir, "st-v2"), "-s", "-", "-N", "-T", "60"], stdout=subprocess.PIPE, stderr=ef, env=env, timeout=90)
        r2 = result_from(errp)
        check(p2.returncode == 0 and p2.stdout == data and bool(r2) and r2["ok"] and r2["streamed_bytes"] == size, "com -s - a saida padrao traz exatamente os bytes do conteudo, e as metricas vao para a saida de erro")
        errp = os.path.join(net.dir, "v3.err")
        with open(errp, "w") as ef:
            p3 = subprocess.Popen([BIN, "get", "-t", net.tracker_addr, "-n", "clip", "-i", "v3", "-d", os.path.join(net.dir, "st-v3"), "-s", "-", "-B", "3", "-T", "60"], stdout=subprocess.PIPE, stderr=ef, env=env)
            head = p3.stdout.read(200000)
            p3.stdout.close()
            rc3 = p3.wait(timeout=90)
        r3 = result_from(errp)
        check(rc3 == 0 and head == data[:200000] and bool(r3) and r3["ok"] and 200000 <= r3["streamed_bytes"] < size, "se o consumidor fecha a saida no meio, o programa nao quebra: conclui o download e sai com codigo 0")
        if shutil.which("ffmpeg") and shutil.which("ffprobe"):
            video = os.path.join(net.dir, "video.ts")
            subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=25", "-f", "lavfi", "-i", "sine=frequency=440", "-t", "6",
                            "-c:v", "mpeg2video", "-b:v", "800k", "-c:a", "mp2", "-b:a", "64k", "-f", "mpegts", video], check=True, capture_output=True)
            rate = int(os.path.getsize(video) * 8 / 6 / 1000 * 1.3)
            seeds = [net.seed(video, "video", "m%d" % i, ["-b", rate, "-r", int(rate * 0.8)]) for i in (1, 2)]
            net.wait_holders("video", 2)
            errp = os.path.join(net.dir, "v4.err")
            with open(errp, "w") as ef:
                g4 = subprocess.Popen([BIN, "get", "-t", net.tracker_addr, "-n", "video", "-i", "v4", "-d", os.path.join(net.dir, "st-v4"), "-s", "-", "-B", "4", "-T", "90"], stdout=subprocess.PIPE, stderr=ef, env=env)
                probe = subprocess.Popen(["ffprobe", "-v", "error", "-count_frames", "-select_streams", "v:0", "-show_entries", "stream=codec_name,nb_read_frames", "-of", "json", "-i", "pipe:0"],
                                         stdin=g4.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                g4.stdout.close()
                time.sleep(2.0)
                seeds[0].kill()
                pout, perr = probe.communicate(timeout=120)
                rc4 = g4.wait(timeout=120)
            info = (json.loads(pout).get("streams") or [{}])[0] if pout.strip() else {}
            r4 = result_from(errp)
            check(rc4 == 0 and info.get("codec_name") == "mpeg2video" and info.get("nb_read_frames") == "150" and perr.strip() == "", "video MPEG-TS real: o ffprobe decodifica os 150 quadros direto da saida do leecher, sem erros")
            check(bool(r4) and r4["ok"] and len(r4["bytes_by_peer"]) == 2 and r4["bytes_by_peer"].get("m1", 0) > 0, "esse video veio dos dois seeders, e um deles foi morto no meio da transmissao")
        else:
            skip("ffmpeg e ffprobe nao estao instalados: o teste com video real foi pulado")
    finally:
        net.close()


def t_swarm():
    section("enxame: varios seeders atendem em paralelo")
    net = Net()
    try:
        path, digest = net.make_file("film.bin", 4 * MIB, seed=3)
        for i in range(1, 4):
            net.seed(path, "film", "s%d" % i, ["-r", "4000"])
        net.wait_holders("film", 3)
        out = os.path.join(net.dir, "out.bin")
        rc, res, _ = net.get("film", "l1", ["-N", "-o", out, "-T", 60])
        check(rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "download a partir de 3 seeders conclui e o arquivo e identico")
        check(bool(res) and len(res["bytes_by_peer"]) == 3, "os tres seeders contribuiram com bytes")
        single_ms = 4 * MIB * 8 / 4000
        check(bool(res) and res["download_ms"] < 0.7 * single_ms, "com 3 seeders de 4 Mbit/s o download leva %.1f s, menos de 70%% dos %.1f s de um seeder so" % (res["download_ms"] / 1000 if res else 0, single_ms / 1000))
    finally:
        net.close()


def t_p2p():
    section("P2P: quem baixou passa a servir os outros")
    net = Net()
    try:
        path, digest = net.make_file("film.bin", 4 * MIB, seed=4)
        net.seed(path, "swarm2", "origin2", ["-r", "4000"])
        pa = net.get_proc("swarm2", "pa", ["-N", "-T", 90])
        pb = net.get_proc("swarm2", "pb", ["-N", "-T", 90])
        pa.wait_exit(90)
        pb.wait_exit(90)
        ra, rb = pa.result(), pb.result()
        exchanged = (ra["bytes_by_peer"].get("pb", 0) if ra else 0) + (rb["bytes_by_peer"].get("pa", 0) if rb else 0)
        check(bool(ra) and bool(rb) and ra["ok"] and rb["ok"] and exchanged > 0, "dois leechers simultaneos trocam chunks entre si (%d KiB vindos do outro leecher), nao so da origem" % (exchanged // 1024))
        check(bool(ra) and bool(rb) and max(ra["download_ms"], rb["download_ms"]) < 0.8 * 2 * 4 * MIB * 8 / 4000, "e terminam antes do que levariam se a origem atendesse os dois sozinha (%.1f s)" % (max(ra["download_ms"], rb["download_ms"]) / 1000 if ra and rb else 0))
        pa.term()
        pb.term()
        origin = net.seed(path, "film", "orig", ["-r", "8000"])
        x = net.get_proc("film", "x", ["-N", "-T", 60, "-L", 30, "-X"])
        check(x.wait_for(r"RESULT", 40) is not None and x.result()["ok"], "um leecher com -X conclui o download")
        time.sleep(1.5)
        holders = [c["holders"] for c in net.status()["contents"] if c["name"] == "film"]
        check(holders == [1], "com -X o leecher nao anuncia chunks: continua so 1 peer com o conteudo no tracker")
        x.term()
        out1 = os.path.join(net.dir, "a.bin")
        a = net.get_proc("film", "a", ["-N", "-o", out1, "-T", 60, "-L", 60])
        check(a.wait_for(r"RESULT", 40) is not None and a.result()["ok"], "o primeiro leecher conclui o download")
        net.wait_holders("film", 2)
        origin.kill()
        check(net.wait_peer("orig", 10, present=False), "o tracker nota que o seeder original caiu")
        out2 = os.path.join(net.dir, "b.bin")
        rc, res, _ = net.get("film", "b", ["-N", "-o", out2, "-T", 60])
        check(rc == 0 and bool(res) and res["ok"] and sha256_file(out2) == digest, "o segundo leecher baixa o arquivo completo sem o seeder original")
        check(bool(res) and list(res["bytes_by_peer"].keys()) == ["a"], "todos os bytes do segundo leecher vieram do primeiro (compartilhamento P2P)")
        a.term()
    finally:
        net.close()


def t_kill_midway():
    section("tolerancia a falhas: um seeder morre no meio do streaming")
    net = Net()
    try:
        path, digest = net.make_file("big.bin", 8 * MIB, seed=5)
        seeds = [net.seed(path, "big", "s%d" % i, ["-r", "4000"]) for i in range(1, 4)]
        net.wait_holders("big", 3)
        out = os.path.join(net.dir, "out.bin")
        g = net.get_proc("big", "leech", ["-N", "-o", out, "-T", 90])
        time.sleep(1.5)
        seeds[1].kill()
        rc = g.wait_exit(90)
        res = g.result()
        check(rc == 0 and bool(res) and res["ok"], "o download conclui apesar da morte de um dos tres seeders")
        check(os.path.exists(out) and sha256_file(out) == digest, "o arquivo continua identico ao original")
        check(bool(res) and res["bytes_by_peer"].get("s2", 0) > 0 and res["bytes_by_peer"].get("s1", 0) > 0 and res["bytes_by_peer"].get("s3", 0) > 0, "o seeder morto serviu antes de cair e os outros dois assumiram o restante")
        check(net.wait_peer("s2", 5, present=False), "o tracker removeu o seeder morto")
        s = net.status()
        check(any("s2 saiu" in e["msg"] for e in s["events"]), "o painel registra o evento de saida do peer")
    finally:
        net.close()


def t_expiry():
    section("deteccao de peer que para de responder (sem fechar a conexao)")
    net = Net(ttl=2000)
    try:
        path, _ = net.make_file("v.bin", MIB, seed=2)
        s = net.seed(path, "v", "s1")
        s.freeze()
        t0 = time.time()
        gone = net.wait_peer("s1", 8, present=False)
        dt = time.time() - t0
        check(gone and 1.5 <= dt <= 5.0, "peer congelado e declarado caido em %.1f s (prazo de 2 s sem heartbeat)" % dt)
        st = net.status()
        check(st["stats"]["expired"] >= 1 and any("sem heartbeat" in e["msg"] for e in st["events"]), "a expiracao por falta de heartbeat aparece nas estatisticas e nos eventos")
        s.thaw()
        check(net.wait_peer("s1", 12), "ao voltar, o peer se registra de novo sozinho")
        check(net.wait_holders("v", 1, 8), "e o conteudo volta ao catalogo")
    finally:
        net.close()


def t_tracker_restart():
    section("tolerancia a falhas: queda e retorno do tracker")
    net = Net()
    try:
        path, digest = net.make_file("a.bin", 2 * MIB, seed=8)
        net.seed(path, "a", "s1")
        net.tracker.kill()
        time.sleep(0.6)
        net.start_tracker()
        check(net.wait_peer("s1", 15), "o seeder se registra sozinho no tracker que voltou")
        check(net.wait_holders("a", 1, 10), "o conteudo e republicado automaticamente (o novo tracker nao o conhecia)")
        out = os.path.join(net.dir, "out1.bin")
        rc, res, _ = net.get("a", "l1", ["-N", "-o", out, "-T", 40])
        check(rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "depois do retorno do tracker, downloads funcionam normalmente")
        path2, digest2 = net.make_file("b.bin", 4 * MIB, seed=9)
        net.seed(path2, "b", "s2", ["-r", "5000"])
        out2 = os.path.join(net.dir, "out2.bin")
        g = net.get_proc("b", "l2", ["-N", "-o", out2, "-T", 60])
        time.sleep(1.0)
        net.tracker.kill()
        rc = g.wait_exit(60)
        res = g.result()
        check(rc == 0 and bool(res) and res["ok"] and sha256_file(out2) == digest2, "se o tracker cai durante o download, ele termina com os peers ja conhecidos")
    finally:
        net.close()


def t_resume():
    section("recuperacao de transmissao interrompida (retomada)")
    net = Net()
    try:
        path, digest = net.make_file("video.bin", 4 * MIB, seed=6)
        net.seed(path, "video", "s1", ["-r", "6000"])
        store = os.path.join(net.dir, "store-resume")
        g = net.get_proc("video", "r1", ["-N", "-T", 60], store=store)
        time.sleep(1.5)
        g.kill()
        out = os.path.join(net.dir, "out.bin")
        rc, res, _ = net.get("video", "r2", ["-N", "-o", out, "-T", 60], store=store)
        check(rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "o leecher reiniciado conclui e o arquivo e identico")
        check(bool(res) and 0 < res["resumed"] < res["chunks"], "ele aproveitou %d dos %d chunks ja baixados antes da interrupcao" % (res["resumed"] if res else 0, res["chunks"] if res else 0))
        check(bool(res) and sum(res["bytes_by_peer"].values()) < 4 * MIB, "so os chunks que faltavam foram baixados pela rede")
    finally:
        net.close()


def t_integrity():
    section("integridade: chunks corrompidos por um peer malicioso sao detectados")
    net = Net()
    try:
        path, digest = net.make_file("video.bin", 2 * MIB, seed=10)
        net.seed(path, "video", "good", ["-r", "8000"])
        net.seed(path, "video", "evil", ["-C", "1.0"])
        net.wait_holders("video", 2)
        out = os.path.join(net.dir, "out.bin")
        rc, res, _ = net.get("video", "l1", ["-N", "-o", out, "-T", 60])
        check(rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "com um seeder honesto e um malicioso, o arquivo final e identico ao original")
        check(bool(res) and res["hash_failures"] > 0, "os chunks adulterados foram rejeitados pelo hash (%d rejeicoes)" % (res["hash_failures"] if res else 0))
    finally:
        net.close()
    net = Net()
    try:
        path, _ = net.make_file("video.bin", MIB, seed=10)
        net.seed(path, "video", "evil", ["-C", "1.0"])
        out = os.path.join(net.dir, "out.bin")
        rc, res, p = net.get("video", "l1", ["-N", "-o", out, "-T", 6])
        res = res or p.result()
        check(rc == 2 and bool(res) and not res["ok"] and res["hash_failures"] > 0 and not os.path.exists(out), "so com o seeder malicioso o download falha e nenhum arquivo corrompido e gravado")
    finally:
        net.close()


def raw_send(port, payload, host="127.0.0.1"):
    s = socket.create_connection((host, port), 2)
    try:
        if payload:
            s.sendall(payload)
        s.settimeout(0.5)
        try:
            s.recv(200)
        except OSError:
            pass
    finally:
        s.close()


def t_auth():
    section("seguranca: autenticacao por chave compartilhada")
    net = Net()
    try:
        path, digest = net.make_file("video.bin", MIB, seed=11)
        net.seed(path, "video", "intruder", key="outra-chave", wait=False)
        time.sleep(2.0)
        st = net.status()
        check(st["stats"]["auth_failures"] >= 1 and "intruder" not in net.peer_ids(), "peer com chave errada e recusado e nao entra na lista")
        for payload in (os.urandom(2000), b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"SP\x01\x01\xff\xff\xff\xff" + b"A" * 50, b"SP\x01\x01\x00\x00\x00\x00", b""):
            raw_send(net.tport, payload)
        good = net.seed(path, "video", "good")
        check(net.wait_peer("good", 8), "o tracker continua atendendo peers legitimos depois de receber lixo na porta de controle")
        ports = good.wait_for(r"tcp=(\d+) udp=(\d+)", 5)
        raw_send(int(ports.group(1)), os.urandom(500))
        raw_send(int(ports.group(1)), b"SP\x01\x01" + b"\xff" * 20)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(20):
            u.sendto(os.urandom(100), ("127.0.0.1", int(ports.group(2))))
        u.close()
        rc, res, _ = net.get("video", "ok1", ["-N", "-T", 30])
        check(rc == 0 and bool(res) and res["ok"], "o seeder segue servindo normalmente depois de receber lixo nas portas de dados (TCP e UDP)")
        rc, res, p = net.get("video", "badleech", ["-T", 3], key="outra-chave")
        check(rc == 2 and not (res and res["ok"]), "um leecher com chave errada nao consegue baixar nada")
        good.term()
        stats = good.stats()
        check(bool(stats) and stats["auth_failures"] >= 2, "o seeder contou as conexoes de dados nao autenticadas (%d)" % (stats["auth_failures"] if stats else 0))
    finally:
        net.close()


def t_udp_loss():
    section("UDP com confiabilidade na aplicacao: perda, atraso e jitter")
    net = Net()
    try:
        path, digest = net.make_file("video.bin", 2 * MIB, seed=12)
        s = net.seed(path, "video", "lossy", ["-l", "0.2", "-S", "5"])
        out = os.path.join(net.dir, "out.bin")
        rc, res, _ = net.get("video", "l1", ["-m", "udp", "-l", "0.2", "-R", "60", "-N", "-o", out, "-T", 100])
        check(rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "com 20% de perda nos dois sentidos, o download UDP conclui e o arquivo e identico")
        s.term()
        st = s.stats()
        check(bool(st) and st["udp_sim_drops"] > 0 and st["udp_retx"] > 0, "houve perdas simuladas (%d) e retransmissoes (%d)" % (st["udp_sim_drops"] if st else 0, st["udp_retx"] if st else 0))
    finally:
        net.close()
    net = Net()
    try:
        path, digest = net.make_file("video.bin", MIB, seed=13)
        net.seed(path, "video", "far", ["-D", "20", "-j", "10"])
        for m in ("tcp", "udp"):
            out = os.path.join(net.dir, "out-%s.bin" % m)
            rc, res, _ = net.get("video", "l-" + m, ["-m", m, "-N", "-o", out, "-T", 60])
            check(rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "com atraso de 20 ms e jitter de 10 ms, %s conclui e o arquivo e identico" % m.upper())
            check(bool(res) and res["lat_p50_ms"] >= 20, "a latencia mediana por chunk em %s (%.0f ms) reflete o atraso emulado" % (m.upper(), res["lat_p50_ms"] if res else 0))
    finally:
        net.close()


def t_ipv6():
    section("IPv6")
    if not ipv6_available():
        skip("este kernel nao tem IPv6 (o suporte dual-stack foi escrito, mas so o caminho IPv4 pode ser exercitado aqui)")
        return
    net = Net(ipv6=True)
    try:
        path, digest = net.make_file("video.bin", MIB, seed=14)
        net.seed(path, "video", "s6")
        for m in ("tcp", "udp"):
            out = os.path.join(net.dir, "o6-%s.bin" % m)
            rc, res, _ = net.get("video", "l6" + m, ["-m", m, "-N", "-o", out, "-T", 40])
            check(rc == 0 and bool(res) and res["ok"] and sha256_file(out) == digest, "download %s com tracker em [::1]" % m.upper())
    finally:
        net.close()


def http(url, method="GET", data=None):
    req = urllib.request.Request(url, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def t_web():
    section("painel web (bonus)")
    net = Net()
    try:
        path, digest = net.make_file("video.bin", MIB, seed=15)
        name = 'Filme "Teste" <script>alert(1)</script>'
        net.seed(path, name, "s1")
        base = "http://127.0.0.1:%d" % net.wport
        code, headers, body = http(base + "/")
        html = body.decode()
        check(code == 200 and "text/html" in headers["Content-Type"] and "painel do tracker" in html, "a pagina inicial e servida como HTML")
        check("innerHTML" not in html and "eval(" not in html and "document.write" not in html and "http://" not in html and "https://" not in html, "a pagina nao usa innerHTML/eval nem carrega recursos externos (funciona offline e sem XSS)")
        check(headers.get("X-Content-Type-Options") == "nosniff" and headers.get("Cache-Control") == "no-store", "cabecalhos de seguranca e de cache presentes")
        st = net.status()
        check(st["peers"][0]["id"] == "s1" and st["contents"][0]["name"] == name, "a API devolve o nome do conteudo com aspas e tags intactos (escapados no JSON)")
        c = st["contents"][0]
        check(len(c["availability"]) == c["chunks"] == 64 and set(c["availability"]) == {1} and c["seeders"] == 1, "a disponibilidade por chunk tem um item por chunk, todos com 1 copia")
        g = net.get_proc(name, "l1", ["-N", "-T", 30, "-L", 8])
        check(g.wait_for(r"RESULT", 20) is not None, "um leecher baixa o conteudo pelo nome (com caracteres especiais)")
        net.wait_holders(name, 2)
        st = net.status()
        peers = {p["id"]: p for p in st["peers"]}
        check(set(st["contents"][0]["availability"]) == {2} and peers["l1"]["downloaded"] > 0 and peers["s1"]["uploaded"] > 0, "o painel mostra 2 copias por chunk e os contadores de envio e recebimento")
        check(any("entrou" in e["msg"] for e in st["events"]) and st["stats"]["registrations"] >= 2, "eventos e estatisticas do tracker estao atualizados")
        g.term()
        check(http(base + "/nada")[0] == 404 and http(base + "/../../etc/passwd")[0] == 404 and http(base + "/api/status", "POST", b"x")[0] == 405, "rota inexistente e tentativa de path traversal dao 404; metodo POST da 405")
        s = socket.create_connection(("127.0.0.1", net.wport), 2)
        s.sendall(b"\x00\x01garbage\r\n\r\n")
        s.settimeout(1)
        try:
            data = s.recv(100)
        except OSError:
            data = b""
        s.close()
        check(b"400" in data[:20] or data == b"" or b"405" in data[:20], "requisicao HTTP malformada e recusada sem derrubar o painel")
        check(http(base + "/api/status")[0] == 200, "o painel continua respondendo")
    finally:
        net.close()


def t_playback():
    section("streaming: buffer de reproducao, pre-buffer e travadas")
    net = Net()
    try:
        path, _ = net.make_file("clip.bin", 2 * MIB, seed=16)
        duration_ms = 2 * MIB * 8 / 8000
        net.seed(path, "clip", "fast", ["-b", "8000"])
        rc, res, _ = net.get("clip", "v1", ["-B", "3", "-T", 30])
        check(rc == 0 and bool(res) and res["ok"] and res["stalls"] == 0, "com banda de sobra o video toca sem nenhuma travada")
        check(bool(res) and res["time_ms"] >= 0.9 * duration_ms, "a reproducao respeita o ritmo do video (%.0f ms para um video de %.0f ms)" % (res["time_ms"] if res else 0, duration_ms))
        check(bool(res) and res["startup_ms"] < 1500, "o tempo de inicio (%.0f ms) e pequeno" % (res["startup_ms"] if res else 0))
        rc, res3, _ = net.get("clip", "v3", ["-B", "3", "-W", "8", "-T", 30])
        check(rc == 0 and bool(res3) and res3["ok"] and res3["download_ms"] > 0.7 * duration_ms and res3["stalls"] == 0, "com buffer limitado a 8 chunks o download acompanha a reproducao (terminou em %.0f ms de um video de %.0f ms), em vez de baixar tudo de uma vez" % (res3["download_ms"] if res3 else 0, duration_ms))
        net.seed(path, "clip2", "slow", ["-b", "8000", "-r", "3000"])
        rc, res2, _ = net.get("clip2", "v2", ["-B", "3", "-T", 60])
        check(rc == 0 and bool(res2) and res2["ok"] and res2["stalls"] > 0 and res2["stall_ms"] > 500, "com banda menor que a taxa do video ha travadas (%d, %.1f s paradas)" % (res2["stalls"] if res2 else 0, res2["stall_ms"] / 1000 if res2 else 0))
        check(bool(res2) and res2["time_ms"] > 1.5 * duration_ms, "e o tempo total passa a ser limitado pela banda do seeder")
    finally:
        net.close()


CLI_DIR = tempfile.mkdtemp(prefix="streamp2p-cli-")


def run_cli(args, key=KEY):
    env = dict(os.environ)
    env.pop("STREAMP2P_KEY", None)
    if key:
        env["STREAMP2P_KEY"] = key
    r = subprocess.run([BIN] + args, capture_output=True, text=True, env=env, timeout=15, cwd=CLI_DIR)
    scan("cli", r.stderr)
    return r


def t_cli():
    section("linha de comando: validacao e codigos de saida")
    bad = [
        (["tracker", "-p", "abc"], "porta nao numerica"),
        (["tracker", "-w", "70000"], "porta web acima de 65535"),
        (["tracker", "-t", "10"], "tempo de expiracao abaixo do minimo"),
        (["seed", "-t", "semporta", "-f", "x"], "tracker sem porta"),
        (["seed", "-t", "127.0.0.1:1", "-l", "2"], "perda fora de 0 a 1"),
        (["seed", "-t", "127.0.0.1:1", "-R", "5"], "temporizador UDP abaixo do minimo"),
        (["get", "-t", "127.0.0.1:1", "-n", "x", "-P", "0"], "concorrencia por peer zero"),
        (["seed", "-t", "127.0.0.1:1", "-i", "id invalido"], "identificador com espaco"),
        (["seed", "-t", "127.0.0.1:1", "-f", "/nao/existe"], "arquivo inexistente"),
        (["get", "-t", "127.0.0.1:1"], "sem conteudo"),
        (["get", "-t", "127.0.0.1:1", "-n", "x", "-I", "y"], "nome e id ao mesmo tempo"),
        (["get", "-t", "127.0.0.1:1", "-I", "zz"], "id de conteudo invalido"),
        (["get", "-t", "127.0.0.1:1", "-n", "x", "-m", "quic"], "transporte desconhecido"),
        (["get", "-t", "127.0.0.1:1", "-n", "x", "-O", "aleatorio"], "ordem desconhecida"),
        (["gen", "-o", "/tmp/x"], "gen sem tamanho"),
        (["list"], "list sem tracker"),
        (["get", "-t", "127.0.0.1:1", "-n", "x", "-s", "/nao/existe/saida"], "saida de streaming em pasta inexistente"),
        (["bogus"], "comando desconhecido"),
        ([], "sem comando"),
    ]
    ok = True
    for args, _ in bad:
        r = run_cli(args)
        ok = ok and r.returncode == 1 and r.stderr.strip() != ""
    check(ok, "%d formas invalidas saem com codigo 1 e mensagem de erro" % len(bad))
    check(os.listdir(CLI_DIR) == [], "os comandos invalidos nao deixam arquivos nem pastas para tras")
    r = run_cli(["tracker"], key=None)
    check(r.returncode == 1 and "chave" in r.stderr, "sem chave compartilhada o programa se recusa a subir")
    check(run_cli(["tracker", "-h"]).returncode == 0 and "uso:" in run_cli(["-h"]).stdout, "-h imprime o uso e sai com codigo 0")
    busy = socket.socket()
    busy.bind(("0.0.0.0", 0))
    busy.listen(1)
    r = run_cli(["tracker", "-p", str(busy.getsockname()[1]), "-w", "0"])
    busy.close()
    check(r.returncode == 1 and "porta" in r.stderr, "porta ocupada: erro claro e codigo 1")


def t_shutdown():
    section("encerramento limpo")
    net = Net()
    try:
        path, _ = net.make_file("v.bin", MIB, seed=17)
        s = net.seed(path, "v", "s1")
        rc, res, _ = net.get("v", "l1", ["-N", "-T", 30])
        check(rc == 0 and res["ok"], "download de teste conclui")
        rc = s.term()
        st = s.stats()
        check(rc == 0 and bool(st) and st["uploaded_bytes"] == MIB and st["chunks_served"] == 64, "SIGTERM no seeder: saida 0 e estatisticas finais (1 MiB, 64 chunks servidos)")
        rc = net.tracker.term()
        ts = net.tracker.stats()
        check(rc == 0 and bool(ts) and ts["registrations"] >= 2 and ts["lookups"] >= 1, "SIGTERM no tracker: saida 0 e estatisticas finais")
    finally:
        net.close()


SECTIONS = [
    ("transfer", t_transfer), ("swarm", t_swarm), ("p2p", t_p2p), ("kill", t_kill_midway), ("expiry", t_expiry),
    ("restart", t_tracker_restart), ("resume", t_resume), ("sizes", t_sizes), ("conformance", t_conformance), ("list", t_list), ("stream", t_stream), ("integrity", t_integrity), ("auth", t_auth),
    ("udp", t_udp_loss), ("ipv6", t_ipv6), ("web", t_web), ("playback", t_playback), ("cli", t_cli), ("shutdown", t_shutdown),
]

if __name__ == "__main__":
    if not os.path.exists(BIN):
        print("binario nao encontrado: %s (rode make)" % BIN)
        sys.exit(2)
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
    print("\nresultado: %d passaram, %d falharam, %d pulados" % (passed, failed, skipped))
    if failed == 0:
        print("TODOS OS TESTES PASSARAM")
    sys.exit(0 if failed == 0 else 1)
