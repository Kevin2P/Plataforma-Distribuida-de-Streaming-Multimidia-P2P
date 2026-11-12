import csv
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import ROOT, Net

RESULTS = os.path.join(ROOT, "results")
MIB = 1 << 20
REPS = dict(chunk=3, delay=3, loss=3, rto=3, swarm=5, p2p=5, faults=3, prebuffer=3, ttl=3)
KEYS = dict(chunk=("chunk_size", "transport"), delay=("delay_ms", "concurrency", "transport"), loss=("loss", "transport"), rto=("rto_ms",),
            swarm=("seeders",), p2p=("mode", "leechers"), faults=("scenario",), prebuffer=("prebuffer",), ttl=("ttl_ms",))


def sort_key(name):
    def key(row):
        out = []
        for k in KEYS[name] + ("rep",):
            try:
                out.append((0, float(row[k]), ""))
            except ValueError:
                out.append((1, 0.0, row[k]))
        return out
    return key


def save(name, rows, reps):
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, name + ".csv")
    rows = [{k: str(v) for k, v in r.items()} for r in rows]
    if set(reps) != set(range(1, REPS[name] + 1)) and os.path.exists(path):
        with open(path) as f:
            rows += [r for r in csv.DictReader(f) if int(r["rep"]) not in reps]
    rows.sort(key=sort_key(name))
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("  %s: %d linhas" % (os.path.relpath(path, ROOT), len(rows)), flush=True)


def metrics(res):
    ok = bool(res and res["ok"])
    g = lambda k: round(res[k], 1) if res else 0
    return dict(ok=int(ok), time_ms=g("time_ms"), download_ms=g("download_ms"), startup_ms=g("startup_ms"), stalls=res["stalls"] if res else 0,
                stall_ms=g("stall_ms"), throughput_kbps=g("throughput_kbps"), lat_p50_ms=g("lat_p50_ms"), lat_p95_ms=g("lat_p95_ms"),
                retries=res["retries"] if res else 0, peer_failures=res["peer_failures"] if res else 0, request_retx=res["request_retx"] if res else 0)


def exp_chunk(reps):
    rows = []
    net = Net()
    try:
        path, _ = net.make_file("v.bin", 8 * MIB, 21)
        for cs in (4096, 16384, 65536, 262144):
            net.seed(path, "v%d" % cs, "s%d" % cs, ["-c", cs])
            for tr in ("tcp", "udp"):
                for rep in reps:
                    rc, res, _ = net.get("v%d" % cs, "l-%s-%d-%d" % (tr, cs, rep), ["-m", tr, "-N", "-T", 60])
                    rows.append(dict(chunk_size=cs, transport=tr, rep=rep, **metrics(res)))
    finally:
        net.close()
    return rows


def exp_delay(reps):
    rows = []
    net = Net()
    try:
        path, _ = net.make_file("v.bin", 2 * MIB, 22)
        for d in (0, 10, 25, 50, 100):
            net.seed(path, "d%d" % d, "s%d" % d, ["-D", d] if d else [])
            for conc in (2, 8):
                for tr in ("tcp", "udp"):
                    for rep in reps:
                        rc, res, _ = net.get("d%d" % d, "l-%s-%d-%d-%d" % (tr, d, conc, rep), ["-m", tr, "-N", "-w", conc, "-P", conc, "-T", 90])
                        rows.append(dict(delay_ms=d, concurrency=conc, transport=tr, rep=rep, **metrics(res)))
    finally:
        net.close()
    return rows


def exp_loss(reps):
    rows = []
    net = Net()
    try:
        path, _ = net.make_file("v.bin", MIB, 23)
        for p in (0.0, 0.02, 0.05, 0.1, 0.2, 0.3):
            for rep in reps:
                ident = "sl%d-%d" % (int(p * 100), rep)
                s = net.seed(path, "loss", ident, ["-D", 5, "-l", p, "-S", 100 * rep + int(p * 100) + 1])
                rc, res, _ = net.get("loss", "lu-%s" % ident, ["-m", "udp", "-l", p, "-R", 60, "-N", "-T", 120])
                s.term()
                st = s.stats() or {}
                rows.append(dict(loss=p, transport="udp", rep=rep, udp_fragments=st.get("udp_fragments", 0), udp_retx=st.get("udp_retx", 0),
                                 sim_drops=st.get("udp_sim_drops", 0), **metrics(res)))
        s = net.seed(path, "losstcp", "tcp-base", ["-D", 5])
        for rep in reps:
            rc, res, _ = net.get("losstcp", "lt-%d" % rep, ["-m", "tcp", "-N", "-T", 60])
            rows.append(dict(loss=0.0, transport="tcp", rep=rep, udp_fragments=0, udp_retx=0, sim_drops=0, **metrics(res)))
        s.term()
    finally:
        net.close()
    return rows


def exp_rto(reps):
    rows = []
    net = Net()
    try:
        path, _ = net.make_file("v.bin", MIB, 29)
        for rto in (10, 20, 40, 80, 160, 320):
            for rep in reps:
                ident = "sr%d-%d" % (rto, rep)
                s = net.seed(path, "rto", ident, ["-D", 5, "-l", 0.1, "-R", rto, "-S", 40 + rep])
                rc, res, _ = net.get("rto", "lr-%s" % ident, ["-m", "udp", "-l", 0.1, "-R", rto, "-N", "-T", 120])
                s.term()
                st = s.stats() or {}
                rows.append(dict(rto_ms=rto, rep=rep, udp_fragments=st.get("udp_fragments", 0), udp_retx=st.get("udp_retx", 0), **metrics(res)))
    finally:
        net.close()
    return rows


def exp_swarm(reps):
    rows = []
    for k in (1, 2, 3, 4):
        net = Net()
        try:
            path, _ = net.make_file("v.bin", 4 * MIB, 24)
            for i in range(k):
                net.seed(path, "w", "s%d" % i, ["-r", 4000])
            net.wait_holders("w", k)
            for rep in reps:
                rc, res, _ = net.get("w", "l%d" % rep, ["-N", "-T", 90])
                rows.append(dict(seeders=k, rep=rep, peers_used=len(res["bytes_by_peer"]) if res else 0, **metrics(res)))
        finally:
            net.close()
    return rows


def exp_p2p(reps):
    rows = []
    for rep in reps:
        for mode in ("noshare", "strict", "rarest", "cheap"):
            for L in (2, 4):
                net = Net()
                try:
                    path, _ = net.make_file("v.bin", 2 * MIB, 25)
                    net.seed(path, "p", "origin", ["-r", 4000])
                    extra = ["-N", "-T", 120] + (["-X"] if mode == "noshare" else ["-O", mode])
                    procs = [net.get_proc("p", "l%d" % i, extra) for i in range(L)]
                    results = []
                    for pr in procs:
                        pr.wait_exit(120)
                        results.append(pr.result())
                    oks = [r for r in results if r and r["ok"]]
                    total = sum(sum(r["bytes_by_peer"].values()) for r in oks) or 1
                    from_origin = sum(r["bytes_by_peer"].get("origin", 0) for r in oks)
                    times = [r["download_ms"] for r in oks]
                    rows.append(dict(mode=mode, leechers=L, rep=rep, all_ok=int(len(oks) == L), max_ms=round(max(times), 1) if times else 0,
                                     mean_ms=round(sum(times) / len(times), 1) if times else 0, origin_fraction=round(from_origin / total, 3)))
                finally:
                    net.close()
    return rows


def exp_faults(reps):
    rows = []
    plans = {"none": [], "kill1": [(1.5, "s0")], "kill2": [(1.5, "s0"), (3.0, "s1")], "tracker": [(1.0, "tracker")]}
    for name, plan in plans.items():
        for rep in reps:
            net = Net()
            try:
                path, _ = net.make_file("v.bin", 4 * MIB, 26)
                seeds = {"s%d" % i: net.seed(path, "f", "s%d" % i, ["-r", 3000, "-b", 5000]) for i in range(3)}
                net.wait_holders("f", 3)
                g = net.get_proc("f", "viewer", ["-B", 3, "-W", 32, "-T", 120])
                t0 = time.time()
                for at, target in plan:
                    time.sleep(max(0.0, at - (time.time() - t0)))
                    (net.tracker if target == "tracker" else seeds[target]).kill()
                g.wait_exit(120)
                rows.append(dict(scenario=name, rep=rep, **metrics(g.result())))
            finally:
                net.close()
    return rows


def exp_prebuffer(reps):
    rows = []
    net = Net()
    try:
        path, _ = net.make_file("v.bin", 2 * MIB, 27)
        for i in range(3):
            net.seed(path, "pb", "s%d" % i, ["-r", 1500, "-D", 20, "-j", 80, "-b", 4000, "-S", i + 1])
        net.wait_holders("pb", 3)
        for B in (1, 2, 4, 8, 16, 32):
            for rep in reps:
                rc, res, _ = net.get("pb", "v%d-%d" % (B, rep), ["-B", B, "-W", 64, "-T", 90])
                rows.append(dict(prebuffer=B, rep=rep, **metrics(res)))
    finally:
        net.close()
    return rows


def exp_ttl(reps):
    rows = []
    for ttl in (1000, 2000, 4000):
        net = Net(ttl=ttl)
        try:
            path, _ = net.make_file("v.bin", MIB, 28)
            for rep in reps:
                ident = "s%d" % rep
                s = net.seed(path, "t", ident)
                s.freeze()
                t0 = time.time()
                gone = net.wait_peer(ident, 30, present=False)
                dt = (time.time() - t0) * 1000
                s.kill()
                rows.append(dict(ttl_ms=ttl, rep=rep, detected=int(gone), detect_ms=round(dt, 1)))
        finally:
            net.close()
    return rows


EXPERIMENTS = dict(chunk=exp_chunk, delay=exp_delay, loss=exp_loss, rto=exp_rto, swarm=exp_swarm, p2p=exp_p2p, faults=exp_faults, prebuffer=exp_prebuffer, ttl=exp_ttl)


def parse(arg):
    name, _, span = arg.partition("@")
    if name not in EXPERIMENTS:
        sys.exit("experimento desconhecido: %s (use %s)" % (name, " ".join(EXPERIMENTS)))
    if not span:
        return name, list(range(1, REPS[name] + 1))
    first, _, last = span.partition("-")
    return name, list(range(int(first), int(last or first) + 1))


if __name__ == "__main__":
    for name, reps in [parse(a) for a in (sys.argv[1:] or list(EXPERIMENTS))]:
        start = time.time()
        print("experimento %s, repeticoes %s" % (name, ",".join(str(r) for r in reps)), flush=True)
        save(name, EXPERIMENTS[name](reps), reps)
        print("  (%.0f s)" % (time.time() - start), flush=True)
