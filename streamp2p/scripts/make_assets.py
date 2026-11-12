import csv
import json
import math
import os
import statistics as st

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")
OUT = os.path.join(ROOT, "report", "generated")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"font.size": 9, "axes.grid": True, "grid.alpha": 0.3, "axes.axisbelow": True})
C = {"tcp": "tab:blue", "udp": "tab:orange", "model": "black", "a": "tab:green", "b": "tab:red"}
NUM = {}


def load(name):
    with open(os.path.join(RES, name + ".csv")) as f:
        return list(csv.DictReader(f))


def col(rows, key, **flt):
    return [float(r[key]) for r in rows if all(r[k] == str(v) for k, v in flt.items())]


def ms(rows, key, **flt):
    v = col(rows, key, **flt)
    return (st.mean(v), st.stdev(v) if len(v) > 1 else 0.0)


def n(x, d=1):
    return ("%.*f" % (d, x)).replace(".", ",")


def pm(pair, d=1):
    return "%s $\\pm$ %s" % (n(pair[0], d), n(pair[1], d))


def short(x):
    return n(x, 1) if x < 5 and abs(x - round(x)) > 0.04 else n(x, 0)


def clipped(pairs):
    return [[min(v[0], v[1]) for v in pairs], [v[1] for v in pairs]]


def put(key, text):
    NUM[key] = text


def save_fig(fig, name):
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, name + ".pdf"))
    fig.savefig(os.path.join(OUT, name + ".png"), dpi=200)
    plt.close(fig)


def table(name, header, rows, spec, top=()):
    lines = ["\\begin{tabular}{%s}" % spec, "\\toprule"] + list(top) + [" & ".join(header) + " \\\\", "\\midrule"]
    lines += [" & ".join(r) + " \\\\" for r in rows]
    lines += ["\\bottomrule", "\\end{tabular}"]
    with open(os.path.join(OUT, name + ".tex"), "w") as f:
        f.write("\n".join(lines) + "\n")


def chunk():
    d = load("chunk")
    sizes = sorted({int(r["chunk_size"]) for r in d})
    fig, ax = plt.subplots(1, 2, figsize=(6.6, 2.6))
    rows = []
    for tr in ("tcp", "udp"):
        y = [ms(d, "throughput_kbps", chunk_size=s, transport=tr) for s in sizes]
        ax[0].errorbar([s / 1024 for s in sizes], [v[0] / 1000 for v in y], yerr=[v[1] / 1000 for v in y], marker="o", capsize=3, color=C[tr], label=tr.upper())
        p95 = [ms(d, "lat_p95_ms", chunk_size=s, transport=tr) for s in sizes]
        ax[1].errorbar([s / 1024 for s in sizes], [v[0] for v in p95], yerr=[v[1] for v in p95], marker="o", capsize=3, color=C[tr], label=tr.upper())
    for a, yl in zip(ax, ("vazão (Mbit/s)", "latência p95 por chunk (ms)")):
        a.set_xscale("log", base=2)
        a.set_xticks([s / 1024 for s in sizes])
        a.set_xticklabels([str(int(s / 1024)) for s in sizes])
        a.set_xlabel("tamanho do chunk (KiB)")
        a.set_ylabel(yl)
    ax[0].legend(loc="lower right")
    ax[1].legend(loc="upper left")
    save_fig(fig, "chunk")
    ratios = []
    for s in sizes:
        t = {tr: ms(d, "throughput_kbps", chunk_size=s, transport=tr) for tr in ("tcp", "udp")}
        ratios.append(t["tcp"][0] / t["udp"][0])
        rows.append([str(s // 1024)] + [pm((t[tr][0] / 1000, t[tr][1] / 1000), 0) for tr in ("tcp", "udp")]
                    + [n(ms(d, "lat_p50_ms", chunk_size=s, transport=tr)[0], 1) for tr in ("tcp", "udp")] + [n(ms(d, "lat_p95_ms", chunk_size=s, transport=tr)[0], 1) for tr in ("tcp", "udp")])
    table("chunk", ["Chunk (KiB)", "TCP (Mbit/s)", "UDP (Mbit/s)", "TCP p50 (ms)", "UDP p50 (ms)", "TCP p95 (ms)", "UDP p95 (ms)"], rows, "rrrrrrr")
    put("chunk.ratio.min16", n(min(ratios[1:]), 1))
    put("chunk.ratio.max16", n(max(ratios[1:]), 1))
    for tr in ("tcp", "udp"):
        put("chunk.%s.k4" % tr, pm((ms(d, "throughput_kbps", chunk_size=sizes[0], transport=tr)[0] / 1000, ms(d, "throughput_kbps", chunk_size=sizes[0], transport=tr)[1] / 1000), 0))
    put("chunk.tcp.p95.k4", n(ms(d, "lat_p95_ms", chunk_size=sizes[0], transport="tcp")[0], 1))
    put("chunk.tcp.p95.k256", n(ms(d, "lat_p95_ms", chunk_size=sizes[-1], transport="tcp")[0], 1))
    put("chunk.tcp.mbps.k4", n(ms(d, "throughput_kbps", chunk_size=sizes[0], transport="tcp")[0] / 1000, 0))
    put("chunk.tcp.mbps.best", n(max(ms(d, "throughput_kbps", chunk_size=s, transport="tcp")[0] for s in sizes) / 1000, 0))


def delay():
    d = load("delay")
    delays = sorted({int(r["delay_ms"]) for r in d})
    N = 128
    fig, ax = plt.subplots(1, 2, figsize=(6.6, 2.6), sharey=True)
    rows = []
    for a, conc in zip(ax, (2, 8)):
        for tr, mk, ls in (("tcp", "o", "-"), ("udp", "s", "--")):
            y = [ms(d, "download_ms", delay_ms=x, concurrency=conc, transport=tr) for x in delays]
            a.errorbar(delays, [v[0] for v in y], yerr=[v[1] for v in y], marker=mk, ls=ls, capsize=3, color=C[tr], label=tr.upper())
        base = ms(d, "download_ms", delay_ms=0, concurrency=conc, transport="tcp")[0]
        a.plot(delays, [base + N * x / conc for x in delays], ":", color=C["model"], label="modelo $t_0+N\\cdot D/c$")
        a.set_title("concorrência c = %d" % conc, fontsize=9)
        a.set_xlabel("atraso emulado D (ms)")
    ax[0].set_ylabel("tempo de download (ms)")
    ax[0].legend()
    save_fig(fig, "delay")
    worst = 0.0
    for x in delays:
        r = [str(x)]
        for conc in (2, 8):
            base = ms(d, "download_ms", delay_ms=0, concurrency=conc, transport="tcp")[0]
            model = base + N * x / conc
            for tr in ("tcp", "udp"):
                v = ms(d, "download_ms", delay_ms=x, concurrency=conc, transport=tr)[0]
                r.append(n(v, 0))
                put("delay.%s.c%d.d%d" % (tr, conc, x), n(v, 0))
                if x >= 25:
                    worst = max(worst, abs(v - model) / model * 100)
            r.append(n(model, 0))
            put("delay.model.c%d.d%d" % (conc, x), n(model, 0))
        rows.append(r)
    table("delay", ["D (ms)", "TCP", "UDP", "modelo", "TCP", "UDP", "modelo"], rows, "rrrrrrr")
    put("delay.model.err", n(math.ceil(worst), 0))
    put("delay.speedup", n(ms(d, "download_ms", delay_ms=100, concurrency=2, transport="tcp")[0] / ms(d, "download_ms", delay_ms=100, concurrency=8, transport="tcp")[0], 1))


def loss():
    emu = [r for r in load("loss") if r["transport"] == "udp"]
    k = load("loss_netem")
    ku = [r for r in k if r["transport"] == "udp"]
    ps = sorted({float(r["loss"]) for r in k})
    tcp_base = ms(k, "throughput_kbps", loss=0.0, transport="tcp")[0] / 1000
    mss, rtt = 1460 * 8, 0.006

    def mathis(p):
        return min(tcp_base, mss / rtt * math.sqrt(1.5) / math.sqrt(p) / 1e6) if p > 0 else tcp_base

    def retx(rows, p):
        return st.mean(r / (f - r) for f, r in zip(col(rows, "udp_fragments", loss=p), col(rows, "udp_retx", loss=p)))

    x = [p * 100 for p in ps]
    fig, ax = plt.subplots(1, 2, figsize=(6.6, 2.6))
    for tr, mk, lab in (("tcp", "o", "TCP medido"), ("udp", "s", "UDP medido")):
        y = [ms(k, "throughput_kbps", loss=p, transport=tr) for p in ps]
        ax[0].errorbar(x, [v[0] / 1000 for v in y], yerr=[v[1] / 1000 for v in y], marker=mk, capsize=3, color=C[tr], label=lab)
    ax[0].plot(x, [mathis(p) for p in ps], "--", color=C["tcp"], lw=0.9, label="TCP: modelo de Mathis")
    ax[0].set_yscale("log")
    ax[0].set_xlabel("perda de pacotes (%)")
    ax[0].set_ylabel("vazão (Mbit/s)")
    ax[0].legend(fontsize=7, loc="lower left")
    ax[1].plot(x, [retx(emu, p) for p in ps], "^--", color=C["udp"], alpha=0.6, label="UDP, emulador")
    ax[1].plot(x, [retx(ku, p) for p in ps], "s-", color=C["udp"], label="UDP, netem")
    ax[1].plot(x, [p / (1 - p) for p in ps], ":", color=C["model"], label="modelo $p/(1-p)$")
    ax[1].set_xlabel("perda de pacotes (%)")
    ax[1].set_ylabel("retransmissões por fragmento")
    ax[1].legend(fontsize=7)
    save_fig(fig, "loss")
    rows = []
    for p in ps:
        key = "p%d" % round(p * 100)
        t, u = ms(k, "download_ms", loss=p, transport="tcp"), ms(k, "download_ms", loss=p, transport="udp")
        mbps = ms(k, "throughput_kbps", loss=p, transport="tcp")[0] / 1000
        p95 = {tr: ms(k, "lat_p95_ms", loss=p, transport=tr)[0] for tr in ("tcp", "udp")}
        retries = ms(k, "retries", loss=p, transport="tcp")[0]
        rows.append([n(p * 100, 0), pm(t, 0), pm(u, 0), n(t[0] / u[0], 2), n(mbps, 2), n(mathis(p), 1), n(p95["tcp"], 0), n(p95["udp"], 0), n(retries, 1)])
        put("netem.tcp.time." + key, n(t[0], 0))
        put("netem.udp.time." + key, n(u[0], 0))
        put("netem.tcp.time.%s.s" % key, n(t[0] / 1000, 1))
        put("netem.udp.time.%s.s" % key, n(u[0] / 1000, 1))
        put("netem.tcp_over_udp." + key, short(t[0] / u[0]))
        put("netem.udp_over_tcp." + key, short(u[0] / t[0]))
        put("netem.tcp.mbps." + key, n(mbps, 1))
        put("netem.mathis." + key, n(mathis(p), 1))
        put("netem.mathis.over." + key, n(mathis(p) / mbps, 0))
        for tr in ("tcp", "udp"):
            put("netem.%s.p95.%s" % (tr, key), n(p95[tr], 0))
            put("netem.%s.p95.%s.s" % (tr, key), n(p95[tr] / 1000, 1))
        put("netem.tcp.retries." + key, short(retries))
        put("netem.udp.retx." + key, n(retx(ku, p), 2))
        put("loss.retx." + key, n(retx(emu, p), 2))
        put("loss.model." + key, n(p / (1 - p), 2))
        put("loss.time." + key, n(ms(emu, "download_ms", loss=p)[0], 0))
    top = ["Perda & \\multicolumn{3}{c}{Tempo (ms)} & \\multicolumn{2}{c}{Vazão TCP (Mbit/s)} & \\multicolumn{2}{c}{p95 por chunk (ms)} & Retentativas \\\\",
           "\\cmidrule(lr){2-4}\\cmidrule(lr){5-6}\\cmidrule(lr){7-8}"]
    table("loss", ["(\\%)", "TCP", "UDP", "TCP/UDP", "medida", "Mathis", "TCP", "UDP", "do TCP"], rows, "rrrrrrrrr", top)
    rows = [[n(p * 100, 0), pm(ms(emu, "download_ms", loss=p), 0), pm(ms(ku, "download_ms", loss=p), 0), n(retx(emu, p), 2), n(retx(ku, p), 2), n(p / (1 - p), 2)] for p in ps]
    top = ["Perda & \\multicolumn{2}{c}{Tempo UDP (ms)} & \\multicolumn{3}{c}{Retransmissões por fragmento} \\\\", "\\cmidrule(lr){2-3}\\cmidrule(lr){4-6}"]
    table("loss_udp", ["(\\%)", "emulador", "netem", "emulador", "netem", "modelo $p/(1-p)$"], rows, "rrrrrr", top)
    put("netem.reps", str(len(col(k, "download_ms", loss=0.0, transport="tcp"))))
    put("loss.reps", str(len(col(emu, "download_ms", loss=0.0))))
    diff = max(abs(ms(ku, "download_ms", loss=p)[0] / ms(emu, "download_ms", loss=p)[0] - 1) for p in ps if p <= 0.2)
    put("netem.emu.maxdiff", n(math.ceil(diff * 100), 0))
    worst = sorted(col(ku, "download_ms", loss=0.3))
    put("netem.udp.p30.min.s", n(worst[0] / 1000, 1))
    put("netem.udp.p30.max.s", n(worst[-1] / 1000, 1))


def rto():
    d = load("rto")
    rs = sorted({int(r["rto_ms"]) for r in d})
    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    y = [ms(d, "download_ms", rto_ms=x) for x in rs]
    ax.errorbar(rs, [v[0] for v in y], yerr=[v[1] for v in y], marker="s", capsize=3, color=C["udp"])
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(rs)
    ax.set_xticklabels([str(x) for x in rs])
    ax.set_xlabel("temporizador de retransmissão (ms)")
    ax.set_ylabel("tempo de download (ms)")
    save_fig(fig, "rto")
    rows = []
    for x in rs:
        fr = col(d, "udp_fragments", rto_ms=x)
        rt = col(d, "udp_retx", rto_ms=x)
        retx = st.mean(r / (f - r) for f, r in zip(fr, rt))
        rows.append([str(x), pm(ms(d, "download_ms", rto_ms=x), 0), n(ms(d, "throughput_kbps", rto_ms=x)[0] / 1000, 1), n(retx, 2)])
        put("rto.time.r%d" % x, n(ms(d, "download_ms", rto_ms=x)[0], 0))
        put("rto.retx.r%d" % x, n(retx, 2))
        put("rto.mbps.r%d" % x, n(ms(d, "throughput_kbps", rto_ms=x)[0] / 1000, 1))
    table("rto", ["Temporizador (ms)", "Tempo (ms)", "Vazão (Mbit/s)", "Retx/fragmento"], rows, "rrrr")
    put("rto.ratio", n(ms(d, "download_ms", rto_ms=rs[-1])[0] / ms(d, "download_ms", rto_ms=rs[0])[0], 0))
    tcp10 = ms(load("loss_netem"), "download_ms", loss=0.1, transport="tcp")[0]
    put("rto.tcp.over.r10", n(tcp10 / ms(d, "download_ms", rto_ms=10)[0], 1))
    put("rto.time.r320.s", n(ms(d, "download_ms", rto_ms=320)[0] / 1000, 1))
    put("rto.time.r10.s", n(ms(d, "download_ms", rto_ms=10)[0] / 1000, 2))


def swarm():
    s = load("swarm")
    p = load("p2p")
    ks = sorted({int(r["seeders"]) for r in s})
    ideal1 = 4 * 1024 * 1024 * 8 / 4000
    single = 2 * 1024 * 1024 * 8 / 4000
    fig, ax = plt.subplots(1, 2, figsize=(6.6, 2.7), gridspec_kw={"width_ratios": [1, 1.25]})
    y = [ms(s, "download_ms", seeders=k) for k in ks]
    ax[0].errorbar(ks, [v[0] / 1000 for v in y], yerr=[v[1] / 1000 for v in y], marker="o", capsize=3, color=C["tcp"], label="medido")
    ax[0].plot(ks, [ideal1 / k / 1000 for k in ks], ":", color=C["model"], label="ideal $T_1/k$")
    ax[0].set_xticks(ks)
    ax[0].set_xlabel("seeders (4 Mbit/s cada)")
    ax[0].set_ylabel("tempo de download (s)")
    ax[0].legend()
    modes = [("noshare", "cliente-servidor", "tab:gray"), ("strict", "P2P, ordem estrita", C["b"]), ("rarest", "P2P, mais raro", C["udp"]), ("cheap", "P2P, mais cópias", C["a"])]
    stats = {}
    for m, _, _ in modes:
        for L in (2, 4):
            stats[(m, L)] = (ms(p, "max_ms", mode=m, leechers=L), ms(p, "origin_fraction", mode=m, leechers=L), len(col(p, "max_ms", mode=m, leechers=L)))
    for j, (m, lab, colr) in enumerate(modes):
        xs = [i + (j - 1.5) * 0.2 for i in range(2)]
        ys = [stats[(m, L)][0][0] / 1000 for L in (2, 4)]
        es = [stats[(m, L)][0][1] / 1000 for L in (2, 4)]
        bars = ax[1].bar(xs, ys, yerr=es, capsize=2, width=0.19, color=colr, label=lab)
        for b, L, e in zip(bars, (2, 4), es):
            ax[1].text(b.get_x() + b.get_width() / 2, b.get_height() + e + 0.25, "%d%%" % round(stats[(m, L)][1][0] * 100), ha="center", fontsize=6)
    ax[1].set_xticks([0, 1])
    ax[1].set_xticklabels(["2 leechers", "4 leechers"])
    ax[1].set_ylabel("tempo do último leecher (s)")
    ax[1].set_ylim(0, max(float(r["max_ms"]) for r in p) / 1000 * 1.15)
    ax[1].legend(fontsize=6.5, loc="upper left")
    save_fig(fig, "swarm")
    rows = []
    for k in ks:
        t = ms(s, "download_ms", seeders=k)
        rows.append([str(k), pm(t, 0), n(ideal1 / k, 0), n(ms(s, "throughput_kbps", seeders=k)[0] / 1000, 1), n(ideal1 / k / t[0] * 100, 0) + "\\%"])
        put("swarm.time.k%d" % k, n(t[0], 0))
        put("swarm.eff.k%d" % k, n(ideal1 / k / t[0] * 100, 0))
    table("swarm", ["Seeders", "Tempo (ms)", "Ideal (ms)", "Vazão (Mbit/s)", "Eficiência"], rows, "rrrrr")
    put("swarm.ideal.k4", n(ideal1 / 4, 0))
    put("swarm.reps", str(len(col(s, "download_ms", seeders=1))))
    rows = []
    for m, lab, _ in modes:
        for L in (2, 4):
            t, o, reps = stats[(m, L)]
            base = stats[("noshare", L)][0][0]
            rows.append([lab, str(L), pm(t, 0), n(base / t[0], 2), pm((o[0] * 100, o[1] * 100), 0) + "\\%"])
            put("p2p.%s.l%d.s" % (m, L), n(t[0] / 1000, 1))
            put("p2p.%s.l%d.sd" % (m, L), n(t[1] / 1000, 2))
            put("p2p.%s.l%d.origin" % (m, L), n(o[0] * 100, 0))
            put("p2p.%s.l%d.gain" % (m, L), n(base / t[0], 2))
            put("p2p.%s.l%d.min" % (m, L), n(min(col(p, "max_ms", mode=m, leechers=L)) / 1000, 1))
            put("p2p.%s.l%d.max" % (m, L), n(max(col(p, "max_ms", mode=m, leechers=L)) / 1000, 1))
    table("p2p", ["Modo", "Leechers", "Tempo (ms)", "Ganho", "Bytes da origem"], rows, "lrrrr")
    put("p2p.reps", str(stats[("cheap", 2)][2]))
    for L in (2, 4):
        c = {r["rep"]: float(r["max_ms"]) for r in p if r["mode"] == "cheap" and int(r["leechers"]) == L}
        r_ = {r["rep"]: float(r["max_ms"]) for r in p if r["mode"] == "rarest" and int(r["leechers"]) == L}
        put("p2p.cheap.wins.l%d" % L, str(sum(1 for k in c if c[k] < r_[k])))
    put("p2p.single.s", n(single / 1000, 1))


def faults():
    d = load("faults")
    sc = [("none", "sem falha"), ("kill1", "1 seeder\nmorre"), ("kill2", "2 seeders\nmorrem"), ("tracker", "tracker\nmorre")]
    video = 4 * 1024 * 1024 * 8 / 5000
    fig, ax = plt.subplots(1, 2, figsize=(6.6, 2.6))
    ys = [ms(d, "stall_ms", scenario=k) for k, _ in sc]
    nst = [ms(d, "stalls", scenario=k)[0] for k, _ in sc]
    bars = ax[0].bar(range(4), [v[0] for v in ys], yerr=[v[1] for v in ys], capsize=3, color=[C["a"], C["tcp"], C["b"], C["udp"]])
    top = max(v[0] + v[1] for v in ys)
    for b, k, v in zip(bars, nst, ys):
        ax[0].text(b.get_x() + b.get_width() / 2, v[0] + v[1] + top * 0.03, "%s %s" % (n(k, 0 if k == int(k) else 1), "parada" if k < 2 else "paradas"), ha="center", fontsize=7)
    ax[0].set_ylabel("tempo parado (ms)")
    ax[0].set_ylim(0, top * 1.25)
    tm = [ms(d, "time_ms", scenario=k) for k, _ in sc]
    ax[1].bar(range(4), [v[0] / 1000 for v in tm], yerr=[v[1] / 1000 for v in tm], capsize=3, color=[C["a"], C["tcp"], C["b"], C["udp"]])
    ax[1].axhline(video / 1000, color=C["model"], ls=":", label="duração do vídeo")
    ax[1].set_ylabel("tempo total de reprodução (s)")
    ax[1].legend(fontsize=7)
    for a in ax:
        a.set_xticks(range(4))
        a.set_xticklabels([l for _, l in sc], fontsize=7)
    save_fig(fig, "faults")
    rows = []
    for k, lab in sc:
        rows.append([lab.replace("\n", " "), pm(ms(d, "time_ms", scenario=k), 0), n(ms(d, "stalls", scenario=k)[0], 1), n(ms(d, "stall_ms", scenario=k)[0], 0), n(ms(d, "retries", scenario=k)[0], 1)])
        put("faults.%s.stalls" % k, n(ms(d, "stalls", scenario=k)[0], 1))
        put("faults.%s.stallms" % k, n(ms(d, "stall_ms", scenario=k)[0], 0))
        put("faults.%s.retries" % k, n(ms(d, "retries", scenario=k)[0], 1))
        put("faults.%s.time" % k, n(ms(d, "time_ms", scenario=k)[0], 0))
        put("faults.%s.late.s" % k, n((ms(d, "time_ms", scenario=k)[0] - video) / 1000, 1))
    table("faults", ["Cenário", "Tempo (ms)", "Paradas", "Parado (ms)", "Retentativas"], rows, "lrrrr")
    put("faults.kill2.stall.s", n(ms(d, "stall_ms", scenario="kill2")[0] / 1000, 1))
    put("faults.video.ms", n(video, 0))


def prebuffer():
    d = load("prebuffer")
    bs = sorted({int(r["prebuffer"]) for r in d})
    fig, ax = plt.subplots(1, 2, figsize=(6.6, 2.6))
    su = [ms(d, "startup_ms", prebuffer=b) for b in bs]
    sm = [ms(d, "stall_ms", prebuffer=b) for b in bs]
    ax[0].errorbar(bs, [v[0] for v in su], yerr=clipped(su), marker="o", capsize=3, color=C["tcp"], label="tempo até iniciar")
    ax[0].errorbar(bs, [v[0] for v in sm], yerr=clipped(sm), marker="s", capsize=3, color=C["b"], label="tempo parado")
    ax[0].set_xscale("log", base=2)
    ax[0].set_xticks(bs)
    ax[0].set_xticklabels([str(b) for b in bs])
    ax[0].set_xlabel("pré-buffer (chunks)")
    ax[0].set_ylabel("ms")
    ax[0].legend(fontsize=7, loc="upper center")
    ns = [ms(d, "stalls", prebuffer=b) for b in bs]
    ax[1].bar(range(len(bs)), [v[0] for v in ns], yerr=clipped(ns), capsize=3, color=C["udp"])
    ax[1].set_xticks(range(len(bs)))
    ax[1].set_xticklabels([str(b) for b in bs])
    ax[1].set_xlabel("pré-buffer (chunks)")
    ax[1].set_ylabel("número de paradas")
    save_fig(fig, "prebuffer")
    rows = []
    for b in bs:
        rows.append([str(b), n(ms(d, "startup_ms", prebuffer=b)[0], 0), n(ms(d, "stalls", prebuffer=b)[0], 1), n(ms(d, "stall_ms", prebuffer=b)[0], 0), n(ms(d, "time_ms", prebuffer=b)[0], 0)])
        put("prebuffer.b%d.startup" % b, n(ms(d, "startup_ms", prebuffer=b)[0], 0))
        put("prebuffer.b%d.startup.s" % b, n(ms(d, "startup_ms", prebuffer=b)[0] / 1000, 1))
        put("prebuffer.b%d.stalls" % b, n(ms(d, "stalls", prebuffer=b)[0], 1))
        put("prebuffer.b%d.stallms" % b, n(ms(d, "stall_ms", prebuffer=b)[0], 0))
    table("prebuffer", ["Pré-buffer", "Início (ms)", "Paradas", "Parado (ms)", "Total (ms)"], rows, "rrrrr")


def ttl():
    d = load("ttl")
    ts = sorted({int(r["ttl_ms"]) for r in d})
    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    for t in ts:
        v = col(d, "detect_ms", ttl_ms=t)
        ax.plot([t] * len(v), v, "o", color=C["tcp"])
    ax.plot([0, 4500], [0, 4500], ":", color=C["model"], label="detecção = TTL")
    ax.set_xlabel("TTL do tracker (ms)")
    ax.set_ylabel("tempo até remover o peer (ms)")
    ax.legend()
    save_fig(fig, "ttl")
    rows = []
    excess = []
    for t in ts:
        v = col(d, "detect_ms", ttl_ms=t)
        rows.append([str(t), n(st.mean(v), 0), n(min(v), 0), n(max(v), 0)])
        put("ttl.mean.t%d" % t, n(st.mean(v), 0))
        excess.append(st.mean(v) - t)
    table("ttl", ["TTL (ms)", "Média (ms)", "Mínimo (ms)", "Máximo (ms)"], rows, "rrrr")
    put("ttl.excess", n(st.mean(excess), 0))
    put("ttl.excess.min", n(min(min(col(d, "detect_ms", ttl_ms=t)) - t for t in ts), 0))
    put("ttl.excess.max", n(max(max(col(d, "detect_ms", ttl_ms=t)) - t for t in ts), 0))


def numbers():
    with open(os.path.join(OUT, "numbers.tex"), "w") as f:
        for key in sorted(NUM):
            f.write("\\expandafter\\def\\csname num@%s\\endcsname{%s}\n" % (key, NUM[key]))
    with open(os.path.join(OUT, "numbers.json"), "w") as f:
        json.dump(NUM, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    chunk()
    delay()
    loss()
    rto()
    swarm()
    faults()
    prebuffer()
    ttl()
    numbers()
    print("figuras, tabelas e %d numeros gerados em %s" % (len(NUM), os.path.relpath(OUT, ROOT)))
