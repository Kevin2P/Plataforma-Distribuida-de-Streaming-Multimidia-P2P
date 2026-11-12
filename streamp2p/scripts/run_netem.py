import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Net
from run_experiments import MIB, metrics

KERNEL = {"Tcp.OutSegs": "k_out_segs", "Tcp.RetransSegs": "k_retrans_segs", "TcpExt.TCPTimeouts": "k_timeouts",
          "TcpExt.TCPLossProbes": "k_loss_probes", "TcpExt.TCPFastRetrans": "k_fast_retrans"}


def kernel_counters():
    vals = {}
    for path in ("/proc/net/snmp", "/proc/net/netstat"):
        with open(path) as f:
            lines = f.read().splitlines()
        for head, body in zip(lines[::2], lines[1::2]):
            prefix = head.split(":")[0]
            for name, v in zip(head.split()[1:], body.split()[1:]):
                vals[prefix + "." + name] = int(v)
    return vals


def main():
    loss = float(sys.argv[1])
    out = sys.argv[2]
    reps = int(sys.argv[3]) if len(sys.argv) > 3 else 2
    rows = []
    net = Net(ttl=60000)
    try:
        path, _ = net.make_file("v.bin", MIB, 23)
        for tr in ("tcp", "udp"):
            for rep in range(1, reps + 1):
                ident = "n%s%d-%d" % (tr, int(loss), rep)
                seed = net.seed(path, "c-" + ident, "s" + ident, ["-D", 5])
                before = kernel_counters()
                extra = ["-m", tr, "-N", "-T", 300] + (["-R", 60] if tr == "udp" else [])
                rc, res, _ = net.get("c-" + ident, "l" + ident, extra, timeout=320)
                after = kernel_counters()
                seed.term()
                st = seed.stats() or {}
                row = dict(loss=loss / 100, transport=tr, rep=rep, udp_fragments=st.get("udp_fragments", 0), udp_retx=st.get("udp_retx", 0), **metrics(res))
                row.update({col: after[k] - before[k] for k, col in KERNEL.items()})
                rows.append(row)
                print("  perda %g%% %s rep %d: ok=%d tempo=%.0f ms" % (loss, tr, rep, row["ok"], row["time_ms"]), flush=True)
    finally:
        net.close()
    new = not os.path.exists(out)
    with open(out, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        if new:
            w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
