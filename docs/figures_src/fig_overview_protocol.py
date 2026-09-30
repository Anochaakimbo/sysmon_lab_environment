"""Figure 1 (research overview) and Figure 2 (dataset + evaluation protocol) for the revised paper."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

INK = "#1f2933"
MUTED = "#52606d"
FILL = ["#e8f1fb", "#eaf6ee", "#fdf3e3", "#f3eefb"]
EDGE = ["#2f6db3", "#2e8b57", "#c07a12", "#6b4fb3"]


def box(ax, x, y, w, h, fill, edge, ls="-", lw=1.4, r=0.012):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=%s" % r,
                                fc=fill, ec=edge, lw=lw, ls=ls))


def arrow(ax, x0, y0, x1, y1, color=INK, ls="-"):
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle="-|>", mutation_scale=14,
                                 color=color, lw=1.4, ls=ls))


def column(ax, x, w, title, items, i, top=0.86, bottom=0.26):
    box(ax, x, bottom, w, top - bottom, FILL[i], EDGE[i])
    ax.text(x + w / 2, top - 0.045, title, ha="center", va="center", fontsize=10.5,
            fontweight="bold", color=EDGE[i])
    n = len(items)
    step = (top - bottom - 0.10) / n
    for k, (head, sub) in enumerate(items):
        yc = top - 0.10 - step * (k + 0.5)
        box(ax, x + 0.012, yc - step / 2 + 0.008, w - 0.024, step - 0.016, "white", EDGE[i], lw=0.9, r=0.008)
        ax.text(x + w / 2, yc + 0.018, head, ha="center", va="center", fontsize=8.8,
                fontweight="bold", color=INK)
        ax.text(x + w / 2, yc - 0.022, sub, ha="center", va="center", fontsize=7.4,
                color=MUTED, linespacing=1.15)


def fig1(path):
    fig, ax = plt.subplots(figsize=(12, 4.9), dpi=200)
    ax.set_xlim(0, 1); ax.set_ylim(0.02, 0.88); ax.axis("off")
    w, gap, x0 = 0.225, 0.028, 0.012
    cols = [
        ("1  Data collection", [
            ("Isolated VMs (Vagrant)", "Ubuntu 22.04 + Sysmon for Linux;\nWindows 10 + Sysmon"),
            ("Scenario runs", "benign + 5 simulated ATT&CK\nscenarios (Atomic Red Team)"),
            ("Run isolation", "snapshot revert before each run;\none run = one run_id"),
        ]),
        ("2  Dataset construction", [
            ("Parse + enrich", "Sysmon records to event table;\nadd parent and command line"),
            ("Lineage labelling", "seed + descendants = 1;\nall other processes = 0"),
            ("Process aggregation", "key = platform + run_id + GUID;\n32 behavioural features"),
        ]),
        ("3  Evaluation", [
            ("Models", "4 supervised classifiers\n3 benign-only anomaly detectors"),
            ("Grouped protocols", "P1 lineage-grouped CV (5x5)\nP2 leave-one-run-out"),
            ("Generalisation tests", "P3 leave-one-scenario-out\nP4 independent later runs"),
        ]),
        ("4  Reported outputs", [
            ("Metrics", "Acc, Prec, Recall, F1, FPR,\nROC-AUC as mean \u00b1 SD"),
            ("Released artefacts", "dataset schema, preprocessing\nand training code, configs"),
            ("Scope", "simulated attack-activity\nclassification (offline)"),
        ]),
    ]
    xs = []
    for i, (t, items) in enumerate(cols):
        x = x0 + i * (w + gap)
        xs.append(x)
        column(ax, x, w, t, items, i)
    for i in range(3):
        arrow(ax, xs[i] + w + 0.003, 0.56, xs[i + 1] - 0.003, 0.56)
    # optional / future component
    bx, by, bw, bh = xs[1], 0.035, xs[3] + w - xs[1], 0.15
    box(ax, bx, by, bw, bh, "#f5f7fa", "#7b8794", ls=(0, (5, 3)), lw=1.2)
    ax.text(bx + bw / 2, by + bh * 0.66, "Optional / future component (not evaluated in this paper)",
            ha="center", va="center", fontsize=9.6, fontweight="bold", color=MUTED)
    ax.text(bx + bw / 2, by + bh * 0.30,
            "Web dashboard: queue scenario runs, import a Sysmon CSV and score it with a saved model",
            ha="center", va="center", fontsize=8.6, color=MUTED)
    arrow(ax, xs[2] + w / 2, 0.255, xs[2] + w / 2, by + bh + 0.005, color="#7b8794", ls=(0, (4, 3)))
    fig.savefig(path, bbox_inches="tight", facecolor="white")


def fig2(path, n):
    fig, ax = plt.subplots(figsize=(10, 6.8), dpi=200)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    steps = [
        ("Sysmon events", "%s events from 12 runs (Linux 6, Windows 6)" % n["events"]),
        ("Lineage labelling", "label = 1 for seed processes and their descendants in attack runs"),
        ("Composite-key aggregation", "key = (platform, run_id, ProcessGuid); %s events with null/zero GUID removed" % n["dropped"]),
        ("Process samples", "%s processes (%s label 1, %s label 0) in %s lineage groups" % (n["proc"], n["mal"], n["ben"], n["lin"])),
    ]
    y = 0.95
    h = 0.095
    for i, (a, b) in enumerate(steps):
        box(ax, 0.18, y - h, 0.64, h, FILL[0], EDGE[0])
        ax.text(0.5, y - h * 0.34, a, ha="center", va="center", fontsize=10.5, fontweight="bold", color=INK)
        ax.text(0.5, y - h * 0.72, b, ha="center", va="center", fontsize=8.6, color=MUTED)
        if i < len(steps) - 1:
            arrow(ax, 0.5, y - h, 0.5, y - h - 0.04)
        y -= h + 0.04
    # protocols
    prot = [
        ("P1 Lineage-\ngrouped CV", "stratified 5-fold x 5 repeats;\na lineage tree never spans\ntrain and test"),
        ("P2 Leave-one-\nrun-out", "hold out 1 attack run (10 folds);\ntest = its attack + its own\nbackground benign processes"),
        ("P3 Leave-one-\nscenario-out", "hold out 1 scenario on\nboth OSes (5 folds)"),
        ("P4 Independent\nruns", "train on the 12 runs;\ntest on 2 Linux runs\ncollected on a later day"),
    ]
    top = y - 0.01
    arrow(ax, 0.5, top + 0.04, 0.5, top)
    pw, pg = 0.232, 0.013
    for i, (a, b) in enumerate(prot):
        x = 0.005 + i * (pw + pg)
        box(ax, x, top - 0.185, pw, 0.185, FILL[2], EDGE[2])
        ax.text(x + pw / 2, top - 0.05, a, ha="center", va="center", fontsize=9.0, fontweight="bold", color=INK)
        ax.text(x + pw / 2, top - 0.128, b, ha="center", va="center", fontsize=7.6, color=MUTED, linespacing=1.2)
    y2 = top - 0.185 - 0.045
    arrow(ax, 0.5, y2 + 0.045, 0.5, y2)
    box(ax, 0.06, y2 - 0.16, 0.88, 0.16, FILL[1], EDGE[1])
    ax.text(0.5, y2 - 0.035, "Inside every fold (training data only)", ha="center", va="center",
            fontsize=10, fontweight="bold", color=INK)
    ax.text(0.5, y2 - 0.1,
            "StandardScaler fit on the training part  |  supervised models: both classes\n"
            "anomaly detectors: benign training processes only; threshold = 95th percentile of scores\n"
            "on a benign-only calibration subset (target FPR 5%)  |  metrics on the held-out part",
            ha="center", va="center", fontsize=8.1, color=MUTED, linespacing=1.35)
    fig.savefig(path, bbox_inches="tight", facecolor="white")


if __name__ == "__main__":
    import json, sys
    s = json.load(open(sys.argv[1]))["dataset"]
    fmt = lambda v: "{:,}".format(v)
    n = dict(events=fmt(s["events"]), dropped=fmt(s["events"] - s["events_used"]), proc=fmt(s["processes"]),
             mal=fmt(s["malicious"]), ben=fmt(s["benign"]), lin=fmt(s["lineage_groups"]))
    fig1("docs/fig1_overview.png")
    fig2("docs/fig2_protocol.png", n)
