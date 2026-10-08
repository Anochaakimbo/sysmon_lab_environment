# -*- coding: utf-8 -*-
"""
label_audit.py - validate the lineage-derived labels (reviewer comment C001).

Two parts:

1. Automatic (no human input), process level, key = (platform, run_id, ProcessGuid)
   * lineage completeness: how many processes have their parent observed in the
     same run, how many have a parent GUID that never appears in the log, and how
     many have no parent information at all (never seen in ProcessCreate)
   * independent evidence tier per process, using the per-column regexes of
     compare_nlme.py: DIRECT / PARENT / OSBOOK / none
   * disagreement candidates between the label and the evidence:
       - label=0 inside an attack run with DIRECT evidence or a lab_sandbox
         reference  -> possible false negative (e.g. a broken lineage)
       - label=1 with no evidence at all -> labeled by lineage alone
       - label=1 inside a benign run -> must be 0, otherwise the labeler is wrong

2. Manual: a stratified random sample (platform x attack scenario x label) for a
   human to check against the Atomic Red Team execution log / process tree.
   Fill the `verdict` column with correct / incorrect / ambiguous, then
       python host/label_audit.py --score reference/label_audit/audit_sample.csv
   prints agreement per stratum with Wilson 95% CI.

usage:
    python host/label_audit.py [--per-cell 15] [--out reference/label_audit]
    python host/label_audit.py --score reference/label_audit/audit_sample.csv
"""
import argparse, json, math, os, re
import numpy as np
import pandas as pd

from compare_nlme import classify

_HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(_HERE, "dataset")
EXTRA_RUNS = ["ransomware_dash_213312_20260825_213312", "trojan_dash_211024_20260825_211024"]
NULL_GUID = "{00000000-0000-0000-0000-000000000000}"
SANDBOX = re.compile(r"lab_sandbox", re.I)
SANDBOX_COLS = ["Image", "CommandLine", "CurrentDirectory", "ParentImage", "ParentCommandLine", "TargetFilename"]
EVIDENCE_COLS = ["Image", "CommandLine", "ParentCommandLine", "TargetFilename", "TargetObject"]
TIER_RANK = {"DIRECT": 3, "PARENT": 2, "OSBOOK": 1, "none": 0}


def load():
    d = [pd.read_csv(os.path.join(DATA, "merged_dataset.csv"), low_memory=False)]
    for r in EXTRA_RUNS:
        p = os.path.join(DATA, r + "_labeled.csv")
        if os.path.exists(p):
            e = pd.read_csv(p, low_memory=False)
            e["run_id"] = r
            if "platform" not in e.columns or e.platform.isna().all():
                e["platform"] = "linux"
            d.append(e)
    df = pd.concat(d, ignore_index=True)
    df["scenario"] = df.session.astype(str).str.replace("_win", "", regex=False)
    return df


def processes(df):
    df = df[df.ProcessGuid.notna() & (df.ProcessGuid != NULL_GUID)].copy()
    df["_k"] = df.platform + "|" + df.run_id + "|" + df.ProcessGuid
    pg = df.ParentProcessGuid.where(df.ParentProcessGuid.notna() & (df.ParentProcessGuid != NULL_GUID))
    df["_pk"] = np.where(pg.notna(), df.platform + "|" + df.run_id + "|" + pg.fillna(""), None)

    # evidence per event, then best tier per process
    tiers, names, texts = [], [], []
    for r in df[EVIDENCE_COLS].fillna("").astype(str).to_dict("records"):
        c = classify(r)
        tiers.append(c[0] if c else "none")
        names.append(c[1] if c else "")
        texts.append(c[2] if c else "")
    df["_tier"], df["_tname"], df["_ttext"] = tiers, names, texts
    df["_rank"] = df._tier.map(TIER_RANK)
    df["_sbx"] = df[SANDBOX_COLS].fillna("").astype(str).apply(lambda c: c.str.contains(SANDBOX)).any(axis=1)

    g = df.groupby("_k", sort=True)
    best = df.sort_values("_rank", ascending=False).drop_duplicates("_k").set_index("_k")
    first = lambda c: g[c].agg(lambda s: s.dropna().iloc[0] if s.notna().any() else "")
    p = pd.DataFrame(dict(
        platform=g.platform.first(), scenario=g.scenario.first(), run_id=g.run_id.first(),
        label=g.label.max().astype(int), is_seed=g.is_seed.max().fillna(0).astype(int),
        n_events=g.size(), has_create=g.EventID.agg(lambda s: int((s == 1).any())),
        Image=first("Image"), CommandLine=first("CommandLine"), CurrentDirectory=first("CurrentDirectory"),
        ParentImage=first("ParentImage"), ParentCommandLine=first("ParentCommandLine"),
        pkey=first("_pk"), sandbox_ref=g._sbx.any().astype(int)))
    p["tier"] = best._tier
    p["evidence_technique"] = best._tname
    p["evidence"] = best._ttext
    known = set(p.index)
    p["parent_status"] = np.where(p.pkey == "", "no_parent_info",
                                  np.where(p.pkey.isin(known), "observed", "parent_not_logged"))
    p["attack_run"] = (p.scenario != "benign").astype(int)
    p["lineage_chain"] = chains(p)
    return p


def chains(p, max_len=12):
    par, img = p.pkey.to_dict(), p.Image.astype(str).to_dict()
    out = []
    for k in p.index:
        seq, seen = [], set()
        while k in img and k not in seen and len(seq) < max_len:
            seen.add(k)
            seq.append(re.split(r"[\\/]", img[k])[-1] or "?")
            k = par.get(k, "")
        out.append(" < ".join(seq))
    return out


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 2
    ph = k / n
    d = 1 + z * z / n
    c = (ph + z * z / (2 * n)) / d
    h = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def score(path):
    s = pd.read_csv(path)
    s["verdict"] = s.verdict.astype(str).str.strip().str.lower()
    done = s[s.verdict.isin(["correct", "incorrect", "ambiguous"])]
    print("checked %d / %d rows" % (len(done), len(s)))
    rows = []
    for key, d in [(("all", "all", "all"), done)] + list(done.groupby(["platform", "scenario", "label"])):
        k, n = int((d.verdict == "correct").sum()), int((d.verdict != "ambiguous").sum())
        lo, hi = wilson(k, n)
        rows.append(dict(platform=key[0], scenario=key[1], label=key[2], checked=len(d),
                         correct=k, incorrect=int((d.verdict == "incorrect").sum()),
                         ambiguous=int((d.verdict == "ambiguous").sum()),
                         agreement=k / n if n else float("nan"), ci95_low=lo, ci95_high=hi))
    r = pd.DataFrame(rows)
    out = path.replace(".csv", "_score.csv")
    r.to_csv(out, index=False)
    print(r.to_string(index=False, float_format=lambda v: "%.3f" % v))
    print("->", out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-cell", type=int, default=15, help="sample size per platform x scenario x label")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(_HERE), "reference", "label_audit"))
    ap.add_argument("--score", help="score a filled-in audit_sample.csv and exit")
    a = ap.parse_args()
    if a.score:
        return score(a.score)
    os.makedirs(a.out, exist_ok=True)
    p = processes(load())
    by = ["platform", "scenario"]

    comp = p.groupby(by + ["label"]).parent_status.value_counts().unstack(fill_value=0).reset_index()
    comp.to_csv(os.path.join(a.out, "lineage_completeness.csv"), index=False)
    tiers = p.groupby(by + ["label"]).tier.value_counts().unstack(fill_value=0).reset_index()
    tiers.to_csv(os.path.join(a.out, "evidence_tiers.csv"), index=False)

    # control: how often each evidence regex fires on processes of the benign runs,
    # where no attack was executed. A regex that fires there is not attack-specific.
    grp = np.select([p.attack_run == 0, p.label == 0], ["benign_run", "attack_run_label0"], "attack_run_label1")
    spec = pd.crosstab(p.evidence_technique.replace("", "(none)"), grp)
    spec = spec.div(pd.Series(grp).value_counts(), axis=1).mul(100).round(2)
    spec.to_csv(os.path.join(a.out, "evidence_specificity_pct.csv"))
    benign_hits = set(p[(p.attack_run == 0) & (p.tier == "DIRECT")].evidence_technique)
    p["strong_evidence"] = ((p.sandbox_ref == 1) |
                            ((p.tier == "DIRECT") & ~p.evidence_technique.isin(benign_hits))).astype(int)

    fn = p[(p.attack_run == 1) & (p.label == 0) & (p.strong_evidence == 1)]
    weak_fn = p[(p.attack_run == 1) & (p.label == 0) & (p.tier == "DIRECT") & (p.strong_evidence == 0)]
    lin_only = p[(p.label == 1) & (p.tier == "none") & (p.sandbox_ref == 0)]
    benign_pos = p[(p.attack_run == 0) & (p.label == 1)]
    fn.to_csv(os.path.join(a.out, "candidates_possible_fn.csv"))
    lin_only.to_csv(os.path.join(a.out, "candidates_lineage_only.csv"))

    rs = np.random.RandomState(0)
    att = p[p.attack_run == 1]
    pick = [k for _, d in att.groupby(by + ["label"]) for k in d.index[rs.permutation(len(d))[:a.per_cell]]]
    sample = att.loc[pick]
    cols = ["platform", "scenario", "run_id", "label", "is_seed", "tier", "evidence_technique", "evidence",
            "sandbox_ref", "strong_evidence", "parent_status", "lineage_chain", "Image", "CommandLine", "CurrentDirectory",
            "ParentImage", "ParentCommandLine", "n_events"]
    sample = sample[cols].assign(verdict="", note="")
    sample.index.name = "process_key"
    sample.to_csv(os.path.join(a.out, "audit_sample.csv"), encoding="utf-8-sig")

    mal = p[p.label == 1]
    summary = dict(
        processes=len(p), malicious=len(mal), benign=int((p.label == 0).sum()),
        parent_status_all=p.parent_status.value_counts().to_dict(),
        parent_status_malicious=mal.parent_status.value_counts().to_dict(),
        parent_status_benign_in_attack_runs=p[(p.attack_run == 1) & (p.label == 0)].parent_status.value_counts().to_dict(),
        tier_malicious=mal.tier.value_counts().to_dict(),
        malicious_with_independent_evidence=int(((mal.tier != "none") | (mal.sandbox_ref == 1)).sum()),
        seeds=int(p.is_seed.sum()),
        attack_specific_techniques=sorted(set(p[p.strong_evidence == 1].evidence_technique) - {""}),
        techniques_also_in_benign_runs=sorted(benign_hits),
        malicious_with_strong_evidence=int(mal.strong_evidence.sum()),
        possible_fn=len(fn), possible_fn_by_parent_status=fn.parent_status.value_counts().to_dict(),
        weak_evidence_label0=len(weak_fn),
        lineage_only_malicious=len(lin_only),
        label1_in_benign_runs=len(benign_pos),
        sample_size=len(sample))
    json.dump(summary, open(os.path.join(a.out, "summary.json"), "w"), indent=2)
    print(json.dumps(summary, indent=2))
    print("\nper platform x scenario (processes / malicious / parent not logged / possible FN / lineage-only):")
    t = p.groupby(by).agg(n=("label", "size"), mal=("label", "sum"),
                          not_logged=("parent_status", lambda s: int((s != "observed").sum())))
    t["possible_fn"] = fn.groupby(by).size().reindex(t.index).fillna(0).astype(int)
    t["lineage_only"] = lin_only.groupby(by).size().reindex(t.index).fillna(0).astype(int)
    print(t.to_string())
    t.to_csv(os.path.join(a.out, "per_scenario.csv"))
    print("\noutputs ->", a.out)
    assert len(benign_pos) == 0, "label=1 found inside a benign run - labeler bug"


if __name__ == "__main__":
    main()
