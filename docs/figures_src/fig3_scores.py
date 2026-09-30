import pandas as pd, numpy as np, matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt
p1 = pd.read_csv("reference/revised_results/p1_lineage_cv.csv")
order = ["Random Forest", "Decision Tree", "SVM", "Naive Bayes", "Local Outlier Factor", "Isolation Forest", "One-Class SVM"]
short = ["RF", "DT", "SVM", "NB", "LOF", "IF", "OCSVM"]
g = p1.groupby("Model")[["Precision", "Recall", "F1"]]
m, s = g.mean().loc[order], g.std().loc[order]
cols = {"Precision": "#2a78d6", "Recall": "#eb6834", "F1": "#1baf7a"}
hatch = {"Precision": "", "Recall": "//", "F1": ".."}
fig, ax = plt.subplots(figsize=(6.6, 3.0), dpi=220)
x = np.arange(len(order)); w = 0.26
for i, k in enumerate(["Precision", "Recall", "F1"]):
    ax.bar(x + (i - 1) * w, m[k], w - 0.03, yerr=s[k], color=cols[k], hatch=hatch[k], edgecolor="white",
           linewidth=0.6, error_kw=dict(elinewidth=0.8, capsize=2, ecolor="#3e4c59"), label=k)
base = p1[p1.Model == "All-positive"].F1.mean()
ax.axhline(base, color="#3e4c59", lw=1, ls="--", label="all-positive baseline F1 (%.2f)" % base)
ax.axvline(3.5, color="#cbd2d9", lw=0.8)
ax.text(1.5, 1.07, "supervised", ha="center", fontsize=8, color="#52606d")
ax.text(5.0, 1.07, "benign-only anomaly (FPR target 5%)", ha="center", fontsize=8, color="#52606d")
ax.set_xticks(x, short, fontsize=8.5); ax.set_ylim(0, 1.12); ax.set_yticks(np.arange(0, 1.01, 0.2))
ax.tick_params(axis="y", labelsize=8); ax.set_ylabel("score (mean ± SD, 25 folds)", fontsize=8.5)
for sp in ["top", "right"]: ax.spines[sp].set_visible(False)
ax.spines["left"].set_color("#9aa5b1"); ax.spines["bottom"].set_color("#9aa5b1")
ax.grid(axis="y", color="#e4e7eb", lw=0.6); ax.set_axisbelow(True)
ax.legend(ncol=4, fontsize=8, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.1))
fig.savefig("docs/fig3_p1_scores.png", bbox_inches="tight", facecolor="white")
