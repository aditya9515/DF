from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from .common import ROOT, load_json


def figures(root=ROOT):
    root = Path(root)
    folder = root / "results/figures"
    folder.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 12,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "figure.dpi": 160,
        }
    )
    saved = []

    def finish(fig, name):
        fig.tight_layout()
        fig.savefig(folder / f"{name}.png", bbox_inches="tight")
        fig.savefig(folder / f"{name}.pdf", bbox_inches="tight")
        plt.close(fig)
        saved.append(name)

    from matplotlib.patches import FancyBboxPatch

    fig, ax = plt.subplots(figsize=(8, 3.1))
    ax.axis("off")
    labels = [
        "Local Qwen agent\nSandbox tools",
        "Event capture\nIndependent receipts",
        "SHA-256 chain\nEd25519 checkpoints",
        "Verify signatures\nReconstruct incidents",
        "Timeline dashboard\nMeasured results",
    ]
    centers = [(0.16, 0.75), (0.50, 0.75), (0.84, 0.75), (0.67, 0.25), (0.33, 0.25)]
    for (x, y), text in zip(centers, labels):
        ax.add_patch(
            FancyBboxPatch(
                (x - 0.14, y - 0.13),
                0.28,
                0.26,
                boxstyle="round,pad=.012",
                transform=ax.transAxes,
                facecolor="#e8f0f5",
                edgecolor="#56748c",
            )
        )
        ax.text(
            x,
            y,
            text,
            ha="center",
            va="center",
            transform=ax.transAxes,
            fontsize=10,
        )
    for start, end in [
        ((0.313, 0.75), (0.347, 0.75)),
        ((0.653, 0.75), (0.687, 0.75)),
        ((0.84, 0.607), (0.67, 0.393)),
        ((0.517, 0.25), (0.483, 0.25)),
    ]:
        ax.annotate(
            "",
            xy=end,
            xytext=start,
            xycoords="axes fraction",
            arrowprops={"arrowstyle": "->", "color": "#435b6b", "lw": 1.5},
        )
    finish(fig, "workflow")
    cases = load_json(root / "data/cases.json")
    df = pd.DataFrame(cases)
    fig, ax = plt.subplots(figsize=(6.5, 3.4))
    counts = df.groupby(["split", "category"]).size().unstack(fill_value=0)
    counts.rename(columns=lambda value: value.replace("_", " ")).plot.bar(
        ax=ax, color=["#527b99", "#df9d48", "#956fa4", "#6f9a7c", "#b66d6d", "#85824f"]
    )
    ax.set_ylabel("Unique scenarios")
    ax.set_xlabel("")
    ax.tick_params(axis="x", rotation=0)
    ax.legend(fontsize=10)
    finish(fig, "dataset")
    metrics = pd.read_csv(root / "results/tables/metrics.csv")
    main = metrics[(metrics.source == "InjecAgent-adapted") & (metrics.split == "test")]
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.4))
    for ax, task, title in zip(axes, ["attack_exposure", "action_violation"], ["Attack exposure", "Action violation"]):
        group = main[main.task == task].set_index("method").reindex(["keyword", "policy_only", "combined"])
        group[["precision", "recall", "f1"]].plot.bar(ax=ax, color=["#527b99", "#df9d48", "#6f9a7c"])
        ax.set_title(title)
        ax.set_ylim(0, 1.08)
        ax.set_xlabel("")
        ax.tick_params(axis="x", rotation=0)
        ax.legend(fontsize=10)
    finish(fig, "detector_comparison")
    fig, axes = plt.subplots(1, 3, figsize=(9, 3.0))
    for ax, method in zip(axes, ["keyword", "policy_only", "combined"]):
        row = main[(main.task == "attack_exposure") & (main.method == method)].iloc[0]
        matrix = np.array([[row.tn, row.fp], [row.fn, row.tp]], dtype=int)
        ax.imshow(matrix, cmap="Blues")
        ax.set_title(method)
        ax.set_xticks([0, 1], ["Benign", "Attack"])
        ax.set_yticks([0, 1], ["Benign", "Attack"])
        ax.set_xlabel("Predicted")
        for (i, j), v in np.ndenumerate(matrix):
            ax.text(j, i, str(v), ha="center", va="center", color="white" if v > matrix.max() / 2 else "black")
    axes[0].set_ylabel("Actual")
    finish(fig, "confusion_matrices")
    tamper = load_json(root / "results/tamper_results.json")
    fig, ax = plt.subplots(figsize=(8, 3.6))
    names = [r["mutation"].replace("_", " ") for r in tamper]
    values = [int(r["valid"] == r["expected_valid"]) for r in tamper]
    ax.barh(names, values, color="#527b99")
    ax.set_xlim(0, 1.15)
    ax.set_xticks([0, 1], ["Incorrect", "Correct"])
    ax.set_title("Integrity verification outcomes")
    finish(fig, "integrity")
    comp = pd.read_csv(root / "results/tables/completeness.csv")
    fig, ax = plt.subplots(figsize=(6.5, 3.1))
    ax.hist(comp.receipt_completeness, bins=np.linspace(0, 1.01, 22), color="#527b99")
    ax.set_xlabel("Captured / independently receipted model and tool events")
    ax.set_ylabel("Sessions")
    ax.set_xlim(0, 1.02)
    finish(fig, "completeness")
    micro = pd.DataFrame(load_json(root / "results/overhead_micro.json"))
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.2))
    axes[0].bar(
        ["Plain JSONL", "Full recorder"],
        [micro.plain_s.mean() * 1000, micro.full_s.mean() * 1000],
        color=["#8b9ba6", "#527b99"],
    )
    axes[0].set_ylabel("Milliseconds per 1,000 events")
    axes[0].set_title("Recorder benchmark")
    live_path = root / "results/overhead_live.json"
    if live_path.exists():
        live = pd.DataFrame(load_json(live_path))
        delta = 100 * (live.full_s / live.plain_s - 1)
        axes[1].scatter(range(1, len(delta) + 1), delta, color="#df9d48")
        axes[1].axhline(0, color="gray", lw=0.8)
        axes[1].set_ylabel("Paired runtime change (%)")
        axes[1].set_xlabel("Scenario pair")
        axes[1].set_title("Live end-to-end variability")
    finish(fig, "overhead")
    return saved
