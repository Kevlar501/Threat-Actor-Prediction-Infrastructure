"""Milestone 2 EDA.
Reads data/features/features.csv and data/processed/actors.csv,
prints summary statistics, and saves figures to figures/.
Run: python eda.py
"""
import os

import matplotlib
matplotlib.use("Agg")  # save to file, no window needed
import matplotlib.pyplot as plt
import pandas as pd

FEATURES = os.path.join("data", "features", "features.csv")
ACTORS = os.path.join("data", "processed", "actors.csv")
OUT = "figures"
os.makedirs(OUT, exist_ok=True)

df = pd.read_csv(FEATURES)
actors = pd.read_csv(ACTORS)
tech_cols = [c for c in df.columns if c.startswith("attack-pattern--")]

# Mark revoked/deprecated actors so they can be excluded
def is_true(s):
    return s.astype(str).str.lower() == "true"

actors["retired"] = is_true(actors["revoked"]) | is_true(actors["deprecated"])
df = df.merge(actors[["id", "retired"]], left_on="group_id", right_on="id", how="left")
df["retired"] = df["retired"].fillna(False).astype(bool)
active = df[~df["retired"]].copy()

# ---- Quality checks ----
print("=== Structure and quality ===")
print(f"Rows in features.csv: {len(df)}")
print(f"Technique columns: {len(tech_cols)}")
print(f"Retired actors excluded: {df['retired'].sum()}")
print(f"Active actors analysed: {len(active)}")
print(f"Missing values in technique columns: {int(df[tech_cols].isna().sum().sum())}")
print(f"Duplicate group_id values: {int(df['group_id'].duplicated().sum())}")
print(f"Active actors with identical technique profiles: {int(active[tech_cols].duplicated().sum())}")

# ---- Class balance ----
counts = active["target_category"].value_counts()
print("\n=== Class balance (active actors) ===")
print(counts.to_string())

fig, ax = plt.subplots(figsize=(7, 4))
counts.plot(kind="bar", ax=ax)
for i, v in enumerate(counts.values):
    ax.text(i, v, str(v), ha="center", va="bottom")
ax.set_title("Tier 1 class balance (active actors)")
ax.set_xlabel("Tier 1 category")
ax.set_ylabel("Number of actors")
plt.xticks(rotation=0)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "01_class_balance.png"), dpi=150)
plt.close(fig)

# ---- Techniques per actor ----
active["n_techniques"] = active[tech_cols].sum(axis=1)
n = active["n_techniques"]
print("\n=== Techniques per actor ===")
print(n.describe().round(1).to_string())
print(f"Actors with 0 techniques: {int((n == 0).sum())}")
print(f"Actors with 1-3 techniques (excluded from Tier 2): {int(((n >= 1) & (n < 4)).sum())}")
print(f"Actors with 4-9 techniques (low confidence): {int(((n >= 4) & (n < 10)).sum())}")
print(f"Actors with >=10 techniques (high confidence): {int((n >= 10).sum())}")
print("\nMedian techniques per actor by category:")
print(active.groupby("target_category")["n_techniques"].median().to_string())

fig, ax = plt.subplots(figsize=(7, 4))
ax.hist(n, bins=30)
ax.axvline(4, color="red", linestyle="--", label="Tier 2 inclusion threshold (4)")
ax.axvline(10, color="green", linestyle="--", label="High-confidence threshold (10)")
ax.set_title("Documented techniques per actor")
ax.set_xlabel("Number of techniques")
ax.set_ylabel("Number of actors")
ax.legend()
fig.tight_layout()
fig.savefig(os.path.join(OUT, "02_techniques_per_actor.png"), dpi=150)
plt.close(fig)

# ---- Technique prevalence / sparsity ----
per_tech = active[tech_cols].sum(axis=0)
sparsity = 1 - active[tech_cols].values.mean()
print("\n=== Technique prevalence ===")
print(f"Techniques used by 0 active actors: {int((per_tech == 0).sum())}")
print(f"Techniques used by exactly 1 actor: {int((per_tech == 1).sum())}")
print(f"Feature matrix sparsity (share of zeros): {sparsity:.3f}")

fig, ax = plt.subplots(figsize=(7, 4))
ax.hist(per_tech, bins=30)
ax.set_title("How many actors use each technique")
ax.set_xlabel("Number of actors using the technique")
ax.set_ylabel("Number of techniques")
fig.tight_layout()
fig.savefig(os.path.join(OUT, "03_technique_prevalence.png"), dpi=150)
plt.close(fig)

print(f"\nFigures saved to {OUT}/")