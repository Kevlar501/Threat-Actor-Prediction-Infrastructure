# Threat Actor Attack Prediction System

## 1. Project Overview

This project builds a machine learning system to predict the **Threat Actor Category** (e.g., Nation-State, Cybercriminal) and, where data permits, the **Specific Actor** responsible for a cyber event, based on observed attack techniques.

- **Data Source:** MITRE ATT&CK STIX Data (Enterprise Domain).
- **Limitations:** This initial iteration uses a single-source dataset (MITRE ATT&CK). It does **not** incorporate temporal data (time of day/year), specific victim company names, or data exfiltration details. Future iterations will expand to a multi-source design to address these variables.

## 2. Data Storage & Management

### Directory Structure

```text
data/
├── raw/
│   ├── enterprise-attack-19.2.json  # Pinned version, excluded from Git
│   └── MANIFEST.md                  # SHA-256 checksums and download dates
├── processed/
│   ├── actors.csv                   # Normalized actor metadata
│   ├── techniques.csv               # Normalized technique metadata
│   ├── relationships.csv            # Actor-Technique links
│   └── actor_categories.csv         # Manual coarse-category mapping
└── features/
    └── features.csv                 # Final flat feature table for modeling
```

### Storage Justification
The processed dataset is small (<1MB), making CSVs the most appropriate format for inspectability and zero-setup overhead. A relational database was considered but deemed unnecessary for this data scale.

## 3. Data Transformation & Features

### Feature Engineering

- **Technique Flags:** Binary columns for each MITRE technique (e.g., `T1059`, `T1566`) indicating presence in an actor's behavioral profile.
- **Labeling:**
  - **Tier 1 (Coarse):** Single-label classification (Nation-State, Cybercriminal, Hacktivist, Other).
  - **Tier 2 (Fine):** Multi-class classification of specific actor names.

### Exposure Filtering

- **Inclusion Threshold:** Actors with fewer than **4** documented technique relationships are excluded from Tier 2 training to prevent noise.
- **Tier 2 Confidence Tiers:**
  - **High-Confidence:** Actors with **≥10** techniques → Single-name prediction.
  - **Low-Confidence:** Actors with **4–9** techniques → Ranked candidate list (no single-name prediction).

## 4. Data Labeling & Curation

### Coarse Categories (Tier 1)

Threat actors are classified into four coarse categories:

1. **Nation-State**: State-sponsored actors engaged in cyber-espionage or sabotage.
2. **Cybercriminal**: Actors primarily motivated by financial gain.
3. **Hacktivist**: Actors motivated by political or social ideology.
4. **Other/Unknown**: Actors with unclear, mixed, or unclassified motivations.

**Labeling Strategy & Source Independence:**

MITRE ATT&CK does not include a structured motivation field; the framework deliberately omits attacker goals because the same tactics serve many different objectives. Labels were therefore derived primarily from MITRE group `description` text and country attribution, which usually make espionage versus financial motivation explicit.

CrowdStrike's 2026 Global Threat Report is used as an **independent cross-check**, not as the primary label source. Because the technique features that feed the model originate from MITRE, deriving all labels from MITRE alone would create circularity — the ground truth would be wholly internal to the feature-generating source. Consulting a structurally independent authority for ambiguous cases breaks that loop.

As a commercial threat-intelligence vendor, CrowdStrike's attributions may reflect a structural bias toward state-linkage, since their business model depends on clients perceiving threats as sophisticated and geopolitically motivated. Where their categorization conflicted with open-source reporting, the more conservative label was applied. Additional non-commercial sources will be incorporated in later iterations to further reduce single-vendor dependency.

### Handling Missing Data

To maintain dataset integrity without introducing bias through imputation:

- **Unknown Categories:** Any actor or technique metadata that could not be verified against the chosen source or was missing from the STIX data is explicitly labeled as **"Unknown"** and included in the **"Other"** category.
- **Rationale:** This approach preserves the original data structure and prevents the model from learning spurious correlations based on assumed or imputed values. It also provides a clear signal to the model that "lack of information" is itself a data point.

## 5. Data Splitting & Leakage Prevention

### Splitting Strategy

- **Method:** `StratifiedGroupKFold` (5 splits).
- **Groups:** `actor_id`.
- **Rationale:** Prevents "actor-level leakage" where similar actors appear in both train and test sets. Ensures the model generalizes to **unseen** actors.

### Preprocessing Pipeline

- All preprocessing (scaling, encoding) is wrapped in a scikit-learn `Pipeline`.
- **Critical Rule:** No data is fit on the full dataset before splitting. All transformers are fit only on the training fold to prevent data leakage.

## 6. Reproducibility

- **Pinned Version:** MITRE ATT&CK STIX v19.2 (Enterprise), released August 5, 2026.
- **Checksums:** All raw files verified via SHA-256 in `data/MANIFEST.md`. For the enterprise domain: `sha256:dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`.
- **Dependencies:** Exact versions pinned in `requirements.txt` (e.g., `scikit-learn==1.4.2`).
- **Seeds:** `random_state=42` applied to all splits and model initializations.
- **Labeling Source:** CrowdStrike 2026 Global Threat Report. Specific actor-to-category assignments are documented row-by-row in `data/processed/actor_categories.csv`, including a `source_note` column citing the page or section used for each decision.
- **Nomenclature Mapping:** Because CrowdStrike and MITRE use different group naming conventions (e.g., CrowdStrike's `FANCY BEAR` corresponds to MITRE's `G0016 / APT29`), a `crowdstrike_to_mitre_map.csv` lookup file resolves labeling sources to STIX actor IDs before merging.

## 7. Limitations & Future Iterations

- **Single-Source Dependency:** The current model relies exclusively on MITRE ATT&CK data for technique features. It cannot account for temporal patterns (e.g., time of day or seasonality), specific victim organizations, or the nature of compromised data. Later iterations will expand to a multi-source design incorporating incident and victim-context data to address these variables.

- **Label Circularity Risk:** Because coarse-category labels are derived primarily from MITRE group descriptions while technique features also originate from MITRE, ground truth and features share a common source. CrowdStrike's 2026 Global Threat Report is used as an independent cross-check for ambiguous cases to mitigate this, but residual dependence remains. Additional non-commercial labeling sources will be introduced in later iterations to reduce single-vendor influence further.

- **Vendor Attribution Bias:** Commercial threat-intelligence vendors have structural incentives to frame adversaries as sophisticated and state-linked. Where CrowdStrike categorizations conflicted with open-source reporting, the more conservative label was applied. This mitigation is partial, not complete, and should be weighed when interpreting category-level results.

- **Exposure Bias in Actor Coverage:** An actor's number of documented technique relationships correlates with media and vendor attention rather than operational capability. Well-reported groups are over-represented in training data; newer, less-publicized, or less-successful actors may be under-represented or excluded entirely by the ≥4 relationship threshold. Reported Tier 2 metrics therefore reflect performance on well-documented actors and should not be read as general attribution accuracy.

- **Class Imbalance in Coarse Categories:** Nation-state and cybercriminal categories are expected to dominate the dataset, while hacktivist groups are sparsely represented in MITRE ATT&CK. Class counts will be reported alongside evaluation metrics; if any category falls below a viable training threshold, it will be consolidated into Other/Unknown rather than trained as a distinct class.

- **Scalability:** The current CSV-based infrastructure is appropriate for this dataset size but will require a relational database and a name-resolution layer as additional sources are integrated.