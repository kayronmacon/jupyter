# Course 01 Capstone Project

## Team Information

- **Team #:**
- **Team Members:**
  -
  -
  -
  -

**GitHub Repository:** <!-- paste link here -->

---

## Project Summary — CRISP-DM Framework

### 1. Business Understanding

**Problem Statement:**
Network intrusion detection is a core component of enterprise cybersecurity. Manual inspection of network traffic is too slow to keep up with modern attack volumes. This project addresses the need for an automated, ML-based system that can classify network traffic in real time.

**Project Goals and Success Criteria:**
Build a machine learning classifier that distinguishes benign network traffic from five cyberattack categories: DDoS, Port Scan, Brute Force, Botnet, and Web Attack. Success is measured by per-class F1-score, with emphasis on minimizing false negatives (missed attacks).

---

### 2. Data Understanding

**Dataset (Source and Description):**
A synthetic dataset modeled after the CICIDS 2017 (Canadian Institute for Cybersecurity) benchmark. It contains 10,100 records and 31 columns representing network flow statistics such as packet lengths, byte rates, inter-arrival times, and TCP flag counts.

**Key Variables and Initial Observations:**
- **Target:** `Label` — 6 classes: BENIGN, DDoS, PortScan, BruteForce, Botnet, WebAttack
- All 30 feature columns are numeric (float64); missing values ranged from ~3.6% to ~4.4% per column
- Class distribution is imbalanced — BENIGN is the majority class
- DDoS and PortScan show distinct spikes in `Flow Bytes/s` and `Flow Pkts/s`
- Negative values were found in `Flow IAT Mean`, indicating sensor glitches

---

### 3. Data Preparation

**Cleaning and Transformation Steps:**
1. Removed 99 exact duplicate rows
2. Capped outliers at the 99th percentile for all numeric columns
3. Fixed negative `Flow IAT Mean` values by taking absolute value (physically impossible in real traffic)
4. Imputed all remaining missing values using column median (robust to skewed distributions)

**Final Dataset Used for Modeling:**
10,001 rows x 33 features (30 original numeric features + 3 engineered features). Zero missing values remaining.

---

### 4. Modeling

**Algorithms Applied:**
- Logistic Regression
- Random Forest (30 estimators)
- Gradient Boosting (HistGradientBoosting, 30 iterations)

**Reason for Model Selection:**
- Logistic Regression serves as a simple, interpretable linear baseline
- Random Forest handles class imbalance well, is robust to outliers, and provides feature importance rankings
- Gradient Boosting typically achieves the highest accuracy on tabular data by learning complex non-linear decision boundaries
- All three were trained on an 80/20 stratified split to preserve class proportions

---

### 5. Evaluation

**Best Model and Performance Metrics:**

| Model | Accuracy |
|---|---|
| Logistic Regression | 99.40% |
| Random Forest | 99.60% |
| **Gradient Boosting** | **99.75%** |

Gradient Boosting — detailed results on the test set (2,001 samples):

| Class | Precision | Recall | F1 |
|---|---|---|---|
| BENIGN | 1.00 | 1.00 | 1.00 |
| Botnet | 1.00 | 1.00 | 1.00 |
| BruteForce | 1.00 | 0.99 | 0.99 |
| DDoS | 1.00 | 1.00 | 1.00 |
| PortScan | 1.00 | 1.00 | 1.00 |
| WebAttack | 1.00 | 0.95 | 0.97 |

**Does the Model Meet Project Goals? Why or Why Not?**
Yes. All classes achieved F1 >= 0.97. DDoS and PortScan — the highest-volume attack types — scored perfect F1. WebAttack showed the lowest recall (0.95) due to class imbalance (only 60 test samples), which is the primary remaining gap.

---

### 6. Insights & Next Steps
*(Deployment excluded for Course 01)*

**Key Analytical Insight:**
High F1 scores on DDoS and PortScan reflect their distinctly extreme traffic patterns (very high byte rates, very short durations). Minority classes like WebAttack and Botnet underperform due to class imbalance rather than model weakness. A SOC could use high-confidence predictions for auto-triage and route ambiguous cases to human analysts.

**Limitations:**
- Dataset is synthetic; real traffic contains more variability and adversarial adaptation
- Class imbalance inflates overall accuracy while suppressing minority-class recall
- No temporal features — real IDS must account for session context and time-series dynamics
- Models were not hyperparameter-tuned

**Future Work:**
- Apply SMOTE or class-weighted training to improve minority-class recall
- Add k-fold cross-validation for more reliable performance estimates
- Explore deep learning (LSTM, autoencoder) to capture temporal flow patterns
- Validate on real CICIDS 2017 data
- Use SHAP or LIME for model explainability
