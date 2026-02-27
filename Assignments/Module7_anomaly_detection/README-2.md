# Module 7 – Anomaly Detection Mini Project (Starter)

## Objective
You will:
- Apply **rule-based** or **statistical** detection
- **Flag suspicious events**
- **Interpret findings** like a security analyst

## Files
- `anomaly_logs_mini.csv` — mixed authentication + activity logs (includes injected suspicious behavior)
- `Anomaly_Detection_MiniProject_Starter.ipynb` — starter notebook
- `SOC_Level_Version/soc_auth_activity_advanced.csv` — advanced dataset (multi-stage brute force + impossible travel)
- `SOC_Level_Version/SOC_Level_Anomaly_Detection_Starter.ipynb` — SOC-level starter notebook

## Mini Project Tasks
### 1) Parse + Prep
- Load the CSV
- Convert `timestamp` to datetime
- Basic sanity checks (missing values, unique users/IPs, event distribution)

### 2) Rule-Based Alerts (Detection Engineering Basics)
Implement **at least 3** rules (examples):
- **Failed logins per user/IP in a 5-minute window** > threshold
- **Successful login after many failures** (possible brute force success)
- **Privilege escalation** after a suspicious login
- **Large `bytes_out`** outliers (possible data exfiltration)
- Activity during **2–4 AM**

Output: an `alerts` DataFrame with:
- `alert_type`, `severity`, `user`, `ip_address`, `start_time`, `end_time`, `evidence`

### 3) Statistical / Baseline Detection
Pick one approach:
- Z-score or modified Z-score for `bytes_out`
- Per-user hourly baseline (mean + k*std)
- Count-based outliers per IP/user

### 4) Interpretation (Write-Up)
Write 6–10 bullet points:
- What looks suspicious?
- What evidence supports it?
- What would you investigate next?
- What could be a false positive?

## Deliverables
Submit:
1) Completed notebook  
2) `alerts.csv` (exported from your notebook)  
3) Short interpretation (in notebook or separate text)

## Notes
This is **not** about perfect security—it's about structured thinking:
**collect → parse → detect → explain → next steps**.
