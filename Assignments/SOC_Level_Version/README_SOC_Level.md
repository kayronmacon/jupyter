# SOC-Level Version – Advanced Detection Scenarios

This version includes:
✅ Multi-stage brute force (AUTH_FAIL burst → MFA_FAIL → AUTH_SUCCESS)  
✅ Post-compromise actions (PRIV_ESCALATION, NEW_ADMIN_GRANTED, DATA_EXPORT)  
✅ Impossible travel (same user authenticates from two distant locations too quickly)

## Dataset
`soc_auth_activity_advanced.csv`

Columns include geo fields:
- `location`, `country`, `lat`, `lon`

## Expectations
Build a small “detection pipeline”:
1) Feature engineering (windowed counts, time deltas, geo speed)
2) Alerts with severity scoring
3) A brief “SOC analyst narrative”:
   - What happened?
   - Which alerts fired?
   - Why it matters?
   - Recommended response actions
