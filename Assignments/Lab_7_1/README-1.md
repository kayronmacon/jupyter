
# Module 7 – Log Parsing Lab

## Objective
In this lab, you will:
✔ Parse raw log data
✔ Extract key fields
✔ Identify suspicious activity

## Dataset
File: auth_logs.csv

Fields:
- timestamp
- user
- ip_address
- event_type

## Tasks

### Task 1 – Load and Inspect Logs
- Load the dataset into a pandas DataFrame.
- Display the first 5 rows.
- Check data types.

### Task 2 – Feature Extraction
Create the following:
- Count of failed logins per user
- Count of login attempts per IP
- Login attempts per hour

### Task 3 – Rule-Based Detection
Flag suspicious behavior:
- More than 5 failed login attempts per user
- Login activity between 2AM–4AM

### Task 4 – Analytical Questions
Answer:
- Which user had the most failed logins?
- Which IP generated the most login attempts?
- Are there signs of brute-force behavior?

## Deliverables
Submit:
- Completed notebook
- Short written interpretation (1–2 paragraphs)
