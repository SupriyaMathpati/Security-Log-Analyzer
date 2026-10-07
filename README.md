# Security Log Analyzer

A beginner-friendly Python and Streamlit project that analyzes fictional security log data and identifies potentially suspicious login activity.

This project was developed as part of the **NexOrbiX Technologies Cyber Security Internship**.

---

## Project Overview

Security logs contain useful information about activities such as login attempts, successful logins, failed logins, and other events.

The Security Log Analyzer reads a CSV security log, processes the entries, and provides a simple security summary.

The analyzer can identify:

- Total number of log events
- Successful login attempts
- Failed login attempts
- Frequently occurring IP addresses
- Users with repeated failed login attempts
- IP addresses with repeated failed login attempts
- Potentially suspicious activity
- A visual IP activity chart

The project uses fictional/sample data for educational purposes.

---

## Objectives

The main objectives of this project are to:

- Understand the importance of security logs
- Read and process CSV log data
- Extract useful information from log entries
- Count successful and failed login attempts
- Identify repeated failed login patterns
- Count frequently occurring IP addresses
- Display potentially suspicious activity
- Generate a basic security summary
- Practice Python data processing
- Understand basic security monitoring concepts

---

## Technologies Used

- Python
- Streamlit
- Pandas
- CSV
- Counter from Python Collections

---

## Project Structure

```text
Security_Log_Analyzer/
│
├── app.py
├── log_analyzer.py
├── sample_logs.csv
├── README.md
│
└── screenshots/
    ├── dashboard.png
    ├── uploaded_log.png
    └── security_summary.png

```
---

## Log Format
The sample security log uses the following CSV fields:

| Field | Description |
|---|---|
| `timestamp` | Date and time of the event |
| `username` | User associated with the event |
| `ip_address` | IP address associated with the event |
| `event_type` | Type of event, such as login or logout |
| `status` | Status of the event, such as success or failed |

Example
timestamp,username,ip_address,event_type,status
2026-10-01 09:15:22,alice,192.168.1.10,login,success
2026-10-01 09:22:10,alice,192.168.1.10,login,failed

The dataset is fictional and was created specifically for this project.

---

## Features

1. CSV Log Input
The application allows a user to upload a CSV security log.
If no file is uploaded, the application uses the included fictional sample_logs.csv dataset.

2. Log Parsing
The application reads the CSV file and processes each log entry.
It checks that the required fields are available:
timestamp
username
ip_address
event_type
status

3. Security Overview
The dashboard displays:
- Total Events
- Successful Logins
- Failed Logins
For the included sample dataset:
Total Events       : 20
Successful Logins  : 6
Failed Logins      : 13

4. Repeated Failed Login Detection
The analyzer counts failed login attempts for each username.
An account with 3 or more failed login attempts is marked as potentially suspicious.
For the sample dataset:
alice    -> 4 failed login attempts
charlie  -> 3 failed login attempts
eve      -> 4 failed login attempts

5. Suspicious IP Detection
The analyzer also counts failed login attempts for each IP address.
An IP address with 3 or more failed login attempts is marked as potentially suspicious.
For the sample dataset:
192.168.1.10 -> 4 failed login attempts
192.168.1.12 -> 3 failed login attempts
10.0.0.15    -> 4 failed login attempts

6. Frequently Occurring IP Addresses
The application counts how frequently each IP address appears in the log.
Example results from the sample dataset:
192.168.1.10 -> 6 events
192.168.1.11 -> 4 events
192.168.1.12 -> 4 events
10.0.0.15    -> 4 events
192.168.1.13 -> 2 events

7. IP Activity Chart
The Streamlit dashboard displays a bar chart showing the number of events associated with each IP address.
This makes frequently occurring IP addresses easier to identify visually.

8. Log Data Display
The application displays the processed log entries in a table so that the user can review the original events.

9. Security Summary
The dashboard generates a basic summary describing:
- Number of processed events
- Successful login count
- Failed login count
- Potentially suspicious activity
Repeated failed login attempts are treated as potentially suspicious patterns and are not automatically considered malicious.

---

## Suspicious Activity Rule

The project uses a simple beginner-level detection rule:
An account or IP address with 3 or more failed login attempts is marked as potentially suspicious.

This threshold is used only for basic pattern detection.

A repeated failed login pattern does not prove that an event is malicious. Further investigation would be required in a real security environment.

---

## Error Handling

The application includes basic error handling for situations such as:
- Missing log files
- Empty CSV files
- Missing required CSV columns
- Invalid file encoding
- Problems reading the log file

---

## Running the Project

Step 1: Open the Project Folder
Open the Security_Log_Analyzer project folder in VS Code.

Step 2: Open the Terminal
Open the VS Code terminal and make sure the terminal is inside the project folder:
Security_Log_Analyzer

Step 3: Run the Streamlit Application
Run:
streamlit run app.py

Step 4: Open the Application
Streamlit will provide a local URL such as:
http://localhost:8501

or another available local port.
Open the URL in your browser to use the Security Log Analyzer.

---

## Testing

The project was tested using the included fictional security log dataset.

Test Results

| Test | Result |
|---|---|
| Load sample CSV | Passed |
| Parse log entries | Passed |
| Count total events | Passed |
| Count successful logins | Passed |
| Count failed logins | Passed |
| Detect repeated failed attempts | Passed |
| Detect suspicious users | Passed |
| Detect suspicious IP addresses | Passed |
| Display frequent IP addresses | Passed |
| Display IP activity chart | Passed |
| Display log data | Passed |
| Generate security summary | Passed |
| Streamlit dashboard | Passed |


Sample Dataset Result
Total Events       : 20
Successful Logins  : 6
Failed Logins      : 13

Potentially suspicious users detected:
alice
charlie
eve

Potentially suspicious IP addresses detected:
192.168.1.10
192.168.1.12
10.0.0.15

---

## Security Considerations
- Only fictional/sample security logs should be used for this project.
- Do not analyze logs that you are not authorized to access.
- Repeated failed login attempts are only indicators of potentially suspicious activity.
- The analyzer does not determine whether an event is definitely malicious.
- Real security investigations require additional context and analysis.
- The application is intended for educational purposes.

---

## Learning Outcomes

Through this project, I practiced:
- Python programming
- CSV file processing
- Log parsing
- Data analysis
- Counting and grouping security events
- Basic suspicious activity detection
- Streamlit dashboard development
- Error handling
- Security monitoring concepts
- Presenting security analysis results

---

## Disclaimer

This project is an educational Cyber Security internship project.
The sample dataset is fictional and does not represent real users, systems, or security incidents.
The analyzer provides basic pattern-based analysis and should not be used as a replacement for professional security monitoring or incident response systems.

---

## Author

Supriya Mathpati
Cyber Security Internship Project
NexOrbiX Technologies
2026

