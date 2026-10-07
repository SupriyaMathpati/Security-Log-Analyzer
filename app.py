import csv
import io

import pandas as pd
import streamlit as st

from log_analyzer import analyze_logs


# Page configuration
st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🔐",
    layout="wide"
)


# Title
st.title("🔐 Security Log Analyzer")
st.write(
    "Analyze a sample security log and identify potentially suspicious "
    "login activity."
)

st.info(
    "This project uses fictional/sample security logs for educational purposes. "
    "Do not upload logs that you are not authorized to analyze."
)


# Sidebar
st.sidebar.header("Log File")

uploaded_file = st.sidebar.file_uploader(
    "Upload a CSV security log",
    type=["csv"]
)

st.sidebar.markdown("---")
st.sidebar.subheader("Suspicious Activity Rule")
st.sidebar.write(
    "An account or IP address with 3 or more failed login attempts "
    "is marked as potentially suspicious."
)


def read_uploaded_logs(uploaded_file):
    """Read and validate an uploaded CSV file in memory."""

    try:
        content = uploaded_file.getvalue().decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))

        required_columns = {
            "timestamp",
            "username",
            "ip_address",
            "event_type",
            "status"
        }

        if not reader.fieldnames:
            raise ValueError("The CSV file has no header row.")

        if not required_columns.issubset(reader.fieldnames):
            raise ValueError(
                "CSV file must contain these columns: "
                "timestamp, username, ip_address, event_type, status"
            )

        logs = list(reader)

        if not logs:
            raise ValueError("The uploaded CSV file is empty.")

        return logs

    except UnicodeDecodeError:
        raise ValueError(
            "The CSV file could not be read as UTF-8 text."
        )


# Use uploaded file or sample file
if uploaded_file is not None:
    try:
        logs = read_uploaded_logs(uploaded_file)
        st.success(f"Loaded {len(logs)} log entries from the uploaded file.")

    except Exception as error:
        st.error(f"Error reading log file: {error}")
        st.stop()

else:
    try:
        with open(
            "sample_logs.csv",
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)
            logs = list(reader)

        st.info(
            "No file uploaded. The built-in fictional sample log is being used."
        )

    except FileNotFoundError:
        st.error(
            "sample_logs.csv was not found. "
            "Please make sure it is in the same folder as app.py."
        )
        st.stop()


# Analyze logs
try:
    results = analyze_logs(logs)

except Exception as error:
    st.error(f"Unable to analyze the logs: {error}")
    st.stop()


# -------------------------
# Security Overview
# -------------------------

st.header("📊 Security Overview")

col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        "Total Events",
        results["total_events"]
    )

with col2:
    st.metric(
        "Successful Logins",
        results["successful_logins"]
    )

with col3:
    st.metric(
        "Failed Logins",
        results["failed_logins"]
    )


# -------------------------
# Suspicious Activity
# -------------------------

st.header("⚠️ Potentially Suspicious Activity")

suspicious_users = results["suspicious_users"]
suspicious_ips = results["suspicious_ips"]

col1, col2 = st.columns(2)

with col1:
    st.subheader("Suspicious Users")

    if suspicious_users:
        user_data = pd.DataFrame(
            [
                {
                    "Username": username,
                    "Failed Login Attempts": count
                }
                for username, count in suspicious_users.items()
            ]
        )

        st.dataframe(
            user_data,
            width="stretch",
            hide_index=True
        )
    else:
        st.success("No potentially suspicious users detected.")


with col2:
    st.subheader("Suspicious IP Addresses")

    if suspicious_ips:
        ip_data = pd.DataFrame(
            [
                {
                    "IP Address": ip,
                    "Failed Login Attempts": count
                }
                for ip, count in suspicious_ips.items()
            ]
        )

        st.dataframe(
            ip_data,
            width="stretch",
            hide_index=True
        )
    else:
        st.success("No potentially suspicious IP addresses detected.")


# -------------------------
# IP Analysis
# -------------------------

st.header("🌐 Frequently Occurring IP Addresses")

ip_data = pd.DataFrame(
    [
        {
            "IP Address": ip,
            "Events": count
        }
        for ip, count in results["ip_counts"].most_common()
    ]
)

st.dataframe(
    ip_data,
    width="stretch",
    hide_index=True
)

st.subheader("IP Address Activity Chart")

chart_data = ip_data.set_index("IP Address")

st.bar_chart(chart_data["Events"])


# -------------------------
# Log Data
# -------------------------

st.header("📋 Log Data")

log_dataframe = pd.DataFrame(logs)

st.dataframe(
    log_dataframe,
    width="stretch",
    hide_index=True
)


# -------------------------
# Security Summary
# -------------------------

st.header("📝 Security Summary")

st.write(
    f"The analyzer processed **{results['total_events']} log events**."
)

st.write(
    f"There were **{results['successful_logins']} successful login attempts** "
    f"and **{results['failed_logins']} failed login attempts**."
)

if suspicious_users or suspicious_ips:
    st.warning(
        "Potentially suspicious activity was detected based on repeated "
        "failed login attempts."
    )

    st.write(
        "These patterns should be investigated further. "
        "A repeated failed login pattern alone does not prove that an "
        "event was malicious."
    )
else:
    st.success(
        "No potentially suspicious repeated failed-login patterns were detected."
    )


# -------------------------
# Footer
# -------------------------

st.markdown("---")

st.caption(
    "Security Log Analyzer | Educational Cyber Security Internship Project"
)