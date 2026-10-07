import csv
from collections import Counter


def load_logs(filename):
    """Load security logs from a CSV file."""
    try:
        with open(filename, "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            required_columns = {
                "timestamp",
                "username",
                "ip_address",
                "event_type",
                "status"
            }

            if not required_columns.issubset(reader.fieldnames or []):
                raise ValueError("CSV file is missing required columns.")

            logs = list(reader)

            if not logs:
                raise ValueError("The log file is empty.")

            return logs

    except FileNotFoundError:
        raise FileNotFoundError("Log file was not found.")

    except Exception as error:
        raise ValueError(f"Unable to read log file: {error}")


def analyze_logs(logs):
    """Analyze security log entries."""

    total_events = len(logs)

    successful_logins = sum(
        1 for log in logs
        if log["status"].lower() == "success"
        and log["event_type"].lower() == "login"
    )

    failed_logins = sum(
        1 for log in logs
        if log["status"].lower() == "failed"
        and log["event_type"].lower() == "login"
    )

    ip_counts = Counter(
        log["ip_address"]
        for log in logs
    )

    username_failed_counts = Counter(
        log["username"]
        for log in logs
        if log["status"].lower() == "failed"
        and log["event_type"].lower() == "login"
    )

    ip_failed_counts = Counter(
        log["ip_address"]
        for log in logs
        if log["status"].lower() == "failed"
        and log["event_type"].lower() == "login"
    )

    # Detect potentially suspicious activity
    suspicious_users = {
        username: count
        for username, count in username_failed_counts.items()
        if count >= 3
    }

    suspicious_ips = {
        ip: count
        for ip, count in ip_failed_counts.items()
        if count >= 3
    }

    return {
        "total_events": total_events,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "ip_counts": ip_counts,
        "suspicious_users": suspicious_users,
        "suspicious_ips": suspicious_ips
    }


def print_summary(results):
    """Display a basic security summary."""

    print("\n" + "=" * 50)
    print("       SECURITY LOG ANALYZER")
    print("=" * 50)

    print(f"Total events       : {results['total_events']}")
    print(f"Successful logins  : {results['successful_logins']}")
    print(f"Failed logins      : {results['failed_logins']}")

    print("\nFrequently Occurring IP Addresses:")
    for ip, count in results["ip_counts"].most_common():
        print(f"  {ip} -> {count} events")

    print("\nPotentially Suspicious Users:")

    if results["suspicious_users"]:
        for username, count in results["suspicious_users"].items():
            print(
                f"  {username} -> {count} failed login attempts"
            )
    else:
        print("  None detected")

    print("\nPotentially Suspicious IP Addresses:")

    if results["suspicious_ips"]:
        for ip, count in results["suspicious_ips"].items():
            print(
                f"  {ip} -> {count} failed login attempts"
            )
    else:
        print("  None detected")

    print("=" * 50)


if __name__ == "__main__":
    try:
        logs = load_logs("sample_logs.csv")
        results = analyze_logs(logs)
        print_summary(results)

    except Exception as error:
        print(f"\nError: {error}")