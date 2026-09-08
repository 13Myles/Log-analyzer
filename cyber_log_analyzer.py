import pandas as pd
import os

# ==========================================
#        CYBERSECURITY LOG ANALYZER
# ==========================================

print("======================================")
print("       CYBERSECURITY LOG ANALYZER")
print("======================================")

# ------------------------------------------
# CREATE CSV FILE
# ------------------------------------------

csv_file = "login_logs.csv"

if not os.path.exists(csv_file):

    data = {
        "username": [
            "admin",
            "admin",
            "admin",
            "admin",
            "admin",
            "john",
            "john",
            "bob",
            "bob",
            "bob",
            "alice",
            "alice"
        ],

        "ip_address": [
            "192.168.1.55",
            "192.168.1.55",
            "192.168.1.55",
            "192.168.1.55",
            "192.168.1.55",
            "10.0.0.10",
            "10.0.0.10",
            "10.0.0.42",
            "10.0.0.42",
            "10.0.0.42",
            "10.0.0.20",
            "10.0.0.20"
        ],

        "status": [
            "failed",
            "failed",
            "failed",
            "failed",
            "failed",
            "success",
            "success",
            "failed",
            "failed",
            "failed",
            "success",
            "success"
        ]
    }

    df = pd.DataFrame(data)

    df.to_csv(csv_file, index=False)

    print("\n[+] CSV file created!")

else:
    print("\n[+] CSV file already exists.")


# ------------------------------------------
# READ CSV
# ------------------------------------------

logs = pd.read_csv(csv_file)

print("[+] Login logs loaded.")


# ------------------------------------------
# BASIC STATISTICS
# ------------------------------------------

total_logins = len(logs)

successful_logins = len(
    logs[logs["status"] == "success"]
)

failed_logins = len(
    logs[logs["status"] == "failed"]
)

print("\n========== LOGIN STATISTICS ==========")

print("Total login attempts:", total_logins)
print("Successful logins:", successful_logins)
print("Failed logins:", failed_logins)


# ------------------------------------------
# USER INPUT
# ------------------------------------------

print("\n======================================")

threshold = int(
    input("How many failed attempts should trigger an alert? ")
)

print("======================================")


# ------------------------------------------
# ANALYZE FAILED LOGINS
# ------------------------------------------

failed_logs = logs[
    logs["status"] == "failed"
]


# Count failed attempts for each IP
failed_by_ip = failed_logs["ip_address"].value_counts()


# ------------------------------------------
# FIND SUSPICIOUS IPs
# ------------------------------------------

print("\n========== IP INVESTIGATION ==========")

suspicious_ips = []

for ip, attempts in failed_by_ip.items():

    if attempts >= threshold:

        suspicious_ips.append(ip)

        print(
            "ALERT:",
            ip,
            "had",
            attempts,
            "failed login attempts"
        )


if len(suspicious_ips) == 0:

    print("No suspicious IP addresses detected.")


# ------------------------------------------
# FIND TARGETED ACCOUNTS
# ------------------------------------------

print("\n========== ACCOUNT INVESTIGATION ==========")

failed_by_user = failed_logs["username"].value_counts()

for username, attempts in failed_by_user.items():

    if attempts >= threshold:

        print(
            "ALERT:",
            username,
            "had",
            attempts,
            "failed login attempts"
        )


# ------------------------------------------
# RISK SCORE
# ------------------------------------------

risk_score = 0


# Lots of failed logins
if failed_logins >= 5:

    risk_score += 30


# Suspicious IP detected
if len(suspicious_ips) > 0:

    risk_score += 30


# Suspicious account detected
for username, attempts in failed_by_user.items():

    if attempts >= threshold:

        risk_score += 20

        break


# Make sure score never goes over 100
if risk_score > 100:

    risk_score = 100


# ------------------------------------------
# SECURITY LEVEL
# ------------------------------------------

print("\n========== SECURITY ASSESSMENT ==========")

print("Risk Score:", risk_score, "/100")


if risk_score >= 70:

    print("🚨 HIGH RISK")
    print("Possible brute-force attack detected.")

elif risk_score >= 40:

    print("⚠ MEDIUM RISK")
    print("Suspicious login activity detected.")

else:

    print("✓ LOW RISK")
    print("No major suspicious activity detected.")


# ------------------------------------------
# FINAL SUMMARY
# ------------------------------------------

print("\n========== FINAL REPORT ==========")

print("Total events:", total_logins)
print("Successful logins:", successful_logins)
print("Failed logins:", failed_logins)
print("Suspicious IPs:", len(suspicious_ips))
print("Risk Score:", risk_score, "/100")

print("\n======================================")
print("          INVESTIGATION COMPLETE")
print("======================================")