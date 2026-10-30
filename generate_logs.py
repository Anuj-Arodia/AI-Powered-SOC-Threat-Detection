
import pandas as pd
import random
from datetime import datetime, timedelta
import os

# ==================================
# AI SOC - SECURITY LOG GENERATOR
# ==================================

random.seed(42)

# Create data directory
os.makedirs("data", exist_ok=True)

users = [
    "admin",
    "john",
    "alice",
    "bob",
    "security_analyst",
    "hr_manager",
    "finance_user",
    "developer"
]

normal_ips = [
    "192.168.1.10",
    "192.168.1.15",
    "192.168.1.20",
    "10.0.0.5",
    "10.0.0.8"
]

suspicious_ips = [
    "185.220.101.1",
    "45.155.205.10",
    "103.75.118.20",
    "91.240.118.172",
    "194.165.16.11"
]

events = []

start_time = datetime.now() - timedelta(days=7)

# ==================================
# 1. NORMAL LOGIN EVENTS
# ==================================

for i in range(650):

    event_time = start_time + timedelta(
        minutes=random.randint(0, 10080)
    )

    events.append({
        "timestamp": event_time,
        "username": random.choice(users),
        "source_ip": random.choice(normal_ips),
        "event_type": "login",
        "status": "success",
        "label": 0
    })


# ==================================
# 2. FAILED LOGIN EVENTS
# ==================================

for i in range(150):

    event_time = start_time + timedelta(
        minutes=random.randint(0, 10080)
    )

    events.append({
        "timestamp": event_time,
        "username": random.choice(users),
        "source_ip": random.choice(normal_ips),
        "event_type": "login",
        "status": "failed",
        "label": 0
    })


# ==================================
# 3. BRUTE FORCE ATTACK EVENTS
# ==================================

for attack in range(8):

    attacker_ip = random.choice(suspicious_ips)
    target_user = random.choice(users)

    attack_start = start_time + timedelta(
        minutes=random.randint(0, 9000)
    )

    for attempt in range(12):

        events.append({
            "timestamp": attack_start + timedelta(
                seconds=attempt * 20
            ),
            "username": target_user,
            "source_ip": attacker_ip,
            "event_type": "login",
            "status": "failed",
            "label": 1
        })


# ==================================
# 4. SUSPICIOUS LOGIN EVENTS
# ==================================

for i in range(100):

    event_time = start_time + timedelta(
        minutes=random.randint(0, 10080)
    )

    events.append({
        "timestamp": event_time,
        "username": random.choice(users),
        "source_ip": random.choice(suspicious_ips),
        "event_type": "login",
        "status": random.choice(["success", "failed"]),
        "label": 1
    })


# ==================================
# 5. ACCOUNT COMPROMISE SIMULATION
# ==================================

for i in range(20):

    event_time = start_time + timedelta(
        minutes=random.randint(0, 10000)
    )

    attacker_ip = random.choice(suspicious_ips)
    target_user = random.choice(users)

    events.append({
        "timestamp": event_time,
        "username": target_user,
        "source_ip": attacker_ip,
        "event_type": "login",
        "status": "success",
        "label": 1
    })


# ==================================
# SAVE DATASET
# ==================================

df = pd.DataFrame(events)

df["timestamp"] = pd.to_datetime(df["timestamp"])

df = df.sort_values("timestamp")

output_file = "data/security_logs.csv"

df.to_csv(output_file, index=False)

print("\n===================================")
print(" AI SOC LOG GENERATOR")
print("===================================")

print(f"\nTotal events generated: {len(df)}")

print("\nEvent distribution:")
print(df["status"].value_counts())

print("\nGround-truth distribution:")
print(df["label"].value_counts())

print("\nSample security logs:")
print(df.head(10).to_string(index=False))

print(f"\nDataset saved successfully: {output_file}")
