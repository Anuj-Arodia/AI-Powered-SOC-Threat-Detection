
import os
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

# ==========================================
# AI POWERED SOC DETECTION ENGINE
# ==========================================

DATA_PATH = "data/security_logs.csv"
MODEL_PATH = "data/soc_model.joblib"

# ==========================================
# 1. LOAD SECURITY LOGS
# ==========================================

def load_logs():

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            "Security logs not found. Run generate_logs.py first."
        )

    df = pd.read_csv(DATA_PATH)

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["timestamp", "username", "source_ip", "status", "label"]
    ).copy()

    df["label"] = df["label"].astype(int)

    print("\n[+] Security logs loaded successfully")
    print(f"[+] Total events: {len(df)}")

    return df


# ==========================================
# 2. FEATURE ENGINEERING
# ==========================================

def engineer_features(df):

    df = df.copy()

    # Time-based features
    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek

    # Login status feature
    df["is_failed"] = (
        df["status"].str.lower() == "failed"
    ).astype(int)

    # IP address features
    df["is_private_ip"] = df["source_ip"].apply(
        lambda ip: int(
            pd.notna(ip)
            and (
                str(ip).startswith("10.")
                or str(ip).startswith("192.168.")
                or str(ip).startswith("172.16.")
            )
        )
    )

    # Failed login attempts from the same IP
    # within the previous 10 minutes.
    df = df.sort_values(
        ["source_ip", "timestamp"]
    ).copy()

    df["failed_attempts_10m"] = 0

    for ip, group in df.groupby("source_ip"):

        failed_times = (
            group.loc[
                group["is_failed"] == 1, "timestamp"
            ].sort_values()
        )

        counts = []

        for timestamp in group["timestamp"]:

            window_start = timestamp - pd.Timedelta(minutes=10)

            count = (
                (failed_times >= window_start)
                & (failed_times < timestamp)
            ).sum()

            counts.append(count)

        df.loc[group.index, "failed_attempts_10m"] = counts

    # Previous failed login events for the same user
    df = df.sort_values(
        ["username", "timestamp"]
    ).copy()

    df["user_failed_attempts_10m"] = 0

    for username, group in df.groupby("username"):

        failed_times = (
            group.loc[
                group["is_failed"] == 1, "timestamp"
            ].sort_values()
        )

        counts = []

        for timestamp in group["timestamp"]:

            window_start = timestamp - pd.Timedelta(minutes=10)

            count = (
                (failed_times >= window_start)
                & (failed_times < timestamp)
            ).sum()

            counts.append(count)

        df.loc[group.index, "user_failed_attempts_10m"] = counts

    # Brute-force indicator
    df["brute_force_indicator"] = (
        df["failed_attempts_10m"] >= 5
    ).astype(int)

    df = df.sort_values("timestamp").reset_index(drop=True)

    print("[+] Feature engineering completed")

    return df


# ==========================================
# 3. RULE-BASED DETECTION
# ==========================================

def detect_brute_force(df):

    df = df.copy()

    df["rule_alert"] = (
        (df["failed_attempts_10m"] >= 5)
        | (df["user_failed_attempts_10m"] >= 5)
    ).astype(int)

    df["rule_severity"] = np.select(
        [
            df["failed_attempts_10m"] >= 10,
            df["failed_attempts_10m"] >= 5,
            df["user_failed_attempts_10m"] >= 5
        ],
        [
            "CRITICAL",
            "HIGH",
            "HIGH"
        ],
        default="LOW"
    )

    print("[+] Rule-based detection completed")
    print(
        f"[+] Rule alerts generated: {df['rule_alert'].sum()}"
    )

    return df


# ==========================================
# 4. MACHINE LEARNING MODEL
# ==========================================

def train_model(df):

    # Only observable features.
    # NEVER include label, rule_alert, or any
    # ground-truth-derived columns as input.

    feature_columns = [
        "username",
        "source_ip",
        "status",
        "hour",
        "day_of_week",
        "is_failed",
        "is_private_ip",
        "failed_attempts_10m",
        "user_failed_attempts_10m",
        "brute_force_indicator"
    ]

    X = df[feature_columns].copy()
    y = df["label"].copy()

    # Split before fitting the preprocessing pipeline.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    categorical_features = [
        "username",
        "source_ip",
        "status"
    ]

    numeric_features = [
        "hour",
        "day_of_week",
        "is_failed",
        "is_private_ip",
        "failed_attempts_10m",
        "user_failed_attempts_10m",
        "brute_force_indicator"
    ]

    # Preprocessing is fitted ONLY on training data.
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                categorical_features
            ),
            (
                "numeric",
                StandardScaler(),
                numeric_features
            )
        ]
    )

    model = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=200,
                    max_depth=12,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1
                )
            )
        ]
    )

    print("\n[+] Training Random Forest model...")

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    # ======================================
    # 5. MODEL EVALUATION
    # ======================================

    print("\n==========================================")
    print("          MODEL EVALUATION")
    print("==========================================")

    print(
        "Accuracy:",
        round(accuracy_score(y_test, predictions), 4)
    )

    print(
        "Precision:",
        round(
            precision_score(
                y_test,
                predictions,
                zero_division=0
            ),
            4
        )
    )

    print(
        "Recall:",
        round(
            recall_score(
                y_test,
                predictions,
                zero_division=0
            ),
            4
        )
    )

    print(
        "F1 Score:",
        round(
            f1_score(
                y_test,
                predictions,
                zero_division=0
            ),
            4
        )
    )

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    print("\nConfusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=[0, 1]
        )
    )

    os.makedirs("data", exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "features": feature_columns
        },
        MODEL_PATH
    )

    print("\n[+] Model saved successfully")
    print(f"[+] Model location: {MODEL_PATH}")

    # Return metrics for dashboard use.
    return {
        "model": model,
        "X_test": X_test,
        "y_test": y_test,
        "predictions": predictions,
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(
            y_test, predictions, zero_division=0
        ),
        "recall": recall_score(
            y_test, predictions, zero_division=0
        ),
        "f1": f1_score(
            y_test, predictions, zero_division=0
        )
    }


# ==========================================
# 6. MAIN EXECUTION
# ==========================================

def main():

    print("\n==========================================")
    print("     AI POWERED SOC DETECTION ENGINE")
    print("==========================================")

    logs = load_logs()

    logs = engineer_features(logs)

    logs = detect_brute_force(logs)

    results = train_model(logs)

    print("\n==========================================")
    print("          ANALYSIS COMPLETED")
    print("==========================================")

    print(
        "\nModel Accuracy:",
        round(results["accuracy"] * 100, 2),
        "%"
    )

    print("\n[+] Ready for dashboard integration")


if __name__ == "__main__":
    main()
