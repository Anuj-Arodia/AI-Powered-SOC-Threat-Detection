
import streamlit as st
import pandas as pd
import plotly.express as px
import joblib
import os

from detector import (
    load_logs,
    engineer_features,
    detect_brute_force
)

# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="AI SOC | Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

DATA_PATH = "data/security_logs.csv"
MODEL_PATH = "data/soc_model.joblib"

# ==========================================
# CUSTOM DARK THEME
# ==========================================

st.markdown("""
<style>

.stApp {
    background-color: #080D18;
    color: #E5E7EB;
}

[data-testid="stSidebar"] {
    background-color: #101827;
    border-right: 1px solid #263247;
}

.block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
}

h1, h2, h3 {
    color: #F8FAFC !important;
}

p, label {
    color: #CBD5E1;
}

div[data-testid="stMetric"] {
    background-color: #111C2E;
    border: 1px solid #26364F;
    padding: 18px;
    border-radius: 12px;
}

div[data-testid="stMetricLabel"] {
    color: #94A3B8;
}

div[data-testid="stMetricValue"] {
    color: #F8FAFC;
}

div[data-testid="stMetricDelta"] {
    color: #34D399;
}

hr {
    border-color: #263247;
}

.stButton button {
    background-color: #2563EB;
    color: white;
    border-radius: 8px;
    border: none;
}

.stButton button:hover {
    background-color: #1D4ED8;
    color: white;
}

</style>
""", unsafe_allow_html=True)


# ==========================================
# LOAD DATA AND MODEL
# ==========================================

@st.cache_data
def get_data():

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            "Security logs missing. Run generate_logs.py first."
        )

    logs = load_logs()

    logs = engineer_features(logs)

    logs = detect_brute_force(logs)

    return logs


@st.cache_resource
def get_model():

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            "ML model missing. Run detector.py first."
        )

    saved = joblib.load(MODEL_PATH)

    return saved["model"], saved["features"]


try:
    df = get_data()
    model, feature_columns = get_model()

    predictions = model.predict(df[feature_columns])

    df["ml_prediction"] = predictions.astype(int)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(
            df[feature_columns]
        )

        positive_class_index = list(model.classes_).index(1)

        df["ml_confidence"] = probabilities[
            :, positive_class_index
        ] * 100

    else:
        df["ml_confidence"] = df["ml_prediction"] * 100

except Exception as e:

    st.error(f"Unable to load SOC data: {e}")
    st.info(
        "Make sure generate_logs.py and detector.py "
        "have been executed successfully."
    )

    st.stop()


# ==========================================
# ALERT CLASSIFICATION
# ==========================================

df["severity"] = "LOW"

df.loc[
    df["ml_prediction"] == 1,
    "severity"
] = "MEDIUM"

df.loc[
    df["rule_alert"] == 1,
    "severity"
] = "HIGH"

df.loc[
    df["failed_attempts_10m"] >= 10,
    "severity"
] = "CRITICAL"

df["alert_status"] = df["severity"].apply(
    lambda x: "ALERT" if x != "LOW" else "NORMAL"
)

df["timestamp"] = pd.to_datetime(df["timestamp"])

# ==========================================
# HEADER
# ==========================================

st.markdown(
    "<h1>🛡️ AI-Powered SOC Dashboard</h1>",
    unsafe_allow_html=True
)

st.markdown(
    "Security Operations Center | "
    "Threat Monitoring & AI-Based Alert Triage"
)

st.caption(
    "Environment: Local SOC Simulation | "
    "Detection: Rule Engine + Random Forest"
)

st.divider()


# ==========================================
# SIDEBAR
# ==========================================

st.sidebar.title("🛡️ SOC CONTROL PANEL")

st.sidebar.markdown("### Monitoring Filters")

severity_options = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW"
]

selected_severity = st.sidebar.multiselect(
    "Select Severity",
    severity_options,
    default=severity_options
)

selected_status = st.sidebar.multiselect(
    "Login Status",
    ["success", "failed"],
    default=["success", "failed"]
)

users = sorted(df["username"].unique())

selected_users = st.sidebar.multiselect(
    "Select Users",
    users,
    default=users
)

ip_search = st.sidebar.text_input(
    "Search Source IP",
    placeholder="Enter an IP address"
)

st.sidebar.divider()

st.sidebar.markdown("### System Information")

st.sidebar.write("**ML Algorithm:** Random Forest")
st.sidebar.write("**Detection Engine:** Rule-based + ML")
st.sidebar.write("**Dataset:** security_logs.csv")

if st.sidebar.button("🔄 Refresh Dashboard"):
    st.cache_data.clear()
    st.cache_resource.clear()
    st.rerun()


# ==========================================
# APPLY FILTERS
# ==========================================

filtered_df = df[
    (df["severity"].isin(selected_severity))
    & (df["status"].isin(selected_status))
    & (df["username"].isin(selected_users))
].copy()

if ip_search:
    filtered_df = filtered_df[
        filtered_df["source_ip"].str.contains(
            ip_search,
            case=False,
            na=False
        )
    ]


# ==========================================
# KPI METRICS
# ==========================================

total_events = len(filtered_df)

total_alerts = (
    filtered_df["alert_status"] == "ALERT"
).sum()

critical_alerts = (
    filtered_df["severity"] == "CRITICAL"
).sum()

high_alerts = (
    filtered_df["severity"] == "HIGH"
).sum()

medium_alerts = (
    filtered_df["severity"] == "MEDIUM"
).sum()

failed_logins = (
    filtered_df["status"] == "failed"
).sum()

unique_ips = filtered_df["source_ip"].nunique()

st.markdown("## Security Overview")

c1, c2, c3, c4 = st.columns(4)

c1.metric(
    "Total Security Events",
    f"{total_events:,}"
)

c2.metric(
    "Total Threat Alerts",
    f"{total_alerts:,}"
)

c3.metric(
    "Critical Alerts",
    f"{critical_alerts:,}"
)

c4.metric(
    "Failed Logins",
    f"{failed_logins:,}"
)

c5, c6, c7, c8 = st.columns(4)

c5.metric(
    "High Severity",
    high_alerts
)

c6.metric(
    "Medium Severity",
    medium_alerts
)

c7.metric(
    "Monitored IPs",
    unique_ips
)

c8.metric(
    "ML Flagged Events",
    int(filtered_df["ml_prediction"].sum())
)

st.divider()


# ==========================================
# SEVERITY DISTRIBUTION
# ==========================================

st.markdown("## Threat Severity Analysis")

col1, col2 = st.columns(2)

severity_counts = (
    filtered_df["severity"]
    .value_counts()
    .reindex(severity_options, fill_value=0)
    .reset_index()
)

severity_counts.columns = ["Severity", "Count"]

with col1:

    fig_severity = px.pie(
        severity_counts,
        names="Severity",
        values="Count",
        hole=0.55,
        title="Security Event Severity Distribution",
        color="Severity",
        color_discrete_map={
            "CRITICAL": "#EF4444",
            "HIGH": "#F97316",
            "MEDIUM": "#EAB308",
            "LOW": "#22C55E"
        }
    )

    fig_severity.update_layout(
        template="plotly_dark",
        paper_bgcolor="#080D18",
        plot_bgcolor="#080D18",
        font_color="#E5E7EB"
    )

    st.plotly_chart(
        fig_severity,
        use_container_width=True
    )


# ==========================================
# LOGIN ACTIVITY CHART
# ==========================================

with col2:

    login_counts = (
        filtered_df.assign(
            hour_bucket=filtered_df["timestamp"].dt.floor("h")
        )
        .groupby(
            ["hour_bucket", "status"]
        )
        .size()
        .reset_index(name="events")
    )

    fig_activity = px.line(
        login_counts,
        x="hour_bucket",
        y="events",
        color="status",
        markers=True,
        title="Login Activity Timeline",
        color_discrete_map={
            "success": "#22C55E",
            "failed": "#EF4444"
        }
    )

    fig_activity.update_layout(
        template="plotly_dark",
        paper_bgcolor="#080D18",
        plot_bgcolor="#080D18",
        font_color="#E5E7EB",
        xaxis_title="Time",
        yaxis_title="Number of Events"
    )

    st.plotly_chart(
        fig_activity,
        use_container_width=True
    )


st.divider()


# ==========================================
# SUSPICIOUS IP ANALYSIS
# ==========================================

st.markdown("## 🌐 Suspicious IP Intelligence")

suspicious_df = filtered_df[
    filtered_df["severity"].isin(
        ["CRITICAL", "HIGH", "MEDIUM"]
    )
]

if not suspicious_df.empty:

    ip_summary = (
        suspicious_df.groupby("source_ip")
        .agg(
            Total_Alerts=("source_ip", "size"),
            Affected_Users=("username", "nunique"),
            Failed_Attempts=("is_failed", "sum"),
            Max_Severity=("severity", "first")
        )
        .reset_index()
        .sort_values(
            "Total_Alerts",
            ascending=False
        )
    )

    st.dataframe(
        ip_summary,
        use_container_width=True,
        hide_index=True
    )

else:

    st.success("No suspicious IP activity in current filters.")


st.divider()


# ==========================================
# AI THREAT PREDICTIONS
# ==========================================

st.markdown("## 🤖 AI Threat Detection Results")

ai_alerts = filtered_df[
    filtered_df["ml_prediction"] == 1
].copy()

if not ai_alerts.empty:

    ai_display = ai_alerts[
        [
            "timestamp",
            "username",
            "source_ip",
            "status",
            "ml_confidence",
            "severity"
        ]
    ].sort_values(
        "ml_confidence",
        ascending=False
    )

    st.dataframe(
        ai_display,
        use_container_width=True,
        hide_index=True,
        column_config={
            "ml_confidence": st.column_config.ProgressColumn(
                "Model probability",
                format="%.1f%%",
                min_value=0,
                max_value=100
            )
        }
    )

else:

    st.success("No ML-flagged events in current filters.")


st.divider()


# ==========================================
# SECURITY EVENT LOGS
# ==========================================

st.markdown("## 📋 Security Event Explorer")

st.caption(
    "Search, inspect and investigate individual authentication events."
)

search_user = st.text_input(
    "Search username or source IP",
    placeholder="Search events..."
)

event_df = filtered_df.copy()

if search_user:

    mask = (
        event_df["username"].str.contains(
            search_user,
            case=False,
            na=False
        )
        |
        event_df["source_ip"].str.contains(
            search_user,
            case=False,
            na=False
        )
    )

    event_df = event_df[mask]

display_columns = [
    "timestamp",
    "username",
    "source_ip",
    "event_type",
    "status",
    "failed_attempts_10m",
    "ml_prediction",
    "ml_confidence",
    "severity",
    "alert_status"
]

st.dataframe(
    event_df[display_columns].sort_values(
        "timestamp",
        ascending=False
    ),
    use_container_width=True,
    hide_index=True,
    height=400
)


# ==========================================
# INCIDENT INVESTIGATION
# ==========================================

st.divider()

st.markdown("## 🔍 Incident Investigation")

if not event_df.empty:

    selected_index = st.selectbox(
        "Select an event to investigate",
        event_df.index,
        format_func=lambda i: (
            f"{event_df.loc[i, 'username']} | "
            f"{event_df.loc[i, 'source_ip']} | "
            f"{event_df.loc[i, 'severity']} | "
            f"{event_df.loc[i, 'timestamp']}"
        )
    )

    incident = event_df.loc[selected_index]

    a, b = st.columns(2)

    with a:

        st.markdown("### Event Details")

        st.write("**Username:**", incident["username"])
        st.write("**Source IP:**", incident["source_ip"])
        st.write("**Timestamp:**", incident["timestamp"])
        st.write("**Login status:**", incident["status"])
        st.write("**Severity:**", incident["severity"])

    with b:

        st.markdown("### Detection Evidence")

        st.write(
            "**Previous failed attempts from IP:**",
            int(incident["failed_attempts_10m"])
        )

        st.write(
            "**Previous failed attempts for user:**",
            int(incident["user_failed_attempts_10m"])
        )

        st.write(
            "**ML prediction:**",
            "Suspicious" if incident["ml_prediction"] == 1
            else "Normal"
        )

        st.write(
            "**ML probability:**",
            f"{incident['ml_confidence']:.2f}%"
        )

    st.markdown("### Recommended Investigation Actions")

    if incident["severity"] in ["CRITICAL", "HIGH"]:

        st.warning(
            "Investigate immediately. Review authentication logs, "
            "validate the affected account, and check the source IP. "
            "Consider containment according to your incident response policy."
        )

    elif incident["severity"] == "MEDIUM":

        st.info(
            "Review the login history, compare the activity with "
            "normal user behavior, and verify whether the event is legitimate."
        )

    else:

        st.success(
            "No current detection rule or ML alert has flagged this event. "
            "Continue normal monitoring."
        )

else:

    st.info("No events available for the current filters.")


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "AI-Powered SOC Alert Triage System | "
    "Python + Streamlit + Random Forest + Plotly"
)

st.caption(
    "Educational simulation using synthetic security logs. "
    "ML predictions are experimental and require analyst validation."
)
