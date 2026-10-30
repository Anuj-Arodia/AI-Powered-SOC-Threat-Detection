# AI-Powered SOC Alert Triage & Threat Detection System

An AI-powered Security Operations Center (SOC) simulation built with Python, Machine Learning, and Streamlit to analyze authentication logs, identify suspicious activity, detect potential brute-force attacks, and support security alert investigation.

## Project Overview

Security Operations Center (SOC) analysts handle large volumes of security events and need to identify suspicious activities efficiently.

This project demonstrates how machine learning and rule-based detection can help automate the initial analysis and prioritization of authentication events.

The application analyzes simulated authentication logs, identifies potentially suspicious login patterns, assigns alert severity, and presents the results through an interactive SOC dashboard.

## Key Features

- **Authentication Log Analysis:** Processes structured authentication logs containing timestamps, usernames, source IP addresses, event types, and login statuses.
- **Brute-Force Detection:** Uses rule-based detection to identify repeated failed login attempts.
- **Machine Learning Detection:** Uses a Random Forest classifier to identify potentially suspicious authentication activity.
- **Alert Severity Classification:** Categorizes events into LOW, MEDIUM, HIGH, and CRITICAL severity levels.
- **SOC Dashboard:** Displays security KPIs, login activity, suspicious IP addresses, and AI-generated predictions.
- **Interactive Investigation:** Allows analysts to filter events and investigate suspicious authentication activity.
- **Incident Recommendations:** Provides suggested investigation and response actions.
- **Report Export:** Exports security events and threat alerts in CSV format and generates PDF security reports.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Pandas | Log processing and data analysis |
| Scikit-learn | Machine learning |
| Random Forest | Suspicious activity classification |
| Streamlit | Interactive SOC dashboard |
| Plotly | Data visualization |
| Joblib | Model serialization |
| ReportLab | PDF report generation |
| NumPy | Numerical operations |

## Project Structure

```text
AI-SOC-Detection/
│
├── data/
│   ├── security_logs.csv
│   └── soc_model.joblib
│
├── app.py
├── detector.py
├── generate_logs.py
├── requirements.txt
├── README.md
└── .gitignore
```

## How It Works

1. **Log Generation:** Generates a simulated authentication dataset containing normal and suspicious login events.
2. **Feature Engineering:** Extracts useful features such as failed login counts, login timestamps, and IP-related information.
3. **Rule-Based Detection:** Identifies repeated failed authentication attempts.
4. **Machine Learning:** Trains a Random Forest classifier to classify potentially suspicious events.
5. **Alert Prioritization:** Assigns severity levels based on detection rules and model predictions.
6. **Dashboard Visualization:** Displays security events, alerts, and investigation information.
7. **Report Generation:** Allows users to export filtered logs and security reports.

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd AI-SOC-Detection
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

### 3. Activate the environment

For macOS/Linux:

```bash
source venv/bin/activate
```

For Windows:

```bash
venv\Scripts\activate
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Generate the authentication dataset

```bash
python generate_logs.py
```

### 6. Train the detection model

```bash
python detector.py
```

### 7. Launch the SOC dashboard

```bash
streamlit run app.py
```

Open the local URL displayed in your terminal, usually:

```text
http://localhost:8501
```

## Detection Capabilities

The project demonstrates detection of:

- Repeated failed authentication attempts
- Potential brute-force activity
- Suspicious successful authentication events
- Unusual authentication patterns
- Potentially suspicious source IP activity

## Machine Learning

The project uses a Random Forest classification model implemented through Scikit-learn.

The model is trained using engineered authentication features and evaluated using:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix

**Note:** The current dataset is simulated. Evaluation results on synthetic data should not be interpreted as real-world SOC detection performance.

## Future Improvements

- Integrate Wazuh SIEM for real-time log collection.
- Ingest Windows Event Logs and Linux authentication logs.
- Add IP reputation and threat intelligence feeds.
- Implement chronological model evaluation.
- Add explainable AI for alert investigation.
- Introduce email or Telegram security alerts.
- Build an incident management workflow.

## Disclaimer

This project is developed for educational and portfolio purposes. It uses simulated authentication logs and is not intended to replace an enterprise SIEM or production SOC monitoring platform.

All generated alerts should be validated by a security analyst before taking action.

## Author

**Anuj Arodia**

Cybersecurity Enthusiast | Aspiring SOC Analyst

