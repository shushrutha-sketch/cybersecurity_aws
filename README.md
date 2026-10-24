# AccessGuard AI — SaaS Access Risk & Permission Drift Detection

[![Cybersecurity Track](https://img.shields.io/badge/Cybersecurity-SaaS%20Access%20Risk-blue.svg)]()
[![AWS Architecture](https://img.shields.io/badge/AWS-Bedrock%20%7C%20SageMaker%20%7C%20AppFlow%20%7C%20Security%20Hub-orange.svg)]()
[![Backend](https://img.shields.io/badge/Backend-Python%20%2F%20Flask-green.svg)]()
[![Frontend](https://img.shields.io/badge/Frontend-TailwindCSS%20Dashboard-06b6d4.svg)]()

> **AccessGuard AI** is an AI-driven Zero-Trust cybersecurity platform built to provide continuous, automated oversight across multi-SaaS environments, mitigating permission drift and privilege creep before outdated or excessive access leads to a breach.

---

## 1. Problem Statement

### SaaS Access Risk & Permission Drift Detection
Organizations increasingly rely on multiple SaaS platforms, where employees may accumulate access privileges as they change roles, projects, or responsibilities. Over time, outdated or excessive permissions can remain unnoticed, increasing the risk of unauthorized access to sensitive organizational data.

---

## 2. Minimum Viable Product (MVP)

Build a tool that uses AI to analyze consented SaaS user roles, permissions, access history, and usage patterns to identify excessive, outdated, or anomalous access, and provide explainable early warnings with recommendations for permissions that should be reviewed or revoked.

### Core Capabilities Built in AccessGuard AI:
1. **Consented SaaS User Roles & Permissions Tracking**: Continuous cataloging of OAuth scopes, group memberships, and role assignments across AWS IAM, Salesforce, GitHub, Snowflake, Okta, and Google Workspace.
2. **Access History & Usage Pattern Analytics**: Real-time anomaly scoring tracking deviation from peer group baselines, off-hours access, and dormancy.
3. **Automated Drift & Outdated Permission Detection**: Detection of residual privileges retained across department or contract transitions.
4. **Explainable AI Early Warnings (Amazon Bedrock)**: Plain-language, context-aware early warnings for security teams detailing risk blast radius and immediate action plans.
5. **Interactive "What-If" Access Simulator**: Zero-risk dry-run simulator allowing security teams to preview risk reductions before applying policy changes.
6. **Automated Zero-Trust Remediation**: One-click and event-driven revocation of unneeded permissions with immutable audit trail creation.

---

## 3. Suggested AWS Tools Architecture

The architecture maps strictly to the AWS Cybersecurity Reference Architecture defined in the specification:

| Module / Functional Area | Suggested AWS Tools | Architectural Role & Implementation Details |
| :--- | :--- | :--- |
| **SaaS Data Ingestion & Integration** | **Amazon AppFlow, AWS Lambda, Amazon API Gateway** | **Amazon AppFlow** securely ingests SaaS audit logs, roles, and event streams from Salesforce, Slack, GitHub, and ServiceNow. **Amazon API Gateway** receives real-time webhook events and REST API telemetry from connected SaaS identity providers, which **AWS Lambda** serverless functions preprocess, validate, and normalize. |
| **Data Storage & Log Analytics** | **Amazon S3, Amazon OpenSearch Service, Amazon Athena** | Normalized access logs and user role snapshots land in an encrypted **Amazon S3** data lake (Bronze/Silver/Gold tiers). **Amazon OpenSearch Service** indexes access events for sub-second search and dashboarding, while **Amazon Athena** enables ad-hoc interactive SQL queries across multi-terabyte historical SaaS audit logs. |
| **AI Permission Drift & Anomaly Detection** | **Amazon SageMaker, Amazon Lookout for Metrics, AWS Glue** | **AWS Glue** orchestrates automated ETL pipelines and maintains the centralized data catalog of multi-SaaS identities. **Amazon SageMaker** runs unsupervised clustering and role-mining models to detect permission drift against department peer baselines. **Amazon Lookout for Metrics** continuously inspects usage patterns to flag anomalous access spikes, unusual off-hours calls, or dormant accounts. |
| **Explainable AI & Remediation Recommendation** | **Amazon Bedrock, AWS Step Functions** | **Amazon Bedrock** (utilizing high-performance foundation models such as Anthropic Claude 3 and Amazon Titan) analyzes enriched findings to produce explainable early warnings and contextualized least-privilege recommendations. **AWS Step Functions** orchestrates multi-step remediation state machines, human-in-the-loop approval workflows, and automated rollback logic. |
| **Alerting & Automated Remediation** | **Amazon EventBridge, Amazon Simple Notification Service (SNS), AWS Security Hub** | **Amazon EventBridge** serves as the central event bus routing high-severity permission drift and anomaly findings. **Amazon SNS** distributes real-time notifications to security operations engineers via Slack/Email/PagerDuty. **AWS Security Hub** aggregates posture findings and triggers automated zero-trust least-privilege revocations across connected SaaS accounts. |
| **Security, Identity & Audit** | **AWS IAM Identity Center, AWS Key Management Service (KMS), AWS CloudTrail** | **AWS IAM Identity Center** governs centralized single sign-on (SSO), multi-factor authentication (MFA), and directory integration. **AWS KMS** enforces customer-managed envelope encryption across all ingested SaaS logs, data stores, and Bedrock prompts. **AWS CloudTrail** captures tamper-proof, immutable audit logs of all administrative actions and automated revocations. |

### End-to-End AWS Architecture Flowchart

```
[ Multi-SaaS Platforms ] (Salesforce, GitHub, Okta, Slack, Google Workspace, Snowflake)
           │
           ▼ (Webhooks & Scheduled Pulls)
[ Amazon API Gateway + Amazon AppFlow + AWS Lambda ]  <-- SaaS Data Ingestion & Integration
           │
           ▼
[ Amazon S3 (Encrypted via AWS KMS) ]  <-- Data Storage & Log Analytics
      │                        │
      ▼                        ▼
[ Amazon OpenSearch Service ]   [ Amazon Athena (SQL Analytics) ]
      │                        │
      ▼                        ▼
[ AWS Glue (ETL & Catalog) ] ──▶ [ Amazon SageMaker & Amazon Lookout for Metrics ]
                                    (AI Permission Drift & Anomaly Usage Detection)
                                                │
                                                ▼
                                 [ AWS Step Functions (Orchestration) ]
                                                │
                                                ▼
                                 [ Amazon Bedrock (Explainable GenAI Warnings) ]
                                                │
                                                ▼
                                 [ Amazon EventBridge (Event Bus) ]
                                    │                     │
                                    ▼                     ▼
                    [ Amazon SNS (Alerts) ]    [ AWS Security Hub (Automated Remediation) ]
                                    │                     │
                                    └──────────┬──────────┘
                                               ▼
            [ AWS IAM Identity Center (SSO/MFA) ] & [ AWS CloudTrail (Immutable Audit) ]
```

---

## 4. Expected Outcome

> **The implementation of this AI-driven platform will deliver continuous, automated oversight across multi-SaaS environments, successfully mitigating permission drift and privilege creep. By combining real-time log ingestion with generative AI recommendations, security teams receive clear, contextualized early warnings regarding redundant or risky access privileges before they lead to data breaches. The platform significantly reduces manual security audit overhead, guarantees compliance through immutable audit trails, and enables automated, zero-trust access revocations—ensuring least-privilege enforcement across the organization.**

---

## 🛡️ Rule-Based & AI Cybersecurity Risk Engine

AccessGuard AI pairs unsupervised machine learning anomaly detection with a transparent, explainable scoring engine (0 = Safe, 100 = Critical Exposure):

| Risk Factor | Trigger Condition | Impact | Rationale | AWS Tool Alignment |
| :--- | :--- | :---: | :--- | :--- |
| **Dormant / Stale Access** | Inactivity &ge; 90 days | **+25 to +35** | Dormant accounts represent silent entry points for credential stuffing. | Amazon Lookout for Metrics & Athena |
| **Authentication Hygiene** | MFA Disabled | **+25** | Single-factor accounts lack basic Zero-Trust identity defenses. | AWS IAM Identity Center |
| **Permission Drift** | Accumulated residual roles post-transfer | **+25** | Former interns/contractors retain elevated rights across SaaS tools. | Amazon SageMaker & AWS Glue |
| **Excessive Administrator Privileges** | Holds Super Admin / Root roles | **+15 per role** | Breaches the Principle of Least Privilege (PoLP). | AWS Security Hub |
| **Toxic Combination** | Non-tech role holding Cloud Infrastructure Admin | **+15** | Cross-department blast radius risk. | Amazon Bedrock & Step Functions |
| **Anomalous Usage Pattern** | Anomaly score &gt; 70 | **+20** | Abnormal data access volume or uncharacteristic API calls. | Amazon Lookout for Metrics |

### Risk Tiers
- **CRITICAL (80 - 100)**: Immediate blast radius risk. Early warning triggered; automated revocation recommended.
- **HIGH (60 - 79)**: Excessive administrative rights or dormant credentials without MFA.
- **MEDIUM (35 - 59)**: Minor role drift or slight departmental boundary overlap.
- **LOW (0 - 34)**: Aligned with current role under Least-Privilege principles.

---

## 🔮 What-If Access Simulator

The **What-If Access Simulator** allows security administrators to model the impact of access remediation *before* executing changes in production:
1. Select any identity (e.g., *Bob Martinez* with a baseline score of **95 - Critical**).
2. Configure proposed changes:
   - [x] Revoke SaaS Administrator Privileges
   - [x] Remediate Accumulated Role Drift
   - [x] Enforce Multi-Factor Authentication (AWS IAM Identity Center)
   - [x] Renew Dormant Inactive Credential
3. Click **"Simulate Risk Impact"**.
4. The system calculates the projected score (e.g., drops to **25**, a **-70 point risk reduction**).
5. **Safe Mode Guarantee**: Dry-run simulation operates with zero impact on production accounts until explicitly committed.

---

## 🚀 Quick Start (Running Locally)

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Run the Automated Test Suite
```powershell
python backend/test_backend.py
```
*(All 20 unit and integration tests run in milliseconds)*

### 3. Start the Flask Backend API
```powershell
python backend/app.py
```
The API server starts on `http://127.0.0.1:5000` (and serves the frontend automatically!).

### 4. Open the Frontend Dashboard
Navigate to `http://127.0.0.1:5000` in your browser, or open `frontend/index.html` directly:
```powershell
start frontend/index.html
```

---

## 📡 REST API Reference

| Endpoint | Method | Description | AWS Tools Emulated / Integrated |
| :--- | :--- | :--- | :--- |
| `/api/health` | `GET` | Service status, engine version, and AWS integration state | AWS Lambda / CloudWatch |
| `/api/aws-architecture`| `GET` | Returns full 6-module AWS architecture matrix and tools from specification | AWS Architecture Blueprint |
| `/api/auth/login` | `POST` | Authenticates administrator via AWS IAM Identity Center SSO, Okta, or direct SecOps credentials | AWS IAM Identity Center |
| `/api/auth/me` | `GET` | Retrieves active authenticated administrator session profile and permissions | AWS IAM Identity Center |
| `/api/auth/logout` | `POST` | Terminates active administrator session | AWS IAM Identity Center |
| `/api/saas-integrations`| `GET` | Returns full catalog of 12 supported SaaS platforms and their privilege roles | Amazon AppFlow & AWS Lambda |
| `/api/employees` | `GET` | Returns all SaaS identities, consented roles, access history, and usage patterns | AppFlow, S3, OpenSearch, Lookout for Metrics |
| `/api/employees` | `POST` | Ingests new identity with custom SaaS consented permissions (demo feature) | Amazon AppFlow & S3 Bronze Data Lake |
| `/api/employees/reset` | `POST` | Restores dataset back to pristine initial sample permission records | AWS IAM Identity Center Console Action |
| `/api/employees/<id>` | `GET` | Detailed security profile, permission graph, and historical audit logs | Athena, CloudTrail |
| `/api/employees/<id>` | `DELETE`| Deprovisions monitored identity from catalog with immutable audit logging | AWS CloudTrail Deprovisioning |
| `/api/scan` | `POST` | Triggers on-demand discovery across connected SaaS APIs | AppFlow, Lambda, API Gateway |
| `/api/simulate` | `POST` | Models What-If remediation scenarios with projected risk delta | SageMaker, Bedrock |
| `/api/drift-history` | `GET` | Chronological audit trail of permission drift events | CloudTrail, KMS |
| `/api/ai-explain` | `POST` | Generates Bedrock-powered contextual early warnings and action plans | Amazon Bedrock, AWS Step Functions |
| `/api/remediate` | `POST` | Executes automated least-privilege revocation with CloudTrail logging | AWS Security Hub, EventBridge, SNS |
