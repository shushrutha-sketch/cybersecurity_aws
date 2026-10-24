"""
AccessGuard AI - SaaS Access Risk & Permission Drift Detection
Backend API (Flask REST)

What this project does (from the reference document)
----------------------------------------------------
1. Problem:  Employees collect SaaS access as their roles change. Old or excessive
             permissions go unnoticed and put company data at risk.
2. MVP:      Use AI to look at consented SaaS roles, permissions, access history and
             usage patterns, find excessive / outdated / anomalous access, and give
             explainable early warnings with permissions to review or revoke.
3. AWS architecture - ONE tool per module (simple, no overlap):
       SaaS Data Ingestion & Integration ........ Amazon AppFlow
       Data Storage & Log Analytics ............. Amazon S3
       AI Permission Drift & Anomaly Detection .. Amazon SageMaker
       Explainable AI & Remediation ............. Amazon Bedrock
       Alerting & Automated Remediation ......... Amazon EventBridge
       Security, Identity & Audit ............... AWS CloudTrail
4. Expected outcome (and where this file delivers it):
       - Continuous, automated oversight ........ /api/employees recalculates live; the dashboard auto-refreshes
       - Early warnings before a breach ......... risk engine + /api/ai-explain
       - Redundant / risky access found ......... calculate_employee_risk()
       - Less manual audit work ................. one-click /api/remediate and what-if /api/simulate
       - Immutable audit trail .................. hash-chained log, verified by /api/audit/verify
       - Automated zero-trust revocation ........ /api/remediate (removes admin, unused and drifted access)

NOTE: This is a prototype. The AWS services are represented by fictional demo data and
labels; nothing here calls AWS. Each place where a real service plugs in is marked.
"""
import boto3
import os
import copy
import json
import hashlib
import datetime
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # lets the HTML dashboard talk to this API
# AWS S3 configuration
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
S3_BUCKET_NAME = os.getenv(
    "S3_BUCKET_NAME",
    "accessguard-audit-demo-2026"
)

s3_client = boto3.client(
    "s3",
    region_name=AWS_REGION
)
def save_audit_entry_to_s3(entry):
    timestamp = datetime.datetime.now(
        datetime.timezone.utc
    ).strftime("%Y%m%dT%H%M%S%fZ")

    key = f"audit-logs/{timestamp}-{entry['id']}.json"

    s3_client.put_object(
        Bucket=S3_BUCKET_NAME,
        Key=key,
        Body=json.dumps(
            entry, ensure_ascii=False, indent=2
        ).encode("utf-8"),
        ContentType="application/json"
    )

    return key

# ==============================================================================
# AWS ARCHITECTURE - exactly ONE tool per module
# ==============================================================================
AWS_ARCHITECTURE_SPEC = {
    "problem_statement": {
        "title": "SaaS Access Risk & Permission Drift Detection",
        "description": (
            "Organizations increasingly rely on multiple SaaS platforms, where employees "
            "may accumulate access privileges as they change roles, projects, or responsibilities. "
            "Over time, outdated or excessive permissions can remain unnoticed, increasing "
            "the risk of unauthorized access to sensitive organizational data."
        )
    },
    "mvp": {
        "title": "Minimum Viable Product (MVP)",
        "description": (
            "Build a tool that uses AI to analyze consented SaaS user roles, permissions, "
            "access history, and usage patterns to identify excessive, outdated, or anomalous access, "
            "and provide explainable early warnings with recommendations for permissions "
            "that should be reviewed or revoked."
        )
    },
    "modules": [
        {
            "id": "ingestion",
            "module": "SaaS Data Ingestion & Integration",
            "tool": "Amazon AppFlow",
            "purpose": "Pulls user roles, permissions and activity logs from SaaS apps (for example Salesforce, Slack, Zendesk) on a schedule, with no custom connector code."
        },
        {
            "id": "storage",
            "module": "Data Storage & Log Analytics",
            "tool": "Amazon S3",
            "purpose": "Stores all ingested access data in one encrypted, durable data lake that the AI models and auditors read from."
        },
        {
            "id": "ai_detection",
            "module": "AI Permission Drift & Anomaly Detection",
            "tool": "Amazon SageMaker",
            "purpose": "Trains and runs the models that compare each person with their peer group to spot drifted roles and unusual usage."
        },
        {
            "id": "explainable_ai",
            "module": "Explainable AI & Remediation Recommendation",
            "tool": "Amazon Bedrock",
            "purpose": "Turns raw findings into plain-English early warnings and a clear list of permissions to review or revoke."
        },
        {
            "id": "alerting",
            "module": "Alerting & Automated Remediation",
            "tool": "Amazon EventBridge",
            "purpose": "Routes every high-risk finding as an event to notify the security team and to trigger the automatic access revocation."
        },
        {
            "id": "security_audit",
            "module": "Security, Identity & Audit",
            "tool": "AWS CloudTrail",
            "purpose": "Records every scan and every revocation in a tamper-proof audit trail for compliance."
        }
    ],
    "expected_outcome": (
        "The implementation of this AI-driven platform will deliver continuous, automated oversight "
        "across multi-SaaS environments, successfully mitigating permission drift and privilege creep. "
        "By combining real-time log ingestion with generative AI recommendations, security teams receive "
        "clear, contextualized early warnings regarding redundant or risky access privileges before they "
        "lead to data breaches. The platform significantly reduces manual security audit overhead, guarantees "
        "compliance through immutable audit trails, and enables automated, zero-trust access revocations - ensuring "
        "least-privilege enforcement across the organization."
    )
}

# The six tools, in module order (used by the health check and the tests)
AWS_TOOLS = [m["tool"] for m in AWS_ARCHITECTURE_SPEC["modules"]]

# ==============================================================================
# FICTIONAL DEMO DATASET (consented SaaS roles, permissions, access history, usage)
# In production: Amazon AppFlow pulls this from the SaaS apps into Amazon S3.
# ==============================================================================
INITIAL_EMPLOYEES = [
    {
        "id": "EMP-001",
        "name": "Bob Martinez",
        "email": "bob.martinez@example.com",
        "department": "Marketing",
        "title": "Contract Content Writer",
        "avatar": "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150&auto=format&fit=crop&q=80",
        "mfa_enabled": False,
        "last_login_days": 114,
        "saas_accounts": ["Salesforce", "AWS IAM", "Snowflake", "Slack"],
        "assigned_roles": ["Salesforce System Admin", "AWS ReadOnlyAccess", "Snowflake Financial Data Reader"],
        "consented_roles": [
            {"service": "Salesforce", "role": "System Administrator", "consent_date": "2024-03-15", "status": "Outdated (Contract Changed)"},
            {"service": "Snowflake", "role": "Financial Ledger Reader", "consent_date": "2024-03-20", "status": "Excessive Scope"},
            {"service": "AWS IAM", "role": "Production Read", "consent_date": "2024-04-10", "status": "Residual Access"},
            {"service": "Slack", "role": "Standard Member", "consent_date": "2024-03-15", "status": "Legitimate"}
        ],
        "permissions": [
            {"service": "Salesforce", "privilege": "System Administrator", "is_admin": True, "sensitive": True},
            {"service": "AWS IAM", "privilege": "Production Read", "is_admin": False, "sensitive": True},
            {"service": "Snowflake", "privilege": "Financial Ledger Query", "is_admin": False, "sensitive": True},
            {"service": "Slack", "privilege": "Standard Member", "is_admin": False, "sensitive": False}
        ],
        "access_history": [
            {"timestamp": "2026-10-14 02:15:00 UTC", "service": "Snowflake", "action": "SELECT * FROM corporate_ledger_2026", "anomaly": True},
            {"timestamp": "2026-09-20 23:40:00 UTC", "service": "Salesforce", "action": "Export User Identity Metadata", "anomaly": True},
            {"timestamp": "2026-07-01 11:30:00 UTC", "service": "Slack", "action": "Channel Read #marketing", "anomaly": False}
        ],
        "usage_patterns": {
            "anomaly_score": 92,
            "status": "Severe Anomaly",
            "details": "Amazon SageMaker anomaly model detected high-volume financial data queries that are unusual for the Marketing Writer peer group.",
            "off_hours_activity": True,
            "dormant_scopes_count": 2
        },
        "drift_detected": True,
        "drift_summary": "Former Marketing Intern retained Salesforce Super Admin and Snowflake Financial DB access after contract change 90 days ago.",
        "previous_role": "Marketing Tech Intern (2024)",
        "joined_date": "2024-03-15"
    },
    {
        "id": "EMP-002",
        "name": "Sarah Jenkins",
        "email": "sarah.j@contractor-example.com",
        "department": "Engineering",
        "title": "Former QA Contractor",
        "avatar": "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=150&auto=format&fit=crop&q=80",
        "mfa_enabled": True,
        "last_login_days": 18,
        "saas_accounts": ["GitHub", "Jira", "AWS IAM"],
        "assigned_roles": ["GitHub Org Owner", "Jira Project Lead", "AWS Staging Deployer"],
        "consented_roles": [
            {"service": "GitHub", "role": "Organization Owner", "consent_date": "2024-08-01", "status": "Outdated (Contract Expired)"},
            {"service": "Jira", "role": "Project Admin", "consent_date": "2024-08-01", "status": "Excessive"},
            {"service": "AWS IAM", "role": "Staging Deployment Role", "consent_date": "2024-08-15", "status": "Pending Revocation"}
        ],
        "permissions": [
            {"service": "GitHub", "privilege": "Organization Owner (Full Admin)", "is_admin": True, "sensitive": True},
            {"service": "Jira", "privilege": "Project Admin", "is_admin": True, "sensitive": False},
            {"service": "AWS IAM", "privilege": "Staging Deployment Role", "is_admin": False, "sensitive": True}
        ],
        "access_history": [
            {"timestamp": "2026-10-18 09:10:00 UTC", "service": "GitHub", "action": "Repository Admin Settings Read", "anomaly": True},
            {"timestamp": "2026-10-05 14:22:00 UTC", "service": "Jira", "action": "Sprint Board View", "anomaly": False}
        ],
        "usage_patterns": {
            "anomaly_score": 78,
            "status": "Outdated Contract Activity",
            "details": "Amazon SageMaker anomaly model flagged GitHub Org Owner API activity 14 days after contract termination.",
            "off_hours_activity": False,
            "dormant_scopes_count": 1
        },
        "drift_detected": True,
        "drift_summary": "Contract completed 14 days ago, but user still holds GitHub Organization Owner privileges.",
        "previous_role": "Lead QA Consultant",
        "joined_date": "2024-08-01"
    },
    {
        "id": "EMP-003",
        "name": "Marcus Vance",
        "email": "marcus.vance@example.com",
        "department": "Sales",
        "title": "VP of Global Sales",
        "avatar": "https://images.unsplash.com/photo-1570295999919-56ceb5ecca61?w=150&auto=format&fit=crop&q=80",
        "mfa_enabled": True,
        "last_login_days": 2,
        "saas_accounts": ["Salesforce", "AWS IAM", "Google Workspace"],
        "assigned_roles": ["Salesforce Sales Lead", "AWS IAM AdministratorAccess"],
        "consented_roles": [
            {"service": "Salesforce", "role": "Enterprise Sales Admin", "consent_date": "2022-01-10", "status": "Legitimate"},
            {"service": "AWS IAM", "role": "AdministratorAccess (Root Equivalent)", "consent_date": "2022-01-10", "status": "Toxic Combination"},
            {"service": "Google Workspace", "role": "Standard User", "consent_date": "2022-01-10", "status": "Legitimate"}
        ],
        "permissions": [
            {"service": "Salesforce", "privilege": "Enterprise Sales Admin", "is_admin": True, "sensitive": False},
            {"service": "AWS IAM", "privilege": "AdministratorAccess (Root Equivalent)", "is_admin": True, "sensitive": True},
            {"service": "Google Workspace", "privilege": "Standard User", "is_admin": False, "sensitive": False}
        ],
        "access_history": [
            {"timestamp": "2026-10-22 17:00:00 UTC", "service": "Salesforce", "action": "Pipeline Opportunity Closed-Won Update", "anomaly": False},
            {"timestamp": "2026-06-12 11:00:00 UTC", "service": "AWS IAM", "action": "IAM Console Login (Zero Infrastructure Actions)", "anomaly": True}
        ],
        "usage_patterns": {
            "anomaly_score": 82,
            "status": "Excessive Cloud Admin",
            "details": "AWS CloudTrail audit records indicate zero deployment activities in 180 days, yet identity holds root AdministratorAccess.",
            "off_hours_activity": False,
            "dormant_scopes_count": 1
        },
        "drift_detected": True,
        "drift_summary": "Retained early-stage startup AWS AdministratorAccess granted in 2022 despite working solely in Sales leadership.",
        "previous_role": "Founding Business Lead (2022)",
        "joined_date": "2022-01-10"
    },
    {
        "id": "EMP-004",
        "name": "David Kim",
        "email": "david.kim@example.com",
        "department": "Engineering",
        "title": "Senior Backend Engineer",
        "avatar": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&auto=format&fit=crop&q=80",
        "mfa_enabled": True,
        "last_login_days": 1,
        "saas_accounts": ["AWS IAM", "GitHub", "Datadog", "PagerDuty"],
        "assigned_roles": ["AWS PowerUser", "GitHub Write", "Datadog Read"],
        "consented_roles": [
            {"service": "AWS IAM", "role": "PowerUserAccess", "consent_date": "2023-06-15", "status": "Least Privilege Aligned"},
            {"service": "GitHub", "role": "Repository Write", "consent_date": "2023-06-15", "status": "Legitimate"},
            {"service": "Datadog", "role": "APM Read Only", "consent_date": "2023-06-15", "status": "Legitimate"}
        ],
        "permissions": [
            {"service": "AWS IAM", "privilege": "PowerUserAccess", "is_admin": False, "sensitive": True},
            {"service": "GitHub", "privilege": "Repository Write", "is_admin": False, "sensitive": False},
            {"service": "Datadog", "privilege": "APM Read Only", "is_admin": False, "sensitive": False}
        ],
        "access_history": [
            {"timestamp": "2026-10-23 10:15:00 UTC", "service": "GitHub", "action": "git push origin feat/api-gateway", "anomaly": False},
            {"timestamp": "2026-10-23 11:00:00 UTC", "service": "AWS IAM", "action": "DescribeLogStreams", "anomaly": False}
        ],
        "usage_patterns": {
            "anomaly_score": 8,
            "status": "Normal Usage Pattern",
            "details": "Routine Git commits and CloudWatch queries strictly aligned with Backend Engineer peer group in Amazon SageMaker.",
            "off_hours_activity": False,
            "dormant_scopes_count": 0
        },
        "drift_detected": False,
        "drift_summary": "Permissions properly aligned with active engineering sprint needs.",
        "previous_role": "Backend Engineer",
        "joined_date": "2023-06-15"
    },
    {
        "id": "EMP-005",
        "name": "Elena Rostova",
        "email": "elena.rostova@example.com",
        "department": "Human Resources",
        "title": "HR Operations Specialist",
        "avatar": "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80",
        "mfa_enabled": True,
        "last_login_days": 3,
        "saas_accounts": ["Workday", "Okta", "Google Workspace"],
        "assigned_roles": ["Workday People Lead", "Okta Standard User"],
        "consented_roles": [
            {"service": "Workday", "role": "Employee Directory Admin", "consent_date": "2023-11-01", "status": "Legitimate"},
            {"service": "Okta", "role": "End User Portal", "consent_date": "2023-11-01", "status": "Legitimate"},
            {"service": "Google Workspace", "role": "Standard Member", "consent_date": "2023-11-01", "status": "Legitimate"}
        ],
        "permissions": [
            {"service": "Workday", "privilege": "Employee Directory Admin", "is_admin": False, "sensitive": True},
            {"service": "Okta", "privilege": "End User Portal", "is_admin": False, "sensitive": False},
            {"service": "Google Workspace", "privilege": "Standard Member", "is_admin": False, "sensitive": False}
        ],
        "access_history": [
            {"timestamp": "2026-10-20 14:00:00 UTC", "service": "Workday", "action": "Generate Monthly Onboarding Report", "anomaly": False}
        ],
        "usage_patterns": {
            "anomaly_score": 5,
            "status": "Normal Usage Pattern",
            "details": "Standard HR directory queries during working hours; zero cross-department access requests.",
            "off_hours_activity": False,
            "dormant_scopes_count": 0
        },
        "drift_detected": False,
        "drift_summary": "Least-privilege compliant. Standard HR departmental boundaries respected.",
        "previous_role": "HR Coordinator",
        "joined_date": "2023-11-01"
    },
    {
        "id": "EMP-006",
        "name": "Frank Castle",
        "email": "frank.c@example.com",
        "department": "Customer Support",
        "title": "Support Tier 1 Agent",
        "avatar": "https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=150&auto=format&fit=crop&q=80",
        "mfa_enabled": False,
        "last_login_days": 145,
        "saas_accounts": ["Zendesk", "Salesforce", "Google Workspace"],
        "assigned_roles": ["Zendesk Agent", "Salesforce Read"],
        "consented_roles": [
            {"service": "Zendesk", "role": "Agent Ticket Access", "consent_date": "2024-01-20", "status": "Dormant Scope"},
            {"service": "Salesforce", "role": "Lead Viewer", "consent_date": "2024-01-20", "status": "Dormant Scope"}
        ],
        "permissions": [
            {"service": "Zendesk", "privilege": "Agent Ticket Access", "is_admin": False, "sensitive": False},
            {"service": "Salesforce", "privilege": "Lead Viewer", "is_admin": False, "sensitive": False}
        ],
        "access_history": [
            {"timestamp": "2026-05-30 08:00:00 UTC", "service": "Zendesk", "action": "Ticket Resolution #1043", "anomaly": False}
        ],
        "usage_patterns": {
            "anomaly_score": 68,
            "status": "Dormant / Stale Account",
            "details": "Zero authentication events for 145 days. High credential-stuffing vulnerability without MFA.",
            "off_hours_activity": False,
            "dormant_scopes_count": 2
        },
        "drift_detected": False,
        "drift_summary": "Account appears dormant (>140 days without activity) and lacks Multi-Factor Authentication.",
        "previous_role": "Support Agent",
        "joined_date": "2024-01-20"
    }
]

# Historical Drift Audit Log (In production, recorded by AWS CloudTrail)
INITIAL_DRIFT_TIMELINE = [
    {
        "id": "LOG-101",
        "timestamp": "2026-10-21 16:45:00 UTC",
        "employee_id": "EMP-001",
        "employee_name": "Bob Martinez",
        "action": "Permission Drift Detected",
        "details": "Contract changed to Copywriter; Salesforce System Admin and Snowflake access were not offboarded.",
        "old_risk": 35,
        "new_risk": 92,
        "risk_delta": "+57",
        "severity": "CRITICAL",
        "aws_source": "Amazon SageMaker (role clustering)"
    },
    {
        "id": "LOG-102",
        "timestamp": "2026-10-18 09:12:00 UTC",
        "employee_id": "EMP-002",
        "employee_name": "Sarah Jenkins",
        "action": "Offboarding Incomplete",
        "details": "Contract ended on Oct 10; GitHub Organization Owner privilege still active.",
        "old_risk": 40,
        "new_risk": 85,
        "risk_delta": "+45",
        "severity": "CRITICAL",
        "aws_source": "Amazon SageMaker (anomaly model)"
    },
    {
        "id": "LOG-103",
        "timestamp": "2026-10-15 14:30:00 UTC",
        "employee_id": "EMP-003",
        "employee_name": "Marcus Vance",
        "action": "Excessive Privilege Flagged",
        "details": "VP of Sales detected with active AWS AdministratorAccess (Root equivalent).",
        "old_risk": 50,
        "new_risk": 78,
        "risk_delta": "+28",
        "severity": "HIGH",
        "aws_source": "Amazon SageMaker (peer comparison)"
    },
    {
        "id": "LOG-104",
        "timestamp": "2026-10-10 11:20:00 UTC",
        "employee_id": "EMP-006",
        "employee_name": "Frank Castle",
        "action": "Dormant Account Alert",
        "details": "User has not logged in for over 120 days. Multi-Factor Authentication is disabled.",
        "old_risk": 20,
        "new_risk": 65,
        "risk_delta": "+45",
        "severity": "HIGH",
        "aws_source": "Amazon S3 (access-log query)"
    },
    {
        "id": "LOG-105",
        "timestamp": "2026-09-28 08:00:00 UTC",
        "employee_id": "EMP-004",
        "employee_name": "David Kim",
        "action": "Routine Access Review",
        "details": "Quarterly engineering access review completed. Least privilege verified.",
        "old_risk": 25,
        "new_risk": 25,
        "risk_delta": "0",
        "severity": "LOW",
        "aws_source": "AWS CloudTrail (access review)"
    }
]

# ==============================================================================
# IN-MEMORY STORAGE (prototype only; production uses Amazon S3 + CloudTrail)
# ==============================================================================
employees_store = copy.deepcopy(INITIAL_EMPLOYEES)   # deep copy so demo data is never changed by accident

SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}

# ------------------------------------------------------------------------------
# TAMPER-PROOF AUDIT TRAIL
# Every entry stores the hash of the entry before it. Changing or deleting any old
# entry breaks the chain, and /api/audit/verify will report it.
# (In production, AWS CloudTrail provides this guarantee.)
# ------------------------------------------------------------------------------
def _hash_entry(entry, prev_hash):
    body = {k: v for k, v in entry.items() if k not in ("hash", "prev_hash")}
    payload = prev_hash + json.dumps(body, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def _seal_chain(entries_newest_first):
    prev = "GENESIS"
    for entry in reversed(entries_newest_first):      # oldest first
        entry["prev_hash"] = prev
        entry["hash"] = _hash_entry(entry, prev)
        prev = entry["hash"]

audit_log = copy.deepcopy(INITIAL_DRIFT_TIMELINE)    # newest entry first
_seal_chain(audit_log)


def add_audit_entry(entry):
    """Adds a new entry to the audit trail and saves a copy to S3."""
    prev = audit_log[0]["hash"] if audit_log else "GENESIS"
    entry["id"] = f"LOG-{len(audit_log) + 101}"
    entry["prev_hash"] = prev
    entry["hash"] = _hash_entry(entry, prev)
    audit_log.insert(0, entry)

    try:
        key = save_audit_entry_to_s3(entry)
        app.logger.info("Audit entry saved to S3: %s", key)
    except Exception:
        app.logger.exception("Failed to save audit entry to S3")

    return entry

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def find_employee(emp_id):
    for emp in employees_store:
        if emp["id"].upper() == str(emp_id or "").upper():
            return emp
    return None

# ==============================================================================
# RISK ENGINE (rule-based, so every score can be explained)
# Looks at: roles, permissions, access history and usage patterns, then flags
# EXCESSIVE, OUTDATED, REDUNDANT or ANOMALOUS access.
# Production: the anomaly score comes from an Amazon SageMaker model.
# ==============================================================================
def find_unused_permissions(emp):
    """Admin/sensitive permissions with no activity at all in the access history = redundant."""
    used_services = {h["service"] for h in emp.get("access_history", [])}
    return [
        p for p in emp.get("permissions", [])
        if (p.get("is_admin") or p.get("sensitive")) and p["service"] not in used_services
    ]

def calculate_employee_risk(emp):
    score = 0
    findings = []
    to_review = []

    def add_finding(category, severity, points, tool, description, remediation):
        findings.append({
            "category": category, "severity": severity, "score_impact": f"+{points}",
            "aws_tool": tool, "description": description, "remediation": remediation
        })

    # 1. OUTDATED: account not used for 90+ days
    days_inactive = emp.get("last_login_days", 0)
    if days_inactive >= 90:
        points = 35 if days_inactive >= 120 else 25
        score += points
        add_finding(
            "Outdated / Stale Access", "CRITICAL" if days_inactive >= 120 else "HIGH", points,
            "Amazon S3 (access logs)",
            f"Account has been inactive for {days_inactive} days (limit: 90 days).",
            "Suspend the account, or require the user to re-authenticate."
        )
        to_review += [f"{p['service']} - {p['privilege']} (Inactive account)" for p in emp.get("permissions", [])]

    # 2. WEAK LOGIN: no MFA
    if not emp.get("mfa_enabled", True):
        score += 25
        add_finding(
            "No Multi-Factor Authentication", "HIGH", 25, "AWS CloudTrail (login logs)",
            "Multi-Factor Authentication (MFA) is turned off for this user's SaaS accounts.",
            "Enforce MFA through your single sign-on provider."
        )

    # 3. OUTDATED: roles left over from a previous job (permission drift)
    if emp.get("drift_detected", False):
        score += 25
        add_finding(
            "Permission Drift", "CRITICAL", 25, "Amazon SageMaker (role clustering)",
            f"Leftover privileges from an earlier role: {emp.get('drift_summary')}",
            "Remove the leftover roles and keep only what the current job needs."
        )
        to_review += [f"{p['service']} - {p['privilege']} (Leftover role)"
                      for p in emp.get("permissions", []) if p.get("is_admin") or p.get("sensitive")]

    # 4. EXCESSIVE: administrator rights
    admins = [p for p in emp.get("permissions", []) if p.get("is_admin")]
    if admins:
        points = min(len(admins) * 15, 30)
        score += points
        add_finding(
            "Excessive Privilege", "HIGH", points, "Amazon SageMaker (peer comparison)",
            f"Holds {len(admins)} administrator role(s) across SaaS apps.",
            "Downgrade to a standard role, or grant admin rights only when needed (just-in-time)."
        )
        to_review += [f"{p['service']} - {p['privilege']} (Excessive admin)" for p in admins]

    # 5. EXCESSIVE: non-technical team holding cloud admin rights
    if emp.get("department", "").lower() in ["marketing", "sales", "customer support", "human resources", "finance", "legal"]:
        for p in emp.get("permissions", []):
            if ("AWS" in p.get("service", "") or "Cloud" in p.get("service", "")) and p.get("is_admin", False):
                score += 15
                add_finding(
                    "Toxic Combination", "CRITICAL", 15, "Amazon SageMaker (peer comparison)",
                    f"A {emp.get('department')} employee holds cloud infrastructure admin access.",
                    "Remove the cloud admin role; give a read-only reporting role if needed."
                )
                to_review.append(f"{p['service']} - {p['privilege']} (Toxic combination)")
                break

    # 6. REDUNDANT: sensitive/admin access that is never used
    unused = find_unused_permissions(emp)
    if unused:
        score += 10
        add_finding(
            "Redundant Access", "MEDIUM", 10, "Amazon S3 (access logs)",
            "Sensitive access with no activity in the access history: "
            + ", ".join(f"{p['service']} ({p['privilege']})" for p in unused) + ".",
            "Remove access that is not being used."
        )
        to_review += [f"{p['service']} - {p['privilege']} (Never used)" for p in unused]

    # 7. ANOMALOUS: unusual behaviour compared with peers
    usage = emp.get("usage_patterns", {})
    anomaly = usage.get("anomaly_score", 0)
    if anomaly >= 70:
        score += 20
        add_finding(
            "Anomalous Usage Pattern", "CRITICAL" if anomaly >= 85 else "HIGH", 20,
            "Amazon SageMaker (anomaly model)",
            f"Anomaly score {anomaly}/100. {usage.get('details')}",
            "Review the recent activity and restrict the unusual access."
        )

    final = max(5, min(100, score))
    if final >= 80:   tier, color = "CRITICAL", "red"
    elif final >= 60: tier, color = "HIGH", "orange"
    elif final >= 35: tier, color = "MEDIUM", "yellow"
    else:             tier, color = "LOW", "green"

    return {
        "risk_score": final,
        "risk_tier": tier,
        "risk_color": color,
        "findings": findings,
        "permissions_to_review_or_revoke": list(dict.fromkeys(to_review))
    }

def enrich_employee(emp):
    """Returns the employee plus a freshly calculated risk assessment."""
    enriched = dict(emp)
    enriched.update(calculate_employee_risk(emp))
    return enriched

# ==============================================================================
# LEAST-PRIVILEGE ENGINE
# One function used by BOTH the what-if simulator (on a copy) and the real
# remediation (on live data), so they always agree.
# ==============================================================================
def apply_least_privilege(emp, revoke_admin=False, resolve_drift=False,
                          enable_mfa=False, remove_unused=False):
    """Changes `emp` in place and returns a plain-English list of what was changed."""
    changes = []
    access_changed = False

    if remove_unused:
        unused = find_unused_permissions(emp)
        unused_ids = {id(p) for p in unused}
        for p in unused:
            changes.append(f"{p['service']}: removed unused access ({p['privilege']})")
        emp["permissions"] = [p for p in emp.get("permissions", []) if id(p) not in unused_ids]
        access_changed = access_changed or bool(unused)

    if revoke_admin:
        for p in emp.get("permissions", []):
            if p.get("is_admin"):
                changes.append(f"{p['service']}: removed administrator rights")
                p["is_admin"] = False
                p["privilege"] = "Standard User (Least Privilege)"
                access_changed = True

    if resolve_drift and emp.get("drift_detected"):
        emp["drift_detected"] = False
        emp["drift_summary"] = "Remediated: leftover roles removed by least-privilege policy."
        changes.append("Leftover roles from the previous job cleaned up")
        access_changed = True

    if enable_mfa and not emp.get("mfa_enabled"):
        emp["mfa_enabled"] = True
        changes.append("Multi-Factor Authentication enforced")

    if access_changed and "usage_patterns" in emp:      # risky access is gone, so activity is normal again
        emp["usage_patterns"]["anomaly_score"] = min(emp["usage_patterns"].get("anomaly_score", 0), 15)
        emp["usage_patterns"]["status"] = "Normal Usage Pattern"

    return changes

# What each remediation "action" does
REMEDIATION_ACTIONS = {
    "full_least_privilege": dict(revoke_admin=True, resolve_drift=True, enable_mfa=True, remove_unused=True),
    "revoke_admin":         dict(revoke_admin=True),
    "resolve_drift":        dict(resolve_drift=True),
    "enable_mfa":           dict(enable_mfa=True),
    "remove_unused":        dict(remove_unused=True),
}

# ==============================================================================
# SUPPORTED SAAS INTEGRATIONS (Expanded SaaS Catalog)
# In production: Amazon AppFlow ingests data from these SaaS connectors
# ==============================================================================
SUPPORTED_SAAS_INTEGRATIONS = [
    {
        "id": "salesforce",
        "name": "Salesforce",
        "category": "CRM & Enterprise Sales",
        "icon": "cloud",
        "color": "sky",
        "connector_status": "Active (Amazon AppFlow Ingestion)",
        "description": "Enterprise customer data, opportunities, and executive pipeline governance.",
        "available_roles": [
            {"role": "System Administrator", "is_admin": True, "sensitive": True, "description": "Full org metadata & user administration"},
            {"role": "Enterprise Sales Admin", "is_admin": True, "sensitive": False, "description": "Pipeline modification & revenue contracts"},
            {"role": "Financial Ledger Reader", "is_admin": False, "sensitive": True, "description": "Access to closed-won revenue ledger"},
            {"role": "Standard User", "is_admin": False, "sensitive": False, "description": "Routine business opportunity read/write"}
        ]
    },
    {
        "id": "aws_iam",
        "name": "AWS IAM",
        "category": "Cloud Infrastructure",
        "icon": "server",
        "color": "amber",
        "connector_status": "Active (AWS Lambda Ingestion)",
        "description": "Cloud infrastructure roles, policies, and root-equivalent credentials.",
        "available_roles": [
            {"role": "AdministratorAccess (Root Equivalent)", "is_admin": True, "sensitive": True, "description": "Full unmetered cloud control across all AWS accounts"},
            {"role": "PowerUserAccess", "is_admin": False, "sensitive": True, "description": "Full access to AWS services without IAM user creation"},
            {"role": "Staging Deployment Role", "is_admin": False, "sensitive": True, "description": "Deploy infrastructure pipelines to non-production envs"},
            {"role": "Production Read", "is_admin": False, "sensitive": True, "description": "Read-only access to production workloads and telemetry"},
            {"role": "ReadOnlyAccess", "is_admin": False, "sensitive": False, "description": "Auditor console viewing role"}
        ]
    },
    {
        "id": "github",
        "name": "GitHub Enterprise",
        "category": "Source Code & CI/CD",
        "icon": "git-pull-request",
        "color": "purple",
        "connector_status": "Active (AppFlow Webhook Stream)",
        "description": "Source code repositories, automated CI/CD runners, and secret environments.",
        "available_roles": [
            {"role": "Organization Owner", "is_admin": True, "sensitive": True, "description": "Full administrative control of repositories, billing, and org secrets"},
            {"role": "Repository Admin", "is_admin": True, "sensitive": True, "description": "Branch protection overrides, collaborator management"},
            {"role": "Repository Write", "is_admin": False, "sensitive": False, "description": "Commit code and submit pull requests"},
            {"role": "Triage & Read", "is_admin": False, "sensitive": False, "description": "Issue tracker review and pull request discussion"}
        ]
    },
    {
        "id": "snowflake",
        "name": "Snowflake",
        "category": "Data Warehouse & Analytics",
        "icon": "database",
        "color": "cyan",
        "connector_status": "Active (Scheduled AppFlow Sync)",
        "description": "Centralized corporate data warehouse, customer financial transactions, and BI marts.",
        "available_roles": [
            {"role": "AccountAdmin", "is_admin": True, "sensitive": True, "description": "Top-level administrator across all databases and virtual warehouses"},
            {"role": "Financial Ledger Reader", "is_admin": False, "sensitive": True, "description": "Direct read access to audited corporate financial ledgers"},
            {"role": "Data Engineer", "is_admin": False, "sensitive": True, "description": "Create schemas, staging tables, and automated pipelines"},
            {"role": "Data Analyst (BI)", "is_admin": False, "sensitive": False, "description": "Query sanitized business marts and dashboard extracts"}
        ]
    },
    {
        "id": "okta",
        "name": "Okta",
        "category": "Identity & Access Management (IdP)",
        "icon": "key-round",
        "color": "blue",
        "connector_status": "Active (API Gateway Webhook)",
        "description": "Central enterprise single sign-on (SSO), multi-factor tokens, and lifecycle groups.",
        "available_roles": [
            {"role": "Super Administrator", "is_admin": True, "sensitive": True, "description": "Master identity management and SSO policy control"},
            {"role": "Application Admin", "is_admin": True, "sensitive": True, "description": "Assign and revoke user bindings to corporate applications"},
            {"role": "Help Desk Admin", "is_admin": False, "sensitive": False, "description": "Reset passwords and assist user authentication"},
            {"role": "End User Portal", "is_admin": False, "sensitive": False, "description": "Standard SSO app launcher dashboard"}
        ]
    },
    {
        "id": "google_workspace",
        "name": "Google Workspace",
        "category": "Productivity & Collaboration",
        "icon": "mail",
        "color": "emerald",
        "connector_status": "Active (Google Admin SDK AppFlow)",
        "description": "Corporate email, Drive confidential storage, calendar and identity directory.",
        "available_roles": [
            {"role": "Super Admin", "is_admin": True, "sensitive": True, "description": "Total control over corporate Gmail, Drive, Meet, and domain"},
            {"role": "User Management Admin", "is_admin": True, "sensitive": False, "description": "Create, suspend, and organize employee accounts"},
            {"role": "Drive Auditor", "is_admin": False, "sensitive": True, "description": "Audit file sharing and DLP violation events"},
            {"role": "Standard Member", "is_admin": False, "sensitive": False, "description": "Regular mailbox and document editing rights"}
        ]
    },
    {
        "id": "slack",
        "name": "Slack Enterprise Grid",
        "category": "Team Communications",
        "icon": "message-square",
        "color": "indigo",
        "connector_status": "Active (AppFlow Audit Event Ingestion)",
        "description": "Internal communication channels, executive boardrooms, and connected webhook bots.",
        "available_roles": [
            {"role": "Primary Org Owner", "is_admin": True, "sensitive": True, "description": "Full governance over workspace grid, data retention, and export"},
            {"role": "Channel Admin", "is_admin": False, "sensitive": False, "description": "Manage private channels and canvas documents"},
            {"role": "Standard Member", "is_admin": False, "sensitive": False, "description": "Regular internal team messaging and calls"},
            {"role": "Single-Channel Guest", "is_admin": False, "sensitive": False, "description": "External partner restricted to designated project channel"}
        ]
    },
    {
        "id": "jira",
        "name": "Jira Software",
        "category": "Project & Issue Tracking",
        "icon": "check-square",
        "color": "blue",
        "connector_status": "Active (Atlassian REST Webhook)",
        "description": "Software sprint backlogs, security vulnerability tickets, and roadmaps.",
        "available_roles": [
            {"role": "Jira System Admin", "is_admin": True, "sensitive": True, "description": "Manage global workflows, plugins, and custom schemes"},
            {"role": "Project Admin", "is_admin": True, "sensitive": False, "description": "Configure components, sprints, and permissions within a project"},
            {"role": "Standard Contributor", "is_admin": False, "sensitive": False, "description": "Create, assign, and transition work tickets"}
        ]
    },
    {
        "id": "servicenow",
        "name": "ServiceNow",
        "category": "ITSM & Enterprise Workflows",
        "icon": "layers",
        "color": "teal",
        "connector_status": "Active (AppFlow Connector)",
        "description": "Enterprise IT change management, production access requests, and incident tracking.",
        "available_roles": [
            {"role": "System Administrator", "is_admin": True, "sensitive": True, "description": "Scripting, schema modification, and security controls"},
            {"role": "ITIL Service Desk Agent", "is_admin": False, "sensitive": False, "description": "Fulfill incident, change, and catalog request records"},
            {"role": "Self-Service User", "is_admin": False, "sensitive": False, "description": "Submit support requests and view knowledge base"}
        ]
    },
    {
        "id": "datadog",
        "name": "Datadog",
        "category": "Cloud Observability & APM",
        "icon": "activity",
        "color": "violet",
        "connector_status": "Active (Datadog Audit API)",
        "description": "Application performance monitoring, log analytics, and production telemetry.",
        "available_roles": [
            {"role": "Datadog Admin", "is_admin": True, "sensitive": True, "description": "API key creation, billing, and monitor governance"},
            {"role": "Standard Engineer", "is_admin": False, "sensitive": False, "description": "Build dashboards, create monitors, inspect APM traces"},
            {"role": "APM Read Only", "is_admin": False, "sensitive": False, "description": "Inspect dashboards and alerts without editing capability"}
        ]
    },
    {
        "id": "zendesk",
        "name": "Zendesk",
        "category": "Customer Support Desk",
        "icon": "headphones",
        "color": "emerald",
        "connector_status": "Active (AppFlow Ingestion)",
        "description": "Customer support ticketing, user identities, and external communication records.",
        "available_roles": [
            {"role": "Account Administrator", "is_admin": True, "sensitive": True, "description": "Configure support channels, macros, and API credentials"},
            {"role": "Agent Ticket Access", "is_admin": False, "sensitive": False, "description": "Respond to tickets and update end-user profiles"},
            {"role": "Light Agent", "is_admin": False, "sensitive": False, "description": "Read-only ticket reviewer"}
        ]
    },
    {
        "id": "microsoft365",
        "name": "Microsoft 365 / Entra ID",
        "category": "Enterprise Productivity & Cloud Identity",
        "icon": "layout-grid",
        "color": "sky",
        "connector_status": "Active (Microsoft Graph API AppFlow)",
        "description": "Entra ID tenant, Exchange Online mail flow, Teams channels, and OneDrive DLP.",
        "available_roles": [
            {"role": "Global Administrator", "is_admin": True, "sensitive": True, "description": "Unfettered management across all M365 suites and Entra ID tenant"},
            {"role": "Exchange Admin", "is_admin": True, "sensitive": True, "description": "Manage mailboxes, DLP rules, and compliance mailflow"},
            {"role": "Teams Administrator", "is_admin": False, "sensitive": False, "description": "Manage calling policies, meeting settings, and channel apps"},
            {"role": "Standard Business User", "is_admin": False, "sensitive": False, "description": "Office apps, OneDrive, and corporate communications"}
        ]
    }
]

# ==============================================================================
# AUTHENTICATION & ZERO-TRUST IDENTITY PORTAL
# In production: Governed by AWS IAM Identity Center (SSO / MFA)
# ==============================================================================
DEMO_USERS = {
    "admin@accessguard.ai": {
        "id": "USR-ADMIN-01",
        "name": "Alex Vance",
        "email": "admin@accessguard.ai",
        "password": "CyberGuard2026!",
        "role": "Principal SecOps Engineer",
        "department": "Cybersecurity & IAM Governance",
        "avatar": "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80",
        "mfa_enforced": True,
        "sso_provider": "AWS IAM Identity Center (SSO)",
        "permissions": ["identity:read", "identity:write", "remediation:execute", "simulator:run", "audit:verify"]
    },
    "auditor@accessguard.ai": {
        "id": "USR-AUDIT-02",
        "name": "Diana Ross",
        "email": "auditor@accessguard.ai",
        "password": "AuditPass2026!",
        "role": "Lead Compliance Auditor",
        "department": "Security Assurance & SOC2",
        "avatar": "https://images.unsplash.com/photo-1580489944761-15a19d654956?w=150&auto=format&fit=crop&q=80",
        "mfa_enforced": True,
        "sso_provider": "Okta Enterprise IdP",
        "permissions": ["identity:read", "audit:verify", "simulator:run"]
    }
}

ACTIVE_TOKENS = {}

# ==============================================================================
# REST API
# ==============================================================================
@app.route("/api/health", methods=["GET"])
def health_check():
    """Is the backend running? Also lists the six AWS tools used."""
    return jsonify({
        "status": "online",
        "service": "AccessGuard AI Core Engine",
        "version": "1.1.0",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "aws_tools_active": AWS_TOOLS
    }), 200

@app.route("/api/aws-architecture", methods=["GET"])
def get_aws_architecture():
    """Problem statement, MVP, the 6 modules (one AWS tool each) and the expected outcome."""
    return jsonify(AWS_ARCHITECTURE_SPEC), 200

@app.route("/api/saas-integrations", methods=["GET"])
def get_saas_integrations():
    """Returns the catalog of supported SaaS integrations and their available roles."""
    return jsonify({
        "status": "success",
        "total_integrations": len(SUPPORTED_SAAS_INTEGRATIONS),
        "integrations": SUPPORTED_SAAS_INTEGRATIONS,
        "aws_ingestion_tool": "Amazon AppFlow + AWS Lambda"
    }), 200

@app.route("/api/employees", methods=["GET", "POST"])
def employees_collection():
    """GET: All identities with live risk scores, plus summary numbers.
    POST: Ingest a new identity with consented SaaS permissions (for demo)."""
    if request.method == "POST":
        data = request.get_json() or {}
        name = data.get("name", "").strip()
        if not name:
            return jsonify({"error": "Employee name is required."}), 400

        department = data.get("department", "Engineering").strip()
        title = data.get("title", "Associate").strip()

        # Generate next EMP-ID
        existing_nums = []
        for e in employees_store:
            parts = e["id"].split("-")
            if len(parts) == 2 and parts[1].isdigit():
                existing_nums.append(int(parts[1]))
        next_num = max(existing_nums, default=6) + 1
        emp_id = f"EMP-{next_num:03d}"

        email = data.get("email", "").strip() or f"{name.lower().replace(' ', '.')}@example.com"
        avatar = data.get("avatar", "").strip() or "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80"
        mfa_enabled = bool(data.get("mfa_enabled", True))
        last_login_days = int(data.get("last_login_days", 1))

        permissions = data.get("permissions", [])
        consented_roles = data.get("consented_roles", [])

        # Sync permissions and consented_roles if only one is provided
        if permissions and not consented_roles:
            consented_roles = [
                {
                    "service": p.get("service", "SaaS"),
                    "role": p.get("privilege", "Standard User"),
                    "consent_date": datetime.date.today().isoformat(),
                    "status": "Residual Access" if data.get("drift_detected") else "Legitimate"
                }
                for p in permissions
            ]
        elif consented_roles and not permissions:
            permissions = [
                {
                    "service": r.get("service", "SaaS"),
                    "privilege": r.get("role", "Standard User"),
                    "is_admin": any(kw in r.get("role", "").lower() for kw in ["admin", "owner", "root", "super"]),
                    "sensitive": any(kw in r.get("role", "").lower() for kw in ["admin", "owner", "root", "ledger", "staging", "sensitive"])
                }
                for r in consented_roles
            ]

        saas_accounts = data.get("saas_accounts")
        if not saas_accounts:
            saas_accounts = list(dict.fromkeys(
                [p["service"] for p in permissions] + [r["service"] for r in consented_roles]
            ))
            if not saas_accounts:
                saas_accounts = ["Salesforce"]

        drift_detected = bool(data.get("drift_detected", False))
        drift_summary = data.get("drift_summary", "").strip()
        if drift_detected and not drift_summary:
            drift_summary = f"Accumulated unneeded SaaS roles detected during cross-departmental transition."

        previous_role = data.get("previous_role", "").strip() or f"Former {title}"

        usage_patterns = data.get("usage_patterns", {})
        anomaly_score = int(usage_patterns.get("anomaly_score", data.get("anomaly_score", 10)))
        status = "Normal Usage Pattern" if anomaly_score < 70 else ("Severe Anomaly" if anomaly_score >= 85 else "Elevated Anomaly")

        usage_obj = {
            "anomaly_score": anomaly_score,
            "status": status,
            "details": usage_patterns.get("details", f"Amazon SageMaker peer model analyzed usage across {', '.join(saas_accounts)}."),
            "off_hours_activity": bool(data.get("off_hours_activity", False)),
            "dormant_scopes_count": int(data.get("dormant_scopes_count", 1 if last_login_days >= 90 else 0))
        }

        access_history = data.get("access_history", [])
        if not access_history:
            access_history = [
                {
                    "timestamp": utc_now(),
                    "service": saas_accounts[0] if saas_accounts else "Salesforce",
                    "action": "Identity Profile Sync via Amazon AppFlow",
                    "anomaly": anomaly_score >= 70
                }
            ]

        new_emp = {
            "id": emp_id,
            "name": name,
            "email": email,
            "department": department,
            "title": title,
            "avatar": avatar,
            "mfa_enabled": mfa_enabled,
            "last_login_days": last_login_days,
            "saas_accounts": saas_accounts,
            "assigned_roles": [r.get("role", "Role") for r in consented_roles],
            "consented_roles": consented_roles,
            "permissions": permissions,
            "access_history": access_history,
            "usage_patterns": usage_obj,
            "drift_detected": drift_detected,
            "drift_summary": drift_summary,
            "previous_role": previous_role,
            "joined_date": data.get("joined_date", datetime.date.today().isoformat())
        }

        # Calculate live risk assessment
        assessment = calculate_employee_risk(new_emp)
        new_emp.update(assessment)

        # Ingest into store
        employees_store.insert(0, new_emp)

        # Append to tamper-proof CloudTrail audit trail
        add_audit_entry({
            "timestamp": utc_now(),
            "employee_id": new_emp["id"],
            "employee_name": new_emp["name"],
            "action": "New Identity Ingested",
            "details": f"Ingested via Amazon AppFlow: {len(permissions)} permission(s) mapped across {', '.join(saas_accounts)}.",
            "old_risk": 0,
            "new_risk": assessment["risk_score"],
            "risk_delta": f"+{assessment['risk_score']}",
            "severity": assessment["risk_tier"],
            "aws_source": "Amazon AppFlow + Amazon S3 (Bronze Data Lake)"
        })

        return jsonify({
            "status": "success",
            "message": f"Successfully ingested {new_emp['name']} into SaaS Identity Governance Matrix.",
            "employee": enrich_employee(new_emp)
        }), 201

    # GET request
    people = [enrich_employee(e) for e in employees_store]
    total = len(people)
    return jsonify({
        "summary": {
            "total_identities": total,
            "critical_risk": sum(1 for e in people if e["risk_tier"] == "CRITICAL"),
            "high_risk": sum(1 for e in people if e["risk_tier"] == "HIGH"),
            "permission_drift_count": sum(1 for e in people if e.get("drift_detected")),
            "dormant_accounts": sum(1 for e in people if e.get("last_login_days", 0) >= 90),
            "anomalous_usage_count": sum(1 for e in people if e.get("usage_patterns", {}).get("anomaly_score", 0) >= 70),
            "avg_risk_score": round(sum(e["risk_score"] for e in people) / max(1, total), 1)
        },
        "employees": people
    }), 200

@app.route("/api/employees/reset", methods=["POST"])
def reset_employees():
    """Resets employees back to initial sample baseline."""
    global employees_store
    employees_store = copy.deepcopy(INITIAL_EMPLOYEES)
    add_audit_entry({
        "timestamp": utc_now(),
        "employee_id": "ALL",
        "employee_name": "SecOps Administrator",
        "action": "Demo Baseline Reset",
        "details": "Restored sample permission records to initial 6 identities.",
        "old_risk": 0,
        "new_risk": 0,
        "risk_delta": "0",
        "severity": "LOW",
        "aws_source": "AWS IAM Identity Center (Console Admin Action)"
    })
    return jsonify({
        "status": "success",
        "message": "Demo employees restored to initial sample baseline."
    }), 200

@app.route("/api/employees/<emp_id>", methods=["GET", "DELETE"])
def employee_by_id(emp_id):
    """GET: Full security profile of one person.
    DELETE: Remove identity from monitored catalog."""
    emp = find_employee(emp_id)
    if not emp:
        return jsonify({"error": f"Identity with ID '{emp_id}' not found."}), 404

    if request.method == "DELETE":
        employees_store.remove(emp)
        add_audit_entry({
            "timestamp": utc_now(),
            "employee_id": emp["id"],
            "employee_name": emp["name"],
            "action": "Identity Deprovisioned",
            "details": f"Identity {emp['name']} removed from monitored catalog.",
            "old_risk": emp.get("risk_score", 0),
            "new_risk": 0,
            "risk_delta": f"-{emp.get('risk_score', 0)}",
            "severity": "LOW",
            "aws_source": "AWS CloudTrail (deprovisioning event)"
        })
        return jsonify({"status": "success", "message": f"Identity {emp_id} deleted."}), 200
    """Full security profile of one person."""
    emp = find_employee(emp_id)
    if not emp:
        return jsonify({"error": f"Identity with ID '{emp_id}' not found."}), 404
    return jsonify({
        "employee": enrich_employee(emp),
        "audit_logs": [log for log in audit_log if log["employee_id"] == emp["id"]],
        "aws_telemetry": {
            "ingestion": "Amazon AppFlow",
            "storage": "Amazon S3",
            "detection": "Amazon SageMaker",
            "explanations": "Amazon Bedrock",
            "alerting": "Amazon EventBridge",
            "audit": "AWS CloudTrail"
        }
    }), 200

@app.route("/api/scan", methods=["POST"])
def run_scan():
    """On-demand scan: re-checks every identity and routes high-risk ones as alerts."""
    people = [enrich_employee(e) for e in employees_store]
    flagged = [e for e in people if e["risk_tier"] in ("CRITICAL", "HIGH")]
    now = utc_now()

    add_audit_entry({
        "timestamp": now, "employee_id": "ALL", "employee_name": "All identities",
        "action": "Security Scan Completed",
        "details": f"{len(people)} identities scanned, {len(flagged)} flagged as high exposure.",
        "old_risk": 0, "new_risk": 0, "risk_delta": "0", "severity": "LOW",
        "aws_source": "AWS CloudTrail (scan record)"
    })

    return jsonify({
        "status": "success",
        "message": f"Scan finished at {now}.",
        "scanned_identities": len(people),
        "flagged_identities": len(flagged),
        "timestamp": now,
        "aws_pipeline": {
            "ingestion": "Amazon AppFlow",
            "storage": "Amazon S3",
            "detection": "Amazon SageMaker",
            "alerting": "Amazon EventBridge",
            "audit": "AWS CloudTrail"
        },
        "critical_alerts": [
            {
                "employee_id": e["id"],
                "name": e["name"],
                "risk_score": e["risk_score"],
                "primary_finding": max(e["findings"], key=lambda f: SEVERITY_RANK[f["severity"]])["description"]
                                   if e["findings"] else "No critical issue"
            }
            for e in flagged
        ]
    }), 200

@app.route("/api/simulate", methods=["POST"])
def simulate_access_change():
    """WHAT-IF: shows the new risk score if changes were made. Never changes live data."""
    data = request.get_json() or {}
    if not data.get("employee_id"):
        return jsonify({"error": "employee_id is required."}), 400
    target = find_employee(data["employee_id"])
    if not target:
        return jsonify({"error": "Employee not found."}), 404

    baseline = enrich_employee(target)

    clone = copy.deepcopy(target)                       # work on a copy only
    changes = apply_least_privilege(
        clone,
        revoke_admin=data.get("revoke_admin", False),
        resolve_drift=data.get("resolve_drift", False),
        enable_mfa=data.get("enable_mfa", False),
        remove_unused=data.get("remove_unused", False),
    )
    if data.get("refresh_dormant"):
        clone["last_login_days"] = 1
        changes.append("Dormant credential renewed")
    if data.get("proposed_role"):
        clone["title"] = data["proposed_role"]
    simulated = enrich_employee(clone)

    reduction = baseline["risk_score"] - simulated["risk_score"]
    return jsonify({
        "simulation_mode": "Dry run - nothing was changed",
        "employee_id": target["id"],
        "employee_name": target["name"],
        "baseline": {"risk_score": baseline["risk_score"], "risk_tier": baseline["risk_tier"],
                     "findings_count": len(baseline["findings"]), "mfa_enabled": baseline["mfa_enabled"]},
        "simulated": {"risk_score": simulated["risk_score"], "risk_tier": simulated["risk_tier"],
                      "findings_count": len(simulated["findings"]), "mfa_enabled": simulated["mfa_enabled"]},
        "changes": changes,
        "risk_reduction_points": reduction,
        "risk_delta": f"-{reduction}" if reduction > 0 else f"+{abs(reduction)}",
        "recommendation": (
            f"Applying these changes lowers risk by {reduction} points "
            f"({baseline['risk_tier']} to {simulated['risk_tier']})."
            if reduction > 0 else "These changes would not reduce risk."
        )
    }), 200

@app.route("/api/drift-history", methods=["GET"])
def get_drift_history():
    """The audit trail (newest first). Each entry carries its hash link."""
    return jsonify({"timeline": audit_log}), 200

@app.route("/api/audit/verify", methods=["GET"])
def verify_audit_trail():
    """Re-calculates the hash chain to prove no audit entry was edited or removed."""
    prev = "GENESIS"
    for entry in reversed(audit_log):
        if entry.get("prev_hash") != prev or entry.get("hash") != _hash_entry(entry, prev):
            return jsonify({"intact": False, "entries_checked": len(audit_log),
                            "broken_at": entry["id"]}), 200
        prev = entry["hash"]
    return jsonify({"intact": True, "entries_checked": len(audit_log), "broken_at": None}), 200

@app.route("/api/ai-explain", methods=["POST"])
def ai_explain():
    """Plain-English early warning and action plan for one person.
    Production: the text is written by Amazon Bedrock from the same findings."""
    data = request.get_json() or {}
    emp = find_employee(data.get("employee_id"))
    if not emp:
        return jsonify({"error": "Employee not found."}), 404

    e = enrich_employee(emp)
    findings = sorted(e["findings"], key=lambda f: SEVERITY_RANK[f["severity"]], reverse=True)

    if not findings:
        warning = (f"No early warning for {e['name']}: access matches the {e['department']} role. "
                   f"Risk score {e['risk_score']}/100 ({e['risk_tier']}).")
        plan = ["No action needed. Keep monitoring."]
        breach_risk = "No risky access found."
    else:
        warning = (f"EARLY WARNING for {e['name']} ({e['title']}, {e['department']}): "
                   f"risk {e['risk_score']}/100 ({e['risk_tier']}). "
                   f"{len(findings)} issue(s): {', '.join(f['category'] for f in findings)}. "
                   f"Main cause: {findings[0]['description']}")
        steps = list(dict.fromkeys(f["remediation"] for f in findings))
        plan = [f"{i}. {s}" for i, s in enumerate(steps, 1)]
        if e["risk_tier"] in ("CRITICAL", "HIGH"):
            plan.append(f"{len(plan) + 1}. Use 'Automated Zero-Trust Revocation' to apply these fixes in one click.")
        services = list(dict.fromkeys(p["service"] for p in e["permissions"] if p.get("is_admin") or p.get("sensitive")))
        breach_risk = ("If this account were compromised, an attacker could reach: " + ", ".join(services) + "."
                       if services else "Limited exposure if compromised.")

    return jsonify({
        "employee_id": emp["id"],
        "employee_name": emp["name"],
        "early_warning": warning,
        "executive_summary": warning,
        "breach_risk_if_ignored": breach_risk,
        "findings_breakdown": findings,
        "permissions_to_review_or_revoke": e["permissions_to_review_or_revoke"],
        "recommended_action_plan": plan,
        "zero_trust_score": f"{100 - e['risk_score']}% Compliance",
        "aws_orchestration": {
            "explanations": "Amazon Bedrock",
            "alerting": "Amazon EventBridge",
            "audit": "AWS CloudTrail"
        }
    }), 200

@app.route("/api/remediate", methods=["POST"])
def remediate_access():
    """AUTOMATED ZERO-TRUST REVOCATION: really changes the stored access and logs it.
    Production: Amazon EventBridge triggers the revocation, AWS CloudTrail records it."""
    data = request.get_json() or {}
    action = data.get("action", "full_least_privilege")
    if action not in REMEDIATION_ACTIONS:
        return jsonify({"error": f"Unknown action. Use one of: {', '.join(REMEDIATION_ACTIONS)}."}), 400
    emp = find_employee(data.get("employee_id"))
    if not emp:
        return jsonify({"error": "Employee not found."}), 404

    baseline = enrich_employee(emp)
    changes = apply_least_privilege(emp, **REMEDIATION_ACTIONS[action])
    updated = enrich_employee(emp)
    reduction = baseline["risk_score"] - updated["risk_score"]

    entry = add_audit_entry({
        "timestamp": utc_now(),
        "employee_id": emp["id"],
        "employee_name": emp["name"],
        "action": "Automated Zero-Trust Revocation",
        "details": ("Changes: " + "; ".join(changes) + ".") if changes else "Access re-certified, nothing to remove.",
        "old_risk": baseline["risk_score"],
        "new_risk": updated["risk_score"],
        "risk_delta": f"-{reduction}" if reduction > 0 else "0",
        "severity": "LOW",
        "aws_source": "Amazon EventBridge (trigger) + AWS CloudTrail (record)"
    })

    return jsonify({
        "status": "success",
        "message": f"Least-privilege remediation completed for {emp['name']}.",
        "changes": changes,
        "baseline_risk": baseline["risk_score"],
        "new_risk": updated["risk_score"],
        "risk_reduction_points": reduction,
        "risk_delta": entry["risk_delta"],
        "audit_log_id": entry["id"],
        "aws_execution": {
            "trigger": "Amazon EventBridge",
            "audit_trail": "AWS CloudTrail"
        }
    }), 200

# ==============================================================================
# AUTHENTICATION API (AWS IAM Identity Center / SSO / Zero-Trust Portal)
# ==============================================================================
@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Authenticate via AWS IAM Identity Center SSO, Okta, or SecOps direct credentials."""
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    demo_role = data.get("demo_role", "").strip().lower()
    sso_provider = data.get("sso_provider", "").strip()

    if demo_role == "admin" or email == "admin@accessguard.ai":
        user_info = copy.deepcopy(DEMO_USERS["admin@accessguard.ai"])
    elif demo_role == "auditor" or email == "auditor@accessguard.ai":
        user_info = copy.deepcopy(DEMO_USERS["auditor@accessguard.ai"])
    elif sso_provider:
        user_info = {
            "id": "USR-SSO-99",
            "name": data.get("name") or "Corporate Identity User",
            "email": email or f"user@{sso_provider.lower().replace(' ', '')}.corp",
            "role": "Enterprise Security Analyst",
            "department": "InfoSec Engineering",
            "avatar": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&auto=format&fit=crop&q=80",
            "mfa_enforced": True,
            "sso_provider": sso_provider,
            "permissions": ["identity:read", "identity:write", "remediation:execute", "simulator:run", "audit:verify"]
        }
    elif email:
        username = email.split("@")[0].replace(".", " ").title()
        user_info = {
            "id": f"USR-{hashlib.md5(email.encode()).hexdigest()[:6].upper()}",
            "name": username,
            "email": email,
            "role": "Security Operations Specialist",
            "department": "SOC Operations",
            "avatar": "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150&auto=format&fit=crop&q=80",
            "mfa_enforced": True,
            "sso_provider": "AccessGuard Zero-Trust Portal",
            "permissions": ["identity:read", "identity:write", "remediation:execute", "simulator:run", "audit:verify"]
        }
    else:
        # Default fallback to Admin for pitch/demo simplicity
        user_info = copy.deepcopy(DEMO_USERS["admin@accessguard.ai"])

    token = f"ag-token-{hashlib.sha256((user_info['email'] + str(datetime.datetime.now())).encode()).hexdigest()[:24]}"
    ACTIVE_TOKENS[token] = {
        "user": user_info,
        "created_at": utc_now()
    }

    add_audit_entry({
        "timestamp": utc_now(),
        "employee_id": user_info["id"],
        "employee_name": user_info["name"],
        "action": "Admin Authentication Succeeded",
        "details": f"Zero-Trust MFA session authorized via {user_info.get('sso_provider', 'AWS IAM Identity Center')}.",
        "old_risk": 0,
        "new_risk": 0,
        "risk_delta": "0",
        "severity": "LOW",
        "aws_source": "AWS IAM Identity Center + CloudTrail"
    })

    return jsonify({
        "status": "success",
        "message": f"Authenticated successfully as {user_info['name']}.",
        "token": token,
        "user": user_info
    }), 200

@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    """Retrieve active authenticated administrator session profile."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    if not token:
        token = request.args.get("token", "")

    if token and token in ACTIVE_TOKENS:
        return jsonify({
            "authenticated": True,
            "user": ACTIVE_TOKENS[token]["user"]
        }), 200

    # Demo fallback: provide admin profile if requested
    return jsonify({
        "authenticated": False,
        "user": None,
        "message": "No active session found"
    }), 200

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """Terminates administrator session."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    if token and token in ACTIVE_TOKENS:
        del ACTIVE_TOKENS[token]
    return jsonify({
        "status": "success",
        "message": "Zero-Trust session terminated successfully."
    }), 200

# ==============================================================================
# STATIC FRONTEND SERVING
# Allows opening http://127.0.0.1:5000 directly or via browser file://
# ==============================================================================
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

@app.route("/", methods=["GET"])
def serve_index():
    if os.path.isfile(os.path.join(FRONTEND_DIR, "index.html")):
        return send_from_directory(FRONTEND_DIR, "index.html")
    elif os.path.isfile(os.path.join(FRONTEND_DIR, "index--.html")):
        return send_from_directory(FRONTEND_DIR, "index--.html")
    return jsonify({"service": "AccessGuard AI Backend", "frontend_status": "place index.html in frontend/"}), 200

@app.route("/<path:path>", methods=["GET"])
def serve_static(path):
    if path.startswith("api/"):
        return jsonify({"error": "Endpoint not found"}), 404
    file_path = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(file_path):
        return send_from_directory(FRONTEND_DIR, path)
    if os.path.isfile(os.path.join(FRONTEND_DIR, "index.html")):
        return send_from_directory(FRONTEND_DIR, "index.html")
    elif os.path.isfile(os.path.join(FRONTEND_DIR, "index--.html")):
        return send_from_directory(FRONTEND_DIR, "index--.html")
    return jsonify({"error": "File not found"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting AccessGuard AI backend on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
