#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Athena SOC - Concise Google Workspace Report
--------------------------------------------
Same design as reports_sophos.py: exception-focused, risk-rated, with an
Athena-AI narrative (rule-based fallback) and prioritized recommendations.

Reads Google Workspace audit events that the Ageleia sync service feeds into
Wazuh (wazuh-alerts-*, data.integration = google-workspace):
  - detections          rule group gws_detection (privilege grants, suspicious
                        sign-ins, external sharing, mass download, 2SV off, ...)
  - sign-in failures    rule 100804
  - admin / config      Admin console activity (user, group, role, setting changes)
  - OAuth app grants    token events, excluding the collector's own grants
  - collection health   sync heartbeats (last seen, errors, failed applications)

Usage:
  python3 reports_gworkspace.py daily
  python3 reports_gworkspace.py weekly
  python3 reports_gworkspace.py monthly
  python3 reports_gworkspace.py custom 2026-11-01T00:00:00Z 2026-11-13T23:59:59Z

Test without email:
  REPORT_GWORKSPACE_SEND_EMAIL=false REPORT_GWORKSPACE_SAVE_OUTPUT=true \
    python3 reports_gworkspace.py daily
"""

import html
import json
# BUILD: GWS-CONCISE-V1 - mirrors SOC-CONCISE-V6 logic of reports_sophos.py
import os
import smtplib
import sys
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is optional; plain environment variables still work
    def load_dotenv(*_args, **_kwargs):
        return False

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
load_dotenv(os.path.join(SCRIPT_DIR, ".env"))
load_dotenv()

# -----------------------------------------------------------------------------
# General configuration
# -----------------------------------------------------------------------------
ATHENA_NAME = os.getenv("ATHENA_NAME", "Athena SOC")
TENANT_NAME = os.getenv("TENANT_NAME", "test.athenasecuritygrp.com")

REPORT_GWORKSPACE_ENABLED = os.getenv("REPORT_GWORKSPACE_ENABLED", "true").lower() == "true"
REPORT_GWORKSPACE_SEND_EMAIL = os.getenv("REPORT_GWORKSPACE_SEND_EMAIL", "true").lower() == "true"
REPORT_GWORKSPACE_SAVE_OUTPUT = os.getenv("REPORT_GWORKSPACE_SAVE_OUTPUT", "false").lower() == "true"
REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", os.path.join(SCRIPT_DIR, "generated_reports"))
REPORT_VERSION = "GWS-CONCISE-2026.11.13-v1"
MAX_DETAIL_ROWS = max(1, int(os.getenv("GWS_MAX_DETAIL_ROWS", "10")))
GWS_FAILED_LOGIN_THRESHOLD = max(1, int(os.getenv("GWS_FAILED_LOGIN_THRESHOLD", "5")))
GWS_SYNC_STALE_MINUTES = max(5, int(os.getenv("GWS_SYNC_STALE_MINUTES", "30")))

# -----------------------------------------------------------------------------
# SMTP
# -----------------------------------------------------------------------------
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME)
SMTP_RECIPIENT = [v.strip() for v in os.getenv("SMTP_RECIPIENT", "").split(",") if v.strip()]

# -----------------------------------------------------------------------------
# OpenSearch
# -----------------------------------------------------------------------------
ES_HOST = os.getenv("ES_HOST", "https://localhost:9200").rstrip("/")
ES_USERNAME = os.getenv("ES_USERNAME", "admin")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
ES_VERIFY_SSL = os.getenv("ES_VERIFY_SSL", "false").lower() == "true"
ES_QUERY_TIMEOUT = int(os.getenv("ES_QUERY_TIMEOUT", "60"))
ES_INDEX_GWS = os.getenv("ES_INDEX_PATTERN_GWORKSPACE", "wazuh-alerts-*")

# Google reports the real event time; the alert timestamp can lag (first sync ingests history at once).
GWS_TIME_FIELD = os.getenv("GWORKSPACE_TIME_FIELD", "data.gws.event_time")
# Extra OAuth client ids / targets to ignore (the collector's own client id is detected automatically).
GWS_IGNORE_TARGETS = [v.strip() for v in os.getenv("GWORKSPACE_IGNORE_TARGETS", "").split(",") if v.strip()]

# -----------------------------------------------------------------------------
# Athena-AI
# -----------------------------------------------------------------------------
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://router.huggingface.co/v1").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-ai/DeepSeek-V3.1-Terminus")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"
HF_ORG_NAME = os.getenv("HF_ORG_NAME", "").strip()
LLM_CHAT_URL = f"{LLM_BASE_URL}/chat/completions"

LOG_FILE = os.path.join(SCRIPT_DIR, "logs", "gworkspace_reporting.log")


def log(message):
    now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
    line = f"{now}: {message}\n"
    print(line, end="")
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(line)
    except Exception:
        pass


class ReportConfigurationError(RuntimeError):
    pass


class ReportDataError(RuntimeError):
    pass


# -----------------------------------------------------------------------------
# OpenSearch helpers
# -----------------------------------------------------------------------------
def es_request(method, path, payload=None, params=None):
    import requests
    import urllib3
    from requests.auth import HTTPBasicAuth

    if not ES_VERIFY_SSL:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        response = requests.request(
            method,
            f"{ES_HOST}/{path.lstrip('/')}",
            params=params,
            json=payload,
            auth=HTTPBasicAuth(ES_USERNAME, ES_PASSWORD) if ES_USERNAME or ES_PASSWORD else None,
            verify=ES_VERIFY_SSL,
            timeout=ES_QUERY_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ReportDataError(f"OpenSearch request failed for {path}: {exc}") from exc
    if not 200 <= response.status_code < 300:
        raise ReportDataError(f"OpenSearch request failed for {path}: {response.status_code} - {response.text[:500]}")
    try:
        result = response.json()
    except ValueError as exc:
        raise ReportDataError(f"OpenSearch returned invalid JSON for {path}") from exc
    if not isinstance(result, dict):
        raise ReportDataError(f"OpenSearch returned an unexpected response for {path}")
    return result


def es_search(query):
    path = f"{ES_INDEX_GWS}/_search"
    result = es_request(
        "POST", path, payload=query,
        params={"ignore_unavailable": "true", "allow_no_indices": "true"},
    )
    if result.get("timed_out"):
        raise ReportDataError(f"OpenSearch request timed out for {path}")
    failed = as_int(result.get("_shards", {}).get("failed"))
    if failed > 0:
        raise ReportDataError(f"OpenSearch returned {failed} failed shard(s) for {path}")
    if not isinstance(result.get("hits"), dict):
        raise ReportDataError(f"OpenSearch response is missing search hits for {path}")
    return result


def total_hits(response):
    total = (response or {}).get("hits", {}).get("total", 0)
    if isinstance(total, dict):
        return int(total.get("value", 0) or 0)
    return int(total or 0)


def parse_hits(response):
    return [(hit.get("_source", {}) or {}) for hit in (response or {}).get("hits", {}).get("hits", [])]


def buckets(response, name):
    return [
        (b.get("key"), as_int(b.get("doc_count")))
        for b in ((response or {}).get("aggregations", {}).get(name, {}) or {}).get("buckets", [])
    ]


def lower(value):
    return str(value or "").strip().lower()


def as_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def parse_datetime(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError):
        return None


def format_timestamp(value):
    parsed = parse_datetime(value)
    if not parsed:
        return "N/A"
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def iso_z(value):
    """Normalise to the 2026-11-13T10:00:00.000Z form Google uses, so string range queries sort correctly."""
    parsed = parse_datetime(value)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z") if parsed else str(value)


def dig(record, *path):
    node = record
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def gws(record, *path):
    return dig(record, "data", "gws", *path)


# -----------------------------------------------------------------------------
# Severity and detection knowledge
# -----------------------------------------------------------------------------
def severity_rank(level):
    level = as_int(level)
    if level >= 12:
        return 4
    if level >= 9:
        return 3
    if level >= 7:
        return 2
    if level >= 1:
        return 1
    return 0


def severity_name(rank):
    return {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(rank, "Unknown")


# rule id -> (category, specific action)
DETECTION_ACTIONS = {
    "100810": ("signin_attack", "Confirm the account owner, reset the password, enforce 2-step verification, and block the source IP if it is not trusted."),
    "100811": ("signin_attack", "Contact the user to confirm the sign-in; if not recognised, reset the password, sign the user out everywhere, and review recent activity."),
    "100812": ("oauth", "Review the OAuth app in Admin console > Security > API controls and revoke access if it is not approved."),
    "100813": ("twosv", "Re-enable 2-step verification for the account and enforce it through the organisational policy."),
    "100820": ("sharing", "Confirm the external share with the document owner and restrict sharing if it was not intended."),
    "100821": ("exfil", "Contact the user about the bulk download; suspend the account and review Drive audit logs if it is unexpected."),
    "100822": ("sharing", "Disable the public link unless the owner confirms it is required."),
    "100830": ("privilege", "Verify the admin role assignment was approved through change control; revoke it immediately if not."),
    "100831": ("config", "Verify the security setting change was approved; restore the previous setting if not."),
    "100840": ("sharing", "Make the calendar private unless public sharing is business-approved."),
    "100850": ("mail_forward", "Disable the external auto-forwarding rule and review the mailbox for signs of compromise."),
    "100860": ("sharing", "Confirm the external group member is expected; remove them if not."),
    "100870": ("alert_center", "Investigate the matched Google security rule in the Alert Center and document the outcome."),
    "100880": ("device", "Have the user bring the device back into compliance or block its access until it is."),
}

CATEGORY_RECOMMENDATIONS = {
    "privilege": "Review every admin privilege change in the period against approved change requests and keep the number of super admins minimal.",
    "signin_attack": "Enforce 2-step verification for all users and reset credentials for accounts targeted by failed or suspicious sign-ins.",
    "oauth": "Audit third-party OAuth apps with broad Gmail or Drive scopes and allow only approved apps in API controls.",
    "twosv": "Enforce 2-step verification organisation-wide so it cannot be switched off by individual users.",
    "sharing": "Restrict external and public sharing in Drive, Calendar, and Groups to approved domains and teams.",
    "exfil": "Investigate bulk Drive downloads and consider data-loss-prevention rules for sensitive content.",
    "config": "Re-check the changed security settings against your baseline and restore any unapproved change.",
    "mail_forward": "Disable external auto-forwarding by policy and review affected mailboxes.",
    "alert_center": "Work the Google Alert Center items to closure and record the outcome.",
    "device": "Enforce device compliance before access to Workspace data is allowed.",
}


def detection_action(record):
    rule_id = str(dig(record, "rule", "id") or "")
    return DETECTION_ACTIONS.get(rule_id, ("other", "Investigate the finding, confirm it with the user or owner, and document the outcome."))


# -----------------------------------------------------------------------------
# Queries
# -----------------------------------------------------------------------------
GWS_ACTIVITY = [
    {"term": {"data.integration": "google-workspace"}},
    {"term": {"data.type": "gws_activity"}},
]
GWS_BEAT = [
    {"term": {"data.integration": "google-workspace"}},
    {"term": {"rule.groups": "gws_heartbeat"}},
]


def time_range(time_from, time_to):
    return {"range": {GWS_TIME_FIELD: {"gte": iso_z(time_from), "lte": iso_z(time_to)}}}


def detect_collector_targets():
    """The sync service's own OAuth grants show up as token events; find its client id from the heartbeat."""
    targets = list(GWS_IGNORE_TARGETS)
    try:
        response = es_search({
            "size": 1, "sort": [{"timestamp": "desc"}],
            "_source": ["data.sync.client_id"],
            "query": {"bool": {"filter": GWS_BEAT}},
        })
        for record in parse_hits(response):
            client_id = dig(record, "data", "sync", "client_id")
            if client_id:
                targets.append(str(client_id))
    except ReportDataError as exc:
        log(f"Warning: could not detect the collector client id: {exc}")
    return sorted(set(targets))


def base_filter(time_from, time_to, ignore_targets):
    query = {"bool": {"filter": GWS_ACTIVITY + [time_range(time_from, time_to)]}}
    if ignore_targets:
        query["bool"]["must_not"] = [
            {"terms": {"data.gws.target": ignore_targets}},
            {"term": {"data.gws.signals.own_sync": "true"}},
        ]
    else:
        query["bool"]["must_not"] = [{"term": {"data.gws.signals.own_sync": "true"}}]
    return query


def with_filter(base, extra):
    query = {"bool": {"filter": list(base["bool"]["filter"]) + extra}}
    if base["bool"].get("must_not"):
        query["bool"]["must_not"] = base["bool"]["must_not"]
    return query


def query_overview(base):
    response = es_search({
        "size": 0, "track_total_hits": True, "query": base,
        "aggs": {
            "apps": {"terms": {"field": "data.gws.application", "size": 12}},
            "outcomes": {"terms": {"field": "data.gws.outcome", "size": 5}},
            "users": {"cardinality": {"field": "data.gws.actor.email"}},
            "top_users": {"terms": {"field": "data.gws.actor.email", "size": 5}},
            "countries": {"terms": {"field": "GeoLocation.country_name", "size": 8}},
        },
    })
    return {
        "total": total_hits(response),
        "apps": buckets(response, "apps"),
        "outcomes": dict(buckets(response, "outcomes")),
        "active_users": as_int(response.get("aggregations", {}).get("users", {}).get("value")),
        "top_users": buckets(response, "top_users"),
        "countries": buckets(response, "countries"),
    }


def query_detections(base):
    response = es_search({
        "size": 200, "track_total_hits": True,
        "sort": [{"rule.level": "desc"}, {"timestamp": "desc"}],
        "_source": [
            "rule.id", "rule.level", "rule.description", "rule.groups", "rule.mitre.id", "timestamp",
            "data.gws.actor.email", "data.gws.target", "data.gws.ip_address", "data.gws.event_time",
            "data.gws.event_name", "GeoLocation.country_name",
        ],
        "query": with_filter(base, [{"term": {"rule.groups": "gws_detection"}}]),
    })
    records = parse_hits(response)
    counts = {4: 0, 3: 0, 2: 0, 1: 0}
    for record in records:
        rank = severity_rank(dig(record, "rule", "level"))
        counts[rank] = counts.get(rank, 0) + 1
    return {
        "total": total_hits(response),
        "records": records,
        "critical": counts[4],
        "high": counts[3],
        "medium": counts[2],
        "low": counts[1],
    }


def query_failed_logins(base):
    response = es_search({
        "size": 0, "track_total_hits": True,
        "query": with_filter(base, [{"term": {"data.gws.event_name": "login_failure"}}]),
        "aggs": {
            "users": {"terms": {"field": "data.gws.actor.email", "size": 10},
                      "aggs": {"ips": {"cardinality": {"field": "data.gws.ip_address"}},
                               "last": {"max": {"field": "timestamp"}}}},
            "ips": {"terms": {"field": "data.gws.ip_address", "size": 5}},
        },
    })
    users = []
    for bucket in (response.get("aggregations", {}).get("users", {}) or {}).get("buckets", []):
        users.append({
            "user": bucket.get("key"),
            "count": as_int(bucket.get("doc_count")),
            "ips": as_int((bucket.get("ips") or {}).get("value")),
            "last": (bucket.get("last") or {}).get("value_as_string"),
        })
    return {"total": total_hits(response), "users": users, "ips": buckets(response, "ips")}


def query_admin_changes(base):
    """Admin-console activity (users, groups, roles, settings), excluding read-only views."""
    response = es_search({
        "size": 0, "track_total_hits": True,
        "query": with_filter(base, [{"term": {"data.gws.application": "admin"}}]),
        "aggs": {
            "events": {"terms": {"field": "data.gws.event_name", "size": 12},
                       "aggs": {"actors": {"terms": {"field": "data.gws.actor.email", "size": 3}}}},
        },
    })
    changes = []
    for bucket in (response.get("aggregations", {}).get("events", {}) or {}).get("buckets", []):
        name = str(bucket.get("key") or "")
        if name.upper().endswith("_VIEW"):  # viewing the Alert Center is not a change
            continue
        actors = [a.get("key") for a in (bucket.get("actors") or {}).get("buckets", [])]
        changes.append({"event": name, "count": as_int(bucket.get("doc_count")), "actors": actors})
    return {"total": sum(item["count"] for item in changes), "changes": changes[:MAX_DETAIL_ROWS]}


def query_oauth_grants(base):
    response = es_search({
        "size": 0, "track_total_hits": True,
        "query": with_filter(base, [{"term": {"data.gws.application": "token"}},
                                    {"term": {"data.gws.event_name": "authorize"}}]),
        "aggs": {"apps": {"terms": {"field": "data.gws.target", "size": 5}}},
    })
    return {"total": total_hits(response), "apps": buckets(response, "apps")}


def query_sync_health(time_from, time_to):
    """Collection health: is the sync alive, and did any Workspace application fail to collect?"""
    latest = es_search({
        "size": 1, "sort": [{"timestamp": "desc"}],
        "_source": ["timestamp", "data.sync.status", "data.sync.error", "data.sync.failed_apps", "data.sync.apps"],
        "query": {"bool": {"filter": GWS_BEAT}},
    })
    errors = es_search({
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": GWS_BEAT + [
            {"term": {"rule.groups": "gws_sync_error"}},
            {"range": {"timestamp": {"gte": time_from, "lte": time_to, "format": "strict_date_optional_time"}}},
        ]}},
    })
    records = parse_hits(latest)
    health = {"seen": bool(records), "last": None, "age_minutes": None, "status": "unknown",
              "error": "", "failed_apps": [], "errors_in_period": total_hits(errors), "stale": False}
    if not records:
        health["stale"] = True
        return health
    record = records[0]
    sync = dig(record, "data", "sync") or {}
    health["last"] = record.get("timestamp")
    health["status"] = str(sync.get("status") or "unknown")
    health["error"] = str(sync.get("error") or "")
    apps = sync.get("apps") if isinstance(sync.get("apps"), dict) else {}
    health["failed_apps"] = sorted(
        name for name, info in apps.items()
        if isinstance(info, dict) and lower(info.get("status")) not in ("", "ok")
    )
    parsed = parse_datetime(record.get("timestamp"))
    if parsed:
        age = (datetime.now(timezone.utc) - parsed).total_seconds() / 60
        health["age_minutes"] = int(age)
        health["stale"] = age > GWS_SYNC_STALE_MINUTES
    return health


def collect_stats(time_from, time_to):
    ignore = detect_collector_targets()
    base = base_filter(time_from, time_to, ignore)
    stats = {
        "overview": query_overview(base),
        "detections": query_detections(base),
        "failed_logins": query_failed_logins(base),
        "admin": query_admin_changes(base),
        "oauth": query_oauth_grants(base),
        "sync": query_sync_health(time_from, time_to),
    }
    stats["attention_users"] = [u for u in stats["failed_logins"]["users"] if u["count"] >= GWS_FAILED_LOGIN_THRESHOLD]
    stats["risk"] = determine_risk(stats)
    return stats


# -----------------------------------------------------------------------------
# SOC risk and recommendation logic
# -----------------------------------------------------------------------------
def sync_problem(sync):
    return sync["stale"] or sync["status"] in ("error",) or bool(sync["failed_apps"]) or sync["errors_in_period"] > 0


def determine_risk(stats):
    det = stats["detections"]
    sync = stats["sync"]
    if det["critical"] > 0:
        return "Critical"
    if det["high"] > 0 or sync["stale"] or sync["status"] == "error":
        return "High"
    if det["medium"] > 0 or stats["attention_users"] or sync_problem(sync):
        return "Medium"
    return "Low"


def build_posture_label(stats):
    risk = stats["risk"]
    det = stats["detections"]
    categories = {detection_action(r)[0] for r in det["records"] if severity_rank(dig(r, "rule", "level")) >= 3}
    if risk == "Critical":
        if "privilege" in categories:
            return "Critical - Privileged Access Change"
        if "signin_attack" in categories:
            return "Critical - Suspected Account Compromise"
        return "Critical - Immediate SOC Action Required"
    if risk == "High":
        if det["high"] > 0:
            if "signin_attack" in categories:
                return "High - Sign-in Attack Activity"
            if "sharing" in categories or "exfil" in categories:
                return "High - Data Exposure Risk"
            return "High - Security Detections Open"
        return "High - Monitoring Gap"
    if risk == "Medium":
        if det["medium"] > 0:
            return "Medium - Security Review Required"
        if stats["attention_users"]:
            return "Medium - Sign-in Failures"
        return "Medium - Collection Attention Required"
    return "Low - Stable Workspace Posture"


def unique_items(items, limit=3):
    result, seen = [], set()
    for item in items:
        text = str(item).strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            result.append(text)
        if len(result) >= limit:
            break
    return result


def detection_summary(record):
    return (
        f"{dig(record, 'rule', 'description') or 'Google Workspace detection'}"
    )


def build_rule_based_soc_assessment(stats):
    det, sync, fails = stats["detections"], stats["sync"], stats["failed_logins"]
    risk = stats["risk"]
    findings, actions = [], []

    for record in det["records"]:
        if severity_rank(dig(record, "rule", "level")) >= 2:
            findings.append(detection_summary(record))
            actions.append(detection_action(record)[1])
    for user in stats["attention_users"]:
        findings.append(f"{user['user']}: {user['count']} failed sign-ins from {user['ips']} IP address(es)")
        actions.append(f"Confirm the owner of {user['user']}, reset the password, and enforce 2-step verification.")
    if sync["stale"]:
        age = f"{sync['age_minutes']} minutes" if sync["age_minutes"] is not None else "an unknown time"
        findings.append(f"Workspace log collection has not reported for {age}; new activity is not being monitored")
        actions.append("Restore the Google Workspace sync service and confirm a fresh heartbeat.")
    elif sync["failed_apps"]:
        findings.append("Collection failed for: " + ", ".join(sync["failed_apps"]))
        actions.append("Check the service-account delegation and API scopes for the failing Workspace applications.")
    elif sync["errors_in_period"] > 0:
        findings.append(f"The sync service reported {sync['errors_in_period']} error/warning cycle(s) in this period")
        actions.append("Review the sync service log for the reported errors.")

    findings, actions = unique_items(findings, 3), unique_items(actions, 3)

    if risk == "Critical":
        narrative = (
            "The Google Workspace posture is critical because a high-impact detection was raised, such as a privilege grant or a suspicious sign-in. "
            "Confirm each one with the user or administrator involved and revoke anything unapproved before it is used."
        )
    elif risk == "High":
        if det["high"] > 0:
            narrative = (
                "The Google Workspace posture is high because security detections require review. "
                "Validate each finding with its owner and remove any unapproved access or sharing."
            )
        else:
            narrative = (
                "The Google Workspace posture is high because log collection is not healthy. "
                "New activity is not being monitored until the sync service reports again."
            )
    elif risk == "Medium":
        narrative = (
            "The Google Workspace posture requires attention because of lower-severity detections, repeated sign-in failures, or collection warnings. "
            "None indicate confirmed compromise, but each should be reviewed and closed."
        )
    else:
        narrative = "The Google Workspace posture is stable, with no condition requiring SOC action during the reporting period."

    return {"overall_posture": build_posture_label(stats), "narrative": narrative,
            "key_findings": findings, "recommended_actions": actions}


def build_llm_headers():
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {LLM_API_KEY}"}
    if HF_ORG_NAME:
        headers["X-HF-Bill-To"] = HF_ORG_NAME
    return headers


def parse_llm_json(content):
    if not content or not content.strip():
        return None
    text = content.strip()
    if text.startswith("```"):
        text = text[3:]
        if text.lower().startswith("json"):
            text = text[4:]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        first, last = text.find("{"), text.rfind("}")
        if first >= 0 and last > first:
            try:
                return json.loads(text[first:last + 1])
            except json.JSONDecodeError:
                return None
    return None


def get_ai_soc_assessment(stats, report_type, time_from, time_to):
    """Short, action-focused narrative from Athena-AI. Falls back to the rule-based assessment."""
    if not LLM_ENABLED or not LLM_API_KEY:
        if not LLM_API_KEY:
            log("LLM_API_KEY is not set; using rule-based Athena-AI Insights")
        return None

    import requests

    det = stats["detections"]
    prompt_data = {
        "period": {"type": report_type, "from": time_from, "to": time_to},
        "risk": stats["risk"],
        "critical_detections": det["critical"],
        "high_detections": det["high"],
        "medium_detections": det["medium"],
        "failed_signins": stats["failed_logins"]["total"],
        "users_over_failed_signin_threshold": len(stats["attention_users"]),
        "collection_healthy": not sync_problem(stats["sync"]),
        "important_detections": [
            {
                "severity": severity_name(severity_rank(dig(r, "rule", "level"))),
                "description": dig(r, "rule", "description"),
                "user": gws(r, "actor", "email"),
                "country": dig(r, "GeoLocation", "country_name"),
            }
            for r in det["records"][:5]
        ],
        "failed_signin_users": [
            {"user": u["user"], "count": u["count"], "distinct_ips": u["ips"]} for u in stats["attention_users"][:5]
        ],
    }
    prompt = f"""You are Athena-AI acting as a senior SOC analyst reviewing Google Workspace audit telemetry.

Create a concise, decision-oriented SOC narrative from this JSON:
{json.dumps(prompt_data, ensure_ascii=False)}

Strict rules:
- Do not mention any metric whose value is zero.
- Do not mention normal, successful, or routine activity.
- Do not restate the complete dataset.
- Explain the current identity and data-exposure posture and what requires action.
- Keep the narrative to a maximum of 3 short sentences.
- Provide no more than 3 key findings and no more than 3 prioritized recommendations.
- Recommendations must be specific to the supplied detections.
- Do not invent evidence, root cause, compromise, or business impact.

Return only valid JSON:
{{
  "overall_posture": "short label such as High - Data Exposure Risk",
  "narrative": "maximum 3 short sentences",
  "key_findings": ["maximum 3 concise actionable findings"],
  "recommended_actions": ["maximum 3 prioritized actions"]
}}"""
    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": "You are a senior SOC analyst specializing in Google Workspace security. Return only concise, valid JSON."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.15,
        "max_tokens": 1000,
        "response_format": {"type": "json_object"},
    }
    try:
        response = requests.post(LLM_CHAT_URL, headers=build_llm_headers(), json=payload, timeout=(10, 180))
        if response.status_code != 200:
            log(f"LLM API error: {response.status_code} - {response.text[:500]}")
            return None
        content = response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        parsed = parse_llm_json(content)
        if not parsed:
            log("LLM response was not valid JSON; using rule-based assessment")
            return None
        fallback = build_rule_based_soc_assessment(stats)
        parsed["key_findings"] = unique_items(parsed.get("key_findings", []), 3)
        parsed["recommended_actions"] = unique_items(parsed.get("recommended_actions", []), 3)
        parsed["overall_posture"] = str(parsed.get("overall_posture") or fallback["overall_posture"]).strip()
        parsed["narrative"] = str(parsed.get("narrative") or fallback["narrative"]).strip()
        return parsed
    except Exception as exc:
        log(f"Error getting Athena-AI assessment: {exc}")
        return None


def build_positive_observations(stats):
    observations = []
    det, sync = stats["detections"], stats["sync"]
    if det["critical"] == 0 and det["high"] == 0:
        observations.append("No critical or high-severity Google Workspace detections were raised in the reporting period.")
    if not sync_problem(sync) and sync["seen"]:
        observations.append("Workspace audit log collection is healthy, with no sync errors or failed applications.")
    if not stats["attention_users"] and stats["failed_logins"]["total"] == 0:
        observations.append("No failed sign-ins were recorded in the reporting period.")
    elif not stats["attention_users"]:
        observations.append("Failed sign-ins stayed below the repeated-failure threshold for every user.")
    if stats["overview"]["total"] > 0 and len(observations) < 3:
        observations.append(f"{stats['overview']['total']:,} Workspace audit events were collected and reviewed.")
    return observations[:3]


def build_recommendations(stats, assessment):
    prioritized = []

    def add(category, text):
        if text and not any(existing == category for existing, _ in prioritized):
            prioritized.append((category, text))

    records = sorted(stats["detections"]["records"], key=lambda r: -as_int(dig(r, "rule", "level")))
    for record in records:
        category = detection_action(record)[0]
        if category in CATEGORY_RECOMMENDATIONS:
            add(category, CATEGORY_RECOMMENDATIONS[category])
    if stats["attention_users"]:
        add("signin_attack", CATEGORY_RECOMMENDATIONS["signin_attack"])
    sync = stats["sync"]
    if sync["stale"]:
        add("sync_stale", "Restore the Google Workspace sync service and confirm a fresh heartbeat so new activity is monitored.")
    elif sync["failed_apps"] or sync["errors_in_period"] > 0:
        add("sync_error", "Review the sync service log and the service-account scopes for the applications that failed to collect.")

    # Athena-AI actions are added only when they say something the rule-based items above do not.
    rule_based = {lower(a) for a in build_rule_based_soc_assessment(stats)["recommended_actions"]}
    for item in assessment.get("recommended_actions", []) or []:
        text = str(item).strip()
        if text and lower(text) not in rule_based:
            add("ai_" + str(len(prioritized)), text)
    return [text for _, text in prioritized[:4]]


# -----------------------------------------------------------------------------
# HTML helpers
# -----------------------------------------------------------------------------
def fmt_num(value):
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def risk_color(risk):
    return {"Critical": "#991b1b", "High": "#dc2626", "Medium": "#d97706", "Low": "#059669"}.get(risk, "#475569")


def sev_color(rank):
    return {4: "#991b1b", 3: "#dc2626", 2: "#d97706", 1: "#64748b"}.get(rank, "#475569")


def esc(value):
    return html.escape(str(value if value is not None else ""))


def metric_card(title, value, color):
    return f"""
    <td style="padding:6px;vertical-align:top;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;">
        <tr><td style="padding:14px;text-align:center;">
          <div style="font-size:25px;font-weight:700;color:{color};">{esc(value)}</div>
          <div style="font-size:11px;text-transform:uppercase;color:#64748b;letter-spacing:.4px;margin-top:4px;">{esc(title)}</div>
        </td></tr>
      </table>
    </td>"""


def build_metric_cards(stats):
    """Exceptions only: zero-value metrics are not shown."""
    det, fails, sync = stats["detections"], stats["failed_logins"], stats["sync"]
    cards = []
    if det["critical"] > 0:
        cards.append(metric_card("Critical Detections", fmt_num(det["critical"]), "#991b1b"))
    if det["high"] > 0:
        cards.append(metric_card("High Detections", fmt_num(det["high"]), "#dc2626"))
    if det["medium"] > 0:
        cards.append(metric_card("Medium Detections", fmt_num(det["medium"]), "#d97706"))
    if fails["total"] > 0:
        cards.append(metric_card("Failed Sign-ins", fmt_num(fails["total"]), "#7c2d12"))
    if sync_problem(sync):
        cards.append(metric_card("Collection Issue", "Yes", "#dc2626"))
    if not cards:
        cards.append(metric_card("Detections Requiring Action", "0", "#059669"))
    width = max(1, min(len(cards), 5))
    cells = [card.replace("<td style=", f'<td width="{100 // width}%" style=', 1) for card in cards]
    return '<table width="100%" cellpadding="0" cellspacing="0"><tr>' + "".join(cells) + "</tr></table>"


def section(title, body, accent="#0d47a1"):
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;margin:14px 0;">
      <tr><td style="padding:14px 18px;border-left:4px solid {accent};">
        <h3 style="margin:0 0 12px 0;color:#0f172a;font-size:16px;">{esc(title)}</h3>
        {body}
      </td></tr>
    </table>"""


def table(headers, rows):
    head = "".join(
        f"<th style='text-align:left;padding:8px;background:#f1f5f9;border-bottom:1px solid #cbd5e1;font-size:12px;'>{esc(h)}</th>"
        for h in headers
    )
    body = "".join(
        "<tr>" + "".join(
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;font-size:12px;vertical-align:top;'>{cell}</td>"
            for cell in row
        ) + "</tr>"
        for row in rows
    )
    return f"<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'><tr>{head}</tr>{body}</table>"


def build_assessment_html(assessment, risk):
    findings = assessment.get("key_findings", [])[:3]
    findings_html = ""
    if findings:
        findings_html = (
            "<div style='margin-top:14px;font-weight:700;'>Key SOC Findings</div>"
            "<ul style='margin:6px 0 0 0;padding-left:20px;'>"
            + "".join(f"<li style='margin:5px 0;'>{esc(item)}</li>" for item in findings)
            + "</ul>"
        )
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #cbd5e1;border-radius:8px;margin:12px 0;">
      <tr><td style="padding:15px 18px;color:#1e293b;font-size:14px;line-height:1.5;border-left:4px solid {risk_color(risk)};">
        <div style="font-weight:700;font-size:16px;margin-bottom:9px;">Athena-AI Narrative</div>
        <div style="margin-bottom:10px;">
          <span style="display:inline-block;background:{risk_color(risk)};color:#fff;padding:5px 10px;border-radius:14px;font-size:12px;font-weight:700;">
            Overall Posture: {esc(assessment.get('overall_posture') or risk)}
          </span>
        </div>
        <div>{esc(assessment.get('narrative', ''))}</div>
        {findings_html}
      </td></tr>
    </table>"""


def build_detection_table(records):
    rows = []
    for record in records[:MAX_DETAIL_ROWS]:
        rank = severity_rank(dig(record, "rule", "level"))
        mitre = ", ".join(dig(record, "rule", "mitre", "id") or [])
        where = " / ".join(x for x in (gws(record, "ip_address"), dig(record, "GeoLocation", "country_name")) if x)
        rows.append([
            esc(format_timestamp(gws(record, "event_time") or record.get("timestamp"))),
            f"<span style='color:{sev_color(rank)};font-weight:700;'>{esc(severity_name(rank))}</span>",
            esc(dig(record, "rule", "description")) + (f"<div style='color:#64748b;'>{esc(mitre)}</div>" if mitre else ""),
            esc(gws(record, "actor", "email") or "N/A") + (f"<div style='color:#64748b;'>{esc(where)}</div>" if where else ""),
            esc(detection_action(record)[1]),
        ])
    extra = len(records) - MAX_DETAIL_ROWS
    note = f"<p style='margin:8px 0 0 0;color:#64748b;font-size:12px;'>+ {extra} more not shown.</p>" if extra > 0 else ""
    return table(["Time", "Severity", "Detection", "User / Source", "Required Action"], rows) + note


def build_failed_login_table(users):
    rows = [[esc(u["user"]), esc(u["count"]), esc(u["ips"]), esc(format_timestamp(u["last"]))] for u in users[:MAX_DETAIL_ROWS]]
    return table(["User", "Failed sign-ins", "Distinct IPs", "Last attempt"], rows)


def build_admin_table(changes):
    rows = [[esc(c["event"]), esc(c["count"]), esc(", ".join(a for a in c["actors"] if a))] for c in changes]
    return table(["Admin action", "Count", "Performed by"], rows)


def build_glance_html(stats):
    ov = stats["overview"]
    apps = ", ".join(f"{name} {fmt_num(count)}" for name, count in ov["apps"][:6]) or "none"
    countries = ", ".join(f"{name} {fmt_num(count)}" for name, count in ov["countries"][:5]) or "none"
    oauth = stats["oauth"]
    cells = [
        ("Audit events", fmt_num(ov["total"])),
        ("Active users", fmt_num(ov["active_users"])),
        ("Applications", apps),
        ("Source countries", countries),
        ("OAuth app grants", fmt_num(oauth["total"])),
    ]
    rows = "".join(
        f"<tr><td style='padding:6px 8px;color:#64748b;font-size:12px;width:150px;'>{esc(k)}</td>"
        f"<td style='padding:6px 8px;font-size:13px;color:#0f172a;'>{esc(v)}</td></tr>"
        for k, v in cells
    )
    return section(
        "Activity at a Glance",
        f"<table width='100%' cellpadding='0' cellspacing='0'>{rows}</table>"
        "<p style='margin:8px 0 0 0;color:#64748b;font-size:12px;'>Routine activity is summarised only; the sections above list exceptions.</p>",
        "#475569",
    )


def build_collection_html(sync):
    if not sync_problem(sync):
        return (
            "<table width='100%' cellpadding='0' cellspacing='0' style='background:#ecfdf5;border:1px solid #a7f3d0;border-radius:8px;margin:14px 0;'>"
            "<tr><td style='padding:12px 18px;color:#065f46;font-size:13px;font-weight:700;'>"
            f"Log collection healthy - last sync {esc(format_timestamp(sync['last']))}.</td></tr></table>"
        )
    issues = []
    if sync["stale"]:
        age = f"{sync['age_minutes']} minutes ago" if sync["age_minutes"] is not None else "never"
        issues.append(f"Last sync heartbeat: {format_timestamp(sync['last'])} ({age}).")
    if sync["status"] == "error" and sync["error"]:
        issues.append(f"Sync error: {sync['error']}")
    if sync["failed_apps"]:
        issues.append("Applications failing to collect: " + ", ".join(sync["failed_apps"]) + ".")
    if sync["errors_in_period"] > 0:
        issues.append(f"{sync['errors_in_period']} sync error/warning cycle(s) in the reporting period.")
    items = "".join(f"<li style='margin:4px 0;'>{esc(i)}</li>" for i in issues)
    return section("Log Collection Needs Attention", f"<ul style='margin:0;padding-left:20px;'>{items}</ul>", "#dc2626")


def build_recommendations_html(stats, assessment):
    positives = build_positive_observations(stats)
    recommendations = build_recommendations(stats, assessment)
    positive_items = "".join(f"<li style='margin:6px 0;'>{esc(i)}</li>" for i in positives) \
        or "<li style='margin:6px 0;'>No positive operational observation is available for this period.</li>"
    rec_items = "".join(f"<li style='margin:7px 0;'>{esc(i)}</li>" for i in recommendations) \
        or "<li style='margin:7px 0;'>No priority remediation action is required for this period.</li>"
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #cbd5e1;border-radius:8px;margin:12px 0;">
      <tr><td style="padding:15px 18px;color:#1e293b;font-size:14px;line-height:1.5;border-left:4px solid #0f766e;">
        <div style="font-weight:700;font-size:16px;color:#134e4a;margin-bottom:12px;">Google Workspace Security &amp; Operational Recommendations</div>
        <div style="background:#ecfdf5;border-left:4px solid #059669;padding:11px 13px;border-radius:6px;margin-bottom:12px;">
          <div style="font-weight:700;color:#065f46;margin-bottom:5px;">Positive Observations:</div>
          <ul style="margin:0;padding-left:20px;">{positive_items}</ul>
        </div>
        <div style="background:#fff7ed;border-left:4px solid #d97706;padding:11px 13px;border-radius:6px;">
          <div style="font-weight:700;color:#92400e;margin-bottom:5px;">Prioritized Recommendations:</div>
          <ol style="margin:0;padding-left:20px;">{rec_items}</ol>
        </div>
      </td></tr>
    </table>"""


def records_by_rank(stats, rank):
    return [r for r in stats["detections"]["records"] if severity_rank(dig(r, "rule", "level")) == rank]


def build_html_report(report_type, time_from, time_to, stats, assessment):
    from_date = parse_datetime(time_from).strftime("%B %d, %Y %H:%M UTC")
    to_date = parse_datetime(time_to).strftime("%B %d, %Y %H:%M UTC")

    sections = []
    for rank, accent in ((4, "#991b1b"), (3, "#dc2626"), (2, "#d97706")):
        records = records_by_rank(stats, rank)
        if records:
            sections.append(section(f"{severity_name(rank)} Security Detections", build_detection_table(records), accent))
    if stats["attention_users"]:
        sections.append(section(
            "Repeated Failed Sign-ins",
            f"<p style='margin:0 0 10px 0;color:#475569;font-size:13px;'>Users with {GWS_FAILED_LOGIN_THRESHOLD} or more failed sign-ins in the period.</p>"
            + build_failed_login_table(stats["attention_users"]), "#7c2d12"))
    if stats["admin"]["changes"]:
        sections.append(section("Admin Console Changes", build_admin_table(stats["admin"]["changes"]), "#0d47a1"))

    if not stats["detections"]["records"] and not stats["attention_users"]:
        top = """
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#ecfdf5;border:1px solid #a7f3d0;border-radius:8px;margin:14px 0;">
          <tr><td style="padding:15px 18px;color:#065f46;font-size:14px;font-weight:700;">
            No Google Workspace detections or sign-in conditions require action in this reporting period.
          </td></tr>
        </table>"""
    else:
        top = ""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:Arial,sans-serif;color:#334155;">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:1100px;background:#f8fafc;">
      <tr><td style="background:#0d47a1;color:#fff;padding:16px 22px;">
        <div style="font-size:20px;font-weight:700;">{esc(ATHENA_NAME)} &mdash; Google Workspace Security Report</div>
        <div style="font-size:12px;margin-top:5px;">Tenant: {esc(TENANT_NAME)} &nbsp;|&nbsp; {esc(report_type.title())}</div>
        <div style="font-size:12px;margin-top:4px;">{esc(from_date)} &mdash; {esc(to_date)}</div>
      </td></tr>
      <tr><td style="padding:16px 20px;">
        <div style="font-size:13px;color:#475569;margin-bottom:8px;">
          Exception-focused view: routine activity is summarised, so detections and operational problems are visible immediately.
        </div>
        {build_metric_cards(stats)}
        {build_assessment_html(assessment, stats['risk'])}
        {top}
        {''.join(sections)}
        {build_collection_html(stats['sync'])}
        {build_glance_html(stats)}
        {build_recommendations_html(stats, assessment)}
      </td></tr>
    </table>
  </td></tr></table>
</body>
</html>"""


def build_plain_report(report_type, time_from, time_to, stats, assessment):
    lines = [
        f"{ATHENA_NAME} - {report_type.upper()} GOOGLE WORKSPACE REPORT",
        f"Tenant: {TENANT_NAME}",
        f"Period: {time_from} to {time_to}",
        f"Overall Risk: {stats['risk']}",
        "",
        f"Posture: {assessment.get('overall_posture', stats['risk'])}",
        "",
        "ATHENA-AI NARRATIVE",
        assessment.get("narrative", ""),
    ]
    findings = assessment.get("key_findings", [])[:3]
    if findings:
        lines.extend(["", "KEY SOC FINDINGS"])
        lines.extend(f"- {item}" for item in findings)

    for rank in (4, 3, 2):
        records = records_by_rank(stats, rank)
        if records:
            lines.extend(["", f"{severity_name(rank).upper()} DETECTIONS"])
            for record in records[:MAX_DETAIL_ROWS]:
                lines.append(
                    f"- {format_timestamp(gws(record, 'event_time') or record.get('timestamp'))} | "
                    f"{dig(record, 'rule', 'description')} | "
                    f"Action: {detection_action(record)[1]}"
                )

    if stats["attention_users"]:
        lines.extend(["", "REPEATED FAILED SIGN-INS"])
        for user in stats["attention_users"][:MAX_DETAIL_ROWS]:
            lines.append(f"- {user['user']} | {user['count']} failures | {user['ips']} IP(s) | last {format_timestamp(user['last'])}")

    if stats["admin"]["changes"]:
        lines.extend(["", "ADMIN CONSOLE CHANGES"])
        for change in stats["admin"]["changes"]:
            lines.append(f"- {change['event']} x{change['count']} by {', '.join(a for a in change['actors'] if a)}")

    sync = stats["sync"]
    lines.extend(["", "LOG COLLECTION"])
    if sync_problem(sync):
        if sync["stale"]:
            lines.append(f"- Last sync heartbeat {format_timestamp(sync['last'])}; collection may be down.")
        if sync["failed_apps"]:
            lines.append("- Failing applications: " + ", ".join(sync["failed_apps"]))
        if sync["errors_in_period"] > 0:
            lines.append(f"- {sync['errors_in_period']} sync error/warning cycle(s) in the period.")
    else:
        lines.append(f"- Healthy, last sync {format_timestamp(sync['last'])}.")

    ov = stats["overview"]
    lines.extend([
        "", "ACTIVITY AT A GLANCE",
        f"- Audit events: {fmt_num(ov['total'])} | Active users: {fmt_num(ov['active_users'])} | OAuth app grants: {fmt_num(stats['oauth']['total'])}",
        "- Applications: " + (", ".join(f"{n} {fmt_num(c)}" for n, c in ov["apps"][:6]) or "none"),
        "- Source countries: " + (", ".join(f"{n} {fmt_num(c)}" for n, c in ov["countries"][:5]) or "none"),
    ])

    lines.extend(["", "GOOGLE WORKSPACE SECURITY & OPERATIONAL RECOMMENDATIONS", "Positive Observations:"])
    positives = build_positive_observations(stats)
    lines.extend(f"- {i}" for i in positives) if positives else lines.append("- No positive operational observation is available for this period.")
    lines.append("Prioritized Recommendations:")
    recs = build_recommendations(stats, assessment)
    lines.extend(f"- {i}" for i in recs) if recs else lines.append("- No priority remediation action is required for this period.")

    if not stats["detections"]["records"] and not stats["attention_users"] and not sync_problem(sync):
        lines.extend(["", "No Google Workspace condition requiring SOC action was identified."])
    lines.extend(["", f"Report version: {REPORT_VERSION}"])
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Output, delivery, entry point
# -----------------------------------------------------------------------------
def save_report_files(report_type, time_from, html_body, plain_body):
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
    date_label = parse_datetime(time_from).strftime("%Y%m%d")
    base = os.path.join(REPORT_OUTPUT_DIR, f"gworkspace_{report_type}_{date_label}")
    with open(f"{base}.html", "w", encoding="utf-8") as handle:
        handle.write(html_body)
    with open(f"{base}.txt", "w", encoding="utf-8") as handle:
        handle.write(plain_body)
    log(f"Saved Google Workspace report files: {base}.html, {base}.txt")


def send_email(recipients, subject, plain_body, html_body):
    try:
        if not recipients:
            raise RuntimeError("SMTP_RECIPIENT is not configured")
        if not SMTP_USERNAME or not SMTP_PASSWORD:
            raise RuntimeError("SMTP_USERNAME or SMTP_PASSWORD is not configured")
        message = EmailMessage()
        message["Subject"] = subject
        message["To"] = ", ".join(recipients)
        message["From"] = formataddr((f"{ATHENA_NAME} Reports", SMTP_FROM))
        message.set_content(plain_body)
        message.add_alternative(html_body, subtype="html")
        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) if SMTP_USE_SSL else smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        server.ehlo()
        if SMTP_USE_TLS and not SMTP_USE_SSL:
            server.starttls()
            server.ehlo()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)
        server.quit()
        log(f"Google Workspace report sent successfully to {recipients}")
        return True
    except Exception as exc:
        log(f"Error sending Google Workspace report email: {exc}")
        return False


def generate_report(report_type, time_from, time_to, recipients):
    log(f"Generating {report_type} Google Workspace report from {time_from} to {time_to}")
    stats = collect_stats(time_from, time_to)
    assessment = get_ai_soc_assessment(stats, report_type, time_from, time_to) or build_rule_based_soc_assessment(stats)
    log("Athena-AI Insights section prepared for Google Workspace report")

    html_body = build_html_report(report_type, time_from, time_to, stats, assessment)
    plain_body = build_plain_report(report_type, time_from, time_to, stats, assessment)
    date_label = parse_datetime(time_from).strftime("%b %d, %Y")
    subject = f"[{TENANT_NAME}] Athena SOC {report_type.title()} Google Workspace Report - {date_label}"

    delivered, saved = False, False
    if REPORT_GWORKSPACE_SEND_EMAIL:
        delivered = send_email(recipients, subject, plain_body, html_body)
        if not delivered:
            log("Email delivery failed; saving a local copy of the generated Google Workspace report")
            save_report_files(report_type, time_from, html_body, plain_body)
            saved = True
    else:
        log("REPORT_GWORKSPACE_SEND_EMAIL=false; email delivery skipped")
    if REPORT_GWORKSPACE_SAVE_OUTPUT and not saved:
        save_report_files(report_type, time_from, html_body, plain_body)
    return delivered if REPORT_GWORKSPACE_SEND_EMAIL else True


def resolve_period(args):
    if len(args) < 2:
        raise ValueError("Usage: reports_gworkspace.py <daily|weekly|monthly|custom> [start_time] [end_time]")
    report_type = args[1].lower()
    now = datetime.now(timezone.utc)
    spans = {"daily": 1, "weekly": 7, "monthly": 30}
    if report_type in spans:
        return (report_type,
                (now - timedelta(days=spans[report_type])).isoformat().replace("+00:00", "Z"),
                now.isoformat().replace("+00:00", "Z"))
    if report_type == "custom":
        if len(args) < 4:
            raise ValueError("Custom report requires: reports_gworkspace.py custom <start_time> <end_time>")
        start, end = parse_datetime(args[2]), parse_datetime(args[3])
        if not start or not end:
            raise ValueError("Custom start_time and end_time must be valid ISO-8601 timestamps")
        if start >= end:
            raise ValueError("Custom start_time must be earlier than end_time")
        return report_type, args[2], args[3]
    raise ValueError(f"Unknown report type: {report_type}")


def validate_runtime_configuration(recipients):
    if not REPORT_GWORKSPACE_SEND_EMAIL:
        return
    missing = [name for name, ok in (("SMTP_RECIPIENT", recipients), ("SMTP_USERNAME", SMTP_USERNAME), ("SMTP_PASSWORD", SMTP_PASSWORD)) if not ok]
    if missing:
        raise ReportConfigurationError("Missing required email configuration: " + ", ".join(missing))


def main(args):
    if not REPORT_GWORKSPACE_ENABLED:
        log("REPORT_GWORKSPACE_ENABLED=false; skipping Google Workspace report")
        return 0
    try:
        report_type, time_from, time_to = resolve_period(args)
        validate_runtime_configuration(SMTP_RECIPIENT)
        log(f"Google Workspace report version: {REPORT_VERSION}")
        log(f"Recipients: {SMTP_RECIPIENT}")
        success = generate_report(report_type, time_from, time_to, SMTP_RECIPIENT)
    except (ReportConfigurationError, ReportDataError, ValueError) as exc:
        log(f"Google Workspace report aborted: {exc}")
        return 1
    if not success:
        log("Google Workspace report generation or delivery did not complete successfully")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:
        log(f"Unhandled exception: {exc}")
        sys.exit(1)
