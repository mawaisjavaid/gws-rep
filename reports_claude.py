#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Athena SOC - Concise Claude Enterprise Report
---------------------------------------------
Same design as reports_gworkspace.py / reports_sophos.py: exception-focused, risk-rated, with an
Athena-AI narrative (rule-based fallback) and prioritized recommendations.

Reads the Claude Enterprise events that the Ageleia sync service (/opt/claude) feeds into Wazuh
(wazuh-alerts-*, data.integration = claude-enterprise). Three feeds, told apart by data.feed:
  - activity   Compliance API activity: security detections (rules 102703-102821), admin and access changes
  - usage      token usage, spend and threshold alerts (rules 102780-102789)
  - content    sensitive-data (DLP) findings (rules 102830-102836); only counts, users and categories are reported,
               never the sensitive content itself
  - health     sync heartbeats of the three feeds (rule groups claude_heartbeat, claude_usage_heartbeat,
               claude_dlp_heartbeat); a heartbeat older than 30 minutes is a problem
The sync service's own polls (rules 102701/102702, user agent athena-claude-sync/) are excluded from every count.

Usage:
  python3 reports_claude.py daily
  python3 reports_claude.py weekly
  python3 reports_claude.py monthly
  python3 reports_claude.py custom 2026-11-01T00:00:00Z 2026-11-13T23:59:59Z

Test without email:
  REPORT_CLAUDE_SEND_EMAIL=false REPORT_CLAUDE_SAVE_OUTPUT=true \
    python3 reports_claude.py daily
"""

import html
import json
# BUILD: CLAUDE-CONCISE-V1 - mirrors the GWS-CONCISE-V1 / SOC-CONCISE-V6 logic of the other Athena reports
import os
import re
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

REPORT_CLAUDE_ENABLED = os.getenv("REPORT_CLAUDE_ENABLED", "true").lower() == "true"
REPORT_CLAUDE_SEND_EMAIL = os.getenv("REPORT_CLAUDE_SEND_EMAIL", "true").lower() == "true"
REPORT_CLAUDE_SAVE_OUTPUT = os.getenv("REPORT_CLAUDE_SAVE_OUTPUT", "false").lower() == "true"
REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", os.path.join(SCRIPT_DIR, "generated_reports"))
REPORT_VERSION = "CLAUDE-CONCISE-2026.11.13-v1"
MAX_DETAIL_ROWS = max(1, int(os.getenv("CLAUDE_MAX_DETAIL_ROWS", "10")))
CLAUDE_SYNC_STALE_MINUTES = max(5, int(os.getenv("CLAUDE_SYNC_STALE_MINUTES", "30")))

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
ES_INDEX_CLAUDE = os.getenv("ES_INDEX_PATTERN_CLAUDE", "wazuh-alerts-*")

# -----------------------------------------------------------------------------
# Athena-AI
# -----------------------------------------------------------------------------
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://router.huggingface.co/v1").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-ai/DeepSeek-V3.1-Terminus")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"
HF_ORG_NAME = os.getenv("HF_ORG_NAME", "").strip()
LLM_CHAT_URL = f"{LLM_BASE_URL}/chat/completions"

LOG_FILE = os.path.join(SCRIPT_DIR, "logs", "claude_reporting.log")


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
    path = f"{ES_INDEX_CLAUDE}/_search"
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


def agg(response, name):
    return ((response or {}).get("aggregations", {}) or {}).get(name, {}) or {}


def buckets(response, name):
    return [(b.get("key"), as_int(b.get("doc_count"))) for b in agg(response, name).get("buckets", [])]


def lower(value):
    return str(value or "").strip().lower()


def as_int(value):
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def as_float(value):
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def clean(value):
    """The sync writes the string 'null' for empty fields."""
    text = str(value if value is not None else "").strip()
    return "" if lower(text) in ("null", "none") else text


_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def parse_datetime(value):
    """ISO-8601 as written by Wazuh ('2026-11-13T16:27:51.829+0500') and by Anthropic ('...:51.041001Z').
    Python 3.10's fromisoformat reads neither the '+0500' offset nor odd fraction lengths, so the text is normalised first."""
    if not value:
        return None
    match = _ISO.match(str(value).strip())
    if not match:
        return None
    day, clock, fraction, zone = match.groups()
    zone = "+00:00" if zone in (None, "", "Z") else (zone if ":" in zone else zone[:3] + ":" + zone[3:])
    try:
        return datetime.fromisoformat(f"{day}T{clock}.{((fraction or '0') + '000000')[:6]}{zone}")
    except ValueError:
        return None


def format_timestamp(value):
    parsed = parse_datetime(value)
    if not parsed:
        return "N/A"
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def iso_z(value):
    """2026-11-13T10:00:00Z, the form the Claude events use for data.created_at (a keyword field, so ranges compare as text)."""
    parsed = parse_datetime(value)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if parsed else str(value)


def dig(record, *path):
    node = record
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def data(record, *path):
    return dig(record, "data", *path)


# -----------------------------------------------------------------------------
# Severity and detection knowledge (rule ids, levels and groups from /var/ossec/etc/rules/claude_*.xml)
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


def normalize_rule_id(rule_id):
    """The Claude rules moved from 101700-101839 to 102700-102839. Alerts written before the move keep the old id in the
    index, so they are reported under the new one (same as the dashboard does)."""
    try:
        number = int(rule_id)
    except (TypeError, ValueError):
        return str(rule_id or "")
    return str(number + 1000) if 101700 <= number <= 101839 else str(number)


# rule id -> (category, short title, specific required action). Levels come from the alert itself.
DETECTION_RULES = {
    "102703": ("compliance_api", "Compliance API queried", "Confirm the audit-API query came from an approved person or tool; rotate the API key if it is not recognised."),
    "102704": ("compliance_api", "Failed Compliance API call", "Find out why the call failed and whether someone is probing with a wrong key; rotate the key if in doubt."),
    "102710": ("audit_off", "Compliance API turned off", "Turn the Compliance API back on now, confirm with the administrator who disabled it, and review what happened during the gap."),
    "102711": ("audit_off", "Compliance API logging turned off", "Turn activity logging back on now, confirm with the administrator who disabled it, and review what happened during the gap."),
    "102712": ("audit_off", "Compliance API settings changed", "Confirm the settings change was approved."),
    "102714": ("api_key", "API key created with write or delete scopes", "Confirm the key was approved and who owns it; revoke it if not, and limit it to read-only scopes."),
    "102715": ("api_key", "API key created (read-only)", "Confirm the new key is expected and record its owner."),
    "102766": ("rbac", "Role or permission change", "Verify the role change was approved; revert it if not."),
    "102769": ("data_export", "Organization data export", "Confirm an authorized administrator requested the export and where the data went."),
    "102730": ("exfil", "Upload burst (10+ files in 2 minutes)", "Contact the user about the burst and review the uploaded files."),
    "102731": ("access", "Repeated failed chat access", "Confirm what the user was trying to open and whether they were reaching for chats they do not own."),
    "102742": ("auth_attack", "Repeated failed logins or API authentications", "Check the source IP, block it if untrusted, and reset credentials for the targeted accounts."),
    "102801": ("exfil", "File upload from a new IP", "Confirm the upload with the user; if unrecognised, revoke their sessions and review the file."),
    "102802": ("off_hours", "File upload outside working hours", "Confirm the upload with the user and review the file."),
    "102803": ("exfil", "Bulk reading (20+ items in 5 minutes)", "Confirm the reading with the user; suspend the account if it is unexpected."),
    "102804": ("cover_tracks", "Bulk deletion of chats", "Review the deletions with the user and restore from retention if needed."),
    "102805": ("cover_tracks", "Chat deleted right after uploads", "Investigate: uploads followed by a deletion can mean data theft with clean-up; review what was uploaded."),
    "102806": ("exfil", "File export outside working hours", "Confirm the export with the user and review where the file went."),
    "102810": ("api_key", "API key used from a new IP", "Confirm the new IP; rotate the key if it is not a trusted location."),
    "102811": ("identity", "Sensitive admin action from a new IP", "Verify the action with the administrator; revoke the session and review the change if unrecognised."),
    "102812": ("identity", "Dormant account active again", "Confirm with the user that the return is expected; reset credentials if not."),
    "102813": ("identity", "Scripted client acting as a user", "Confirm the automation is approved; move scripts to API keys instead of user sessions."),
    "102814": ("identity", "Account active from 3 IPs within 10 minutes", "Check for a shared or compromised account; enforce SSO and MFA."),
    "102815": ("identity", "Account used a new IP", "Confirm the new location with the user."),
    "102820": ("admin_burst", "Admin change burst (3+ in 10 minutes)", "Review the changes made in quick succession and confirm each was approved."),
    "102821": ("off_hours", "Activity outside working hours", "Confirm the activity with the user."),
}

CATEGORY_RECOMMENDATIONS = {
    "audit_off": "Keep the Compliance API and activity logging on, and alert on any change to those settings.",
    "compliance_api": "Limit Compliance API keys to the sync service and named owners, and rotate any key that was used from an unknown place.",
    "api_key": "Review every API key created or used from a new location; keep keys read-only and rotate the unrecognised ones.",
    "rbac": "Review every role or permission change against approved requests and keep the number of administrators small.",
    "data_export": "Restrict organization data exports to named administrators and record where each export goes.",
    "exfil": "Investigate the upload, export and bulk-reading activity with the users involved and consider tighter file controls.",
    "cover_tracks": "Review deleted chats against uploads in the same period and confirm retention can recover them.",
    "access": "Check the failed chat-access attempts with the users and restrict who can open shared chats.",
    "auth_attack": "Enforce SSO with MFA and reset credentials for accounts hit by repeated failed logins.",
    "identity": "Confirm unusual account use (new IPs, dormant accounts, scripted clients) with the owners and enforce SSO with MFA.",
    "off_hours": "Confirm out-of-hours activity with the users; unexpected activity should lead to a session revoke.",
    "admin_burst": "Review bursts of admin changes against approved change requests.",
    "dlp": "Remind users not to paste regulated data (health, personal, card) into Claude, and review the flagged chats and files with their owners.",
    "usage": "Review the token and spend alerts with the users; adjust spend limits or investigate unusual usage.",
}

HEALTH_ACTION_NOW = "Restore the Claude sync service and confirm fresh heartbeats so activity is monitored."
HEALTH_ACTION_PAST = "Review the sync log for the error cycle(s); the feeds are reporting normally again, so no data should be missing."
DLP_ACTION = ("Review the flagged chat or file with its owner, remove or redact the sensitive data, "
              "and confirm the user knows the data-handling rule.")
USAGE_ACTION = "Review the usage with the user; raise or lower the spend limit, or investigate if the usage is unexpected."


def detection_info(rule_id):
    return DETECTION_RULES.get(rule_id, ("other", None, "Investigate the finding, confirm it with the user or owner, and document the outcome."))


# -----------------------------------------------------------------------------
# Queries
# -----------------------------------------------------------------------------
CLAUDE = {"term": {"data.integration": "claude-enterprise"}}
FEED_ACTIVITY = {"term": {"data.feed": "activity"}}
FEED_USAGE = {"term": {"data.feed": "usage"}}
FEED_CONTENT = {"term": {"data.feed": "content"}}
HEARTBEAT_GROUPS = ["claude_heartbeat", "claude_usage_heartbeat", "claude_dlp_heartbeat"]
# the sync service's own polls (rule 102701 is the suppressed poll, 102702 a failed poll, which is a health problem)
SYNC_USER_AGENT_PREFIX = "athena-claude-sync/"
NOISE = [
    {"terms": {"rule.groups": HEARTBEAT_GROUPS + ["claude_selfnoise", "claude_health"]}},
    {"terms": {"rule.id": ["101701", "101702", "102701", "102702"]}},
    {"prefix": {"data.actor.user_agent": SYNC_USER_AGENT_PREFIX}},
]
ALERT_RANGE_FORMAT = "strict_date_optional_time"


def event_range(time_from, time_to):
    """Window on the event time (data.created_at, set by Anthropic); an event without one falls back to the alert time,
    because the first sync ingests days of history at once and the alert timestamp alone would put it in the wrong window."""
    return {"bool": {"minimum_should_match": 1, "should": [
        {"range": {"data.created_at": {"gte": iso_z(time_from), "lte": iso_z(time_to)}}},
        {"bool": {"must_not": [{"exists": {"field": "data.created_at"}}],
                  "filter": [{"range": {"timestamp": {"gte": time_from, "lte": time_to, "format": ALERT_RANGE_FORMAT}}}]}},
    ]}}


def alert_range(time_from, time_to):
    return {"range": {"timestamp": {"gte": time_from, "lte": time_to, "format": ALERT_RANGE_FORMAT}}}


def activity_base(time_from, time_to):
    return {"bool": {"filter": [CLAUDE, FEED_ACTIVITY, event_range(time_from, time_to)], "must_not": NOISE}}


def with_filter(base, extra):
    return {"bool": {"filter": list(base["bool"]["filter"]) + extra, "must_not": base["bool"].get("must_not", [])}}


def who_label(bucket_user, key_id):
    return bucket_user or (f"API key {key_id[:22]}" if key_id else "unknown")


def query_detections(time_from, time_to):
    """Security detections on the activity feed (level 7 and above), one row per rule with counts and the newest example."""
    base = with_filter(activity_base(time_from, time_to), [{"range": {"rule.level": {"gte": 7}}}])
    response = es_search({
        "size": 0, "track_total_hits": True, "query": base,
        "aggs": {"rules": {"terms": {"field": "rule.id", "size": 80}, "aggs": {
            "users": {"terms": {"field": "data.srcuser", "size": 3}},
            "keys": {"terms": {"field": "data.actor.api_key_id", "size": 2}},
            "ips": {"cardinality": {"field": "data.actor.ip_address"}},
            "latest": {"top_hits": {"size": 1, "sort": [{"timestamp": "desc"}], "_source": [
                "rule.level", "rule.description", "rule.groups", "data.created_at", "data.srcuser", "data.srcip",
                "data.actor.ip_address", "data.actor.api_key_id", "GeoLocation.country_name", "timestamp"]}},
        }}},
    })
    merged = {}
    for bucket in agg(response, "rules").get("buckets", []):
        rule_id = normalize_rule_id(bucket.get("key"))      # old and new ids of the same rule are one row
        hits = parse_hits(bucket.get("latest"))
        sample = hits[0] if hits else {}
        level = as_int(dig(sample, "rule", "level"))
        users = [b.get("key") for b in (bucket.get("users") or {}).get("buckets", [])]
        keys = [b.get("key") for b in (bucket.get("keys") or {}).get("buckets", [])]
        row = merged.setdefault(rule_id, {"rule": rule_id, "level": level, "count": 0, "users": [], "keys": [],
                                          "ips": 0, "last": None, "country": None, "description": ""})
        row["count"] += as_int(bucket.get("doc_count"))
        row["level"] = max(row["level"], level)
        row["users"] = unique_items(row["users"] + users, 3)
        row["keys"] = unique_items(row["keys"] + keys, 2)
        row["ips"] = max(row["ips"], as_int((bucket.get("ips") or {}).get("value")))
        seen = data(sample, "created_at") or sample.get("timestamp")
        if seen and (not row["last"] or str(seen) > str(row["last"])):
            row["last"] = seen
            row["country"] = dig(sample, "GeoLocation", "country_name")
            row["description"] = dig(sample, "rule", "description") or ""
    rows = sorted(merged.values(), key=lambda r: (-severity_rank(r["level"]), -r["count"]))
    for row in rows:
        row["category"], title, row["action"] = detection_info(row["rule"])
        row["title"] = title or row["description"] or "Claude Enterprise detection"
        row["rank"] = severity_rank(row["level"])
    counts = {rank: sum(r["count"] for r in rows if r["rank"] == rank) for rank in (4, 3, 2)}
    return {"total": total_hits(response), "rows": rows, "critical": counts[4], "high": counts[3], "medium": counts[2]}


def query_dlp(time_from, time_to):
    """Sensitive-data findings from the content feed: counts per severity and category and the top users. Never the content."""
    base = {"bool": {"filter": [CLAUDE, FEED_CONTENT, {"term": {"rule.groups": "claude_dlp_finding"}}, event_range(time_from, time_to)]}}
    uniq = {"cardinality": {"field": "data.id"}}
    response = es_search({
        "size": 0, "track_total_hits": True, "query": base,
        "aggs": {
            "findings": uniq,
            "severity": {"terms": {"field": "data.dlp.severity", "size": 5}, "aggs": {"n": uniq}},
            "category": {"terms": {"field": "data.dlp.category", "size": 8}, "aggs": {"n": uniq}},
            "users": {"terms": {"field": "data.srcuser", "size": 10, "order": {"n": "desc"}}, "aggs": {
                "n": uniq,
                "categories": {"terms": {"field": "data.dlp.category", "size": 4}},
                "severities": {"terms": {"field": "data.dlp.severity", "size": 4}},
            }},
        },
    })
    by_sev = {lower(b["key"]): as_int((b.get("n") or {}).get("value")) for b in agg(response, "severity").get("buckets", [])}
    users = []
    order = ["critical", "high", "medium", "low"]
    for bucket in agg(response, "users").get("buckets", []):
        sevs = [lower(b["key"]) for b in (bucket.get("severities") or {}).get("buckets", [])]
        top = next((s for s in order if s in sevs), sevs[0] if sevs else "low")
        users.append({"user": bucket.get("key"), "count": as_int((bucket.get("n") or {}).get("value")),
                      "categories": [b["key"] for b in (bucket.get("categories") or {}).get("buckets", [])], "severity": top})
    return {
        "findings": as_int((agg(response, "findings")).get("value")),
        "critical": by_sev.get("critical", 0), "high": by_sev.get("high", 0),
        "medium": by_sev.get("medium", 0), "low": by_sev.get("low", 0),
        "categories": [(b["key"], as_int((b.get("n") or {}).get("value"))) for b in agg(response, "category").get("buckets", [])],
        "users": users,
    }


def hour_floor(value):
    parsed = parse_datetime(value)
    return parsed.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def query_usage_buckets(time_from, time_to):
    """Hourly token buckets (rule 102781) in the window, newest copy per bucket id (a bucket is written again when revised)."""
    lo, hi = parse_datetime(hour_floor(time_from)), parse_datetime(time_to)
    rows, truncated, cursor = [], False, lo
    while cursor < hi:
        end = min(cursor + timedelta(hours=24), hi + timedelta(seconds=1))
        response = es_search({
            "size": 10000, "sort": [{"timestamp": "desc"}], "collapse": {"field": "data.id"},
            "_source": ["data.usage.email", "data.usage.name", "data.usage.total_tokens", "data.usage.requests",
                        "data.usage.product", "data.usage.model", "data.usage.starting_at", "data.srcuser"],
            "query": {"bool": {"filter": [CLAUDE, FEED_USAGE, {"term": {"rule.groups": "claude_usage_bucket"}},
                                          {"range": {"data.usage.starting_at": {
                                              "gte": cursor.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                              "lt": end.strftime("%Y-%m-%dT%H:%M:%SZ")}}}]}},
        })
        hits = parse_hits(response)
        truncated = truncated or len(hits) >= 10000
        rows.extend(hits)
        cursor = end
    by_user, by_model, total_tokens, total_requests = {}, {}, 0, 0
    for record in rows:
        usage = data(record, "usage") or {}
        tokens, requests_ = as_int(usage.get("total_tokens")), as_int(usage.get("requests"))
        user = clean(usage.get("email")) or clean(data(record, "srcuser")) or clean(usage.get("name")) or "unknown"
        entry = by_user.setdefault(user, {"user": user, "tokens": 0, "requests": 0})
        entry["tokens"] += tokens
        entry["requests"] += requests_
        model = clean(usage.get("model")) or "unknown"
        by_model[model] = by_model.get(model, 0) + tokens
        total_tokens += tokens
        total_requests += requests_
    top_users = sorted(by_user.values(), key=lambda e: -e["tokens"])
    return {"tokens": total_tokens, "requests": total_requests, "users": [u for u in top_users if u["tokens"] > 0][:5],
            "active_users": len([u for u in top_users if u["tokens"] > 0]),
            "models": sorted(by_model.items(), key=lambda kv: -kv[1])[:3], "truncated": truncated}


def query_usage_alerts(time_from, time_to):
    """Token threshold and spend-limit alerts (rules 102785-102789, group claude_token_alert), one row per user and level."""
    response = es_search({
        "size": 1000, "track_total_hits": True, "sort": [{"timestamp": "desc"}],
        "_source": ["timestamp", "rule.id", "rule.level", "data.threshold"],
        "query": {"bool": {"filter": [CLAUDE, FEED_USAGE, {"term": {"rule.groups": "claude_token_alert"}}, alert_range(time_from, time_to)]}},
    })
    grouped = {}
    for record in parse_hits(response):
        t = data(record, "threshold") or {}
        key = (clean(t.get("scope")), lower(t.get("level")), clean(t.get("email")) or clean(t.get("user_id")), clean(t.get("window")))
        row = grouped.setdefault(key, {"scope": key[0], "level": key[1], "user": key[2], "window": key[3], "count": 0,
                                       "percent": 0.0, "value": 0.0, "limit": 0.0, "metric": clean(t.get("metric")),
                                       "last": record.get("timestamp"), "rule_level": as_int(dig(record, "rule", "level"))})
        row["count"] += 1
        row["percent"] = max(row["percent"], as_float(t.get("percent_of_limit")))
        row["value"] = max(row["value"], as_float(t.get("value")))
        row["limit"] = max(row["limit"], as_float(t.get("limit")))
    rows = sorted(grouped.values(), key=lambda r: (-r["rule_level"], -r["percent"]))
    critical = sum(1 for r in rows if r["level"] == "critical")
    return {"rows": rows, "critical": critical, "warn": len(rows) - critical, "total": len(rows)}


def query_spend(month):
    """Latest month-to-date spend line per member (rule 102787), highest spenders first."""
    response = es_search({
        "size": 500, "sort": [{"timestamp": "desc"}], "_source": ["data.spend"],
        "query": {"bool": {"filter": [CLAUDE, FEED_USAGE, {"term": {"rule.groups": "claude_usage_spend"}},
                                      {"term": {"data.spend.month": month}}]}},
    })
    seen, rows = set(), []
    for record in parse_hits(response):
        s = data(record, "spend") or {}
        uid = clean(s.get("user_id"))
        if not uid or uid in seen:
            continue
        seen.add(uid)
        spent, limit = as_float(s.get("spent_cents")) / 100, as_float(s.get("limit_cents")) / 100
        if spent > 0:
            rows.append({"user": clean(s.get("email")) or clean(s.get("name")) or uid, "spent": spent, "limit": limit,
                         "percent": as_float(s.get("percent")), "month": clean(s.get("month"))})
    rows.sort(key=lambda r: -r["spent"])
    return {"rows": rows[:5], "month": month}


def query_admin_changes(time_from, time_to):
    """Admin and access changes (rule group claude_admin): members, roles, API keys, SSO / settings, exports, invites."""
    base = with_filter(activity_base(time_from, time_to), [{"term": {"rule.groups": "claude_admin"}}])
    response = es_search({
        "size": 0, "track_total_hits": True, "query": base,
        "aggs": {"types": {"terms": {"field": "data.type", "size": 20}, "aggs": {
            "users": {"terms": {"field": "data.srcuser", "size": 3}},
            "level": {"max": {"field": "rule.level"}},
            "latest": {"top_hits": {"size": 1, "sort": [{"timestamp": "desc"}], "_source": ["data.created_at", "timestamp"]}},
        }}},
    })
    changes = []
    for bucket in agg(response, "types").get("buckets", []):
        sample = (parse_hits(bucket.get("latest")) or [{}])[0]
        changes.append({"event": str(bucket.get("key") or ""), "count": as_int(bucket.get("doc_count")),
                        "users": [b.get("key") for b in (bucket.get("users") or {}).get("buckets", []) if b.get("key")],
                        "level": as_int((bucket.get("level") or {}).get("value")),
                        "last": data(sample, "created_at") or sample.get("timestamp")})
    changes.sort(key=lambda c: (-c["level"], -c["count"]))
    return {"total": sum(c["count"] for c in changes), "changes": changes[:MAX_DETAIL_ROWS]}


def query_overview(time_from, time_to):
    base = activity_base(time_from, time_to)
    response = es_search({
        "size": 0, "track_total_hits": True, "query": base,
        "aggs": {
            "users": {"cardinality": {"field": "data.srcuser"}},
            "types": {"terms": {"field": "data.type", "size": 6}},
            "countries": {"terms": {"field": "GeoLocation.country_name", "size": 5}},
            "kinds": {"filters": {"filters": {
                "chats": {"term": {"data.type": "claude_chat_created"}},
                "uploads": {"term": {"data.type": "claude_file_uploaded"}},
                "login_failures": {"term": {"rule.groups": "authentication_failed"}},
            }}},
        },
    })
    kinds = {k: as_int(v.get("doc_count")) for k, v in (agg(response, "kinds").get("buckets") or {}).items()}
    return {"total": total_hits(response), "active_users": as_int(agg(response, "users").get("value")),
            "types": buckets(response, "types"), "countries": buckets(response, "countries"), "kinds": kinds}


# heartbeat rule group -> (label, error group, key under data holding the heartbeat, stated interval in the heartbeat)
FEEDS = (
    ("activity", "Activity feed", "claude_heartbeat", "claude_sync_error", "sync"),
    ("usage", "Usage feed", "claude_usage_heartbeat", "claude_usage_error", "usage_sync"),
    ("content", "Sensitive-data scan", "claude_dlp_heartbeat", "claude_dlp_error", "dlp_sync"),
)


def query_feed_health(label, hb_group, err_group, hb_key, time_from, time_to):
    latest = es_search({
        "size": 1, "sort": [{"timestamp": "desc"}], "_source": ["timestamp", f"data.{hb_key}"],
        "query": {"bool": {"filter": [CLAUDE, {"term": {"rule.groups": hb_group}}]}},
    })
    errors = es_search({
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [CLAUDE, {"term": {"rule.groups": err_group}}, alert_range(time_from, time_to)]}},
    })
    records = parse_hits(latest)
    health = {"label": label, "seen": bool(records), "last": None, "age_minutes": None, "status": "unknown", "error": "",
              "errors_in_period": total_hits(errors), "stale": False, "http_status": ""}
    if not records:
        health["stale"] = True
        return health
    record = records[0]
    beat = data(record, hb_key) or {}
    health["last"] = record.get("timestamp")
    health["status"] = lower(beat.get("status")) or "unknown"
    health["error"] = clean(beat.get("error"))
    health["http_status"] = clean(beat.get("http_status"))
    parsed = parse_datetime(record.get("timestamp"))
    if parsed:
        age = (datetime.now(timezone.utc) - parsed).total_seconds() / 60
        health["age_minutes"] = int(age)
        health["stale"] = age > CLAUDE_SYNC_STALE_MINUTES
    return health


def query_sync_failures(time_from, time_to):
    """Failed polls of the Compliance API by the sync service itself (rule 102702): a collection problem, not a detection."""
    response = es_search({
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [CLAUDE, {"terms": {"rule.id": ["101702", "102702"]}}, alert_range(time_from, time_to)]}},
    })
    return total_hits(response)


def query_health(time_from, time_to):
    feeds = [query_feed_health(label, hb, eg, key, time_from, time_to) for _name, label, hb, eg, key in FEEDS]
    return {"feeds": feeds, "failed_polls": query_sync_failures(time_from, time_to)}


def collect_stats(time_from, time_to):
    month = (parse_datetime(time_to) or datetime.now(timezone.utc)).strftime("%Y-%m")
    stats = {
        "overview": query_overview(time_from, time_to),
        "detections": query_detections(time_from, time_to),
        "dlp": query_dlp(time_from, time_to),
        "usage": query_usage_buckets(time_from, time_to),
        "usage_alerts": query_usage_alerts(time_from, time_to),
        "spend": query_spend(month),
        "admin": query_admin_changes(time_from, time_to),
        "health": query_health(time_from, time_to),
    }
    stats["risk"] = determine_risk(stats)
    return stats


# -----------------------------------------------------------------------------
# SOC risk and recommendation logic
# -----------------------------------------------------------------------------
def feed_current_problem(feed):
    """The feed is down or reporting an error right now (as opposed to an error cycle earlier in the period that recovered)."""
    return feed["stale"] or feed["status"] not in ("ok", "unknown") or bool(feed["error"])


def feed_problem(feed):
    return feed_current_problem(feed) or feed["errors_in_period"] > 0


def health_problem(health):
    return any(feed_problem(f) for f in health["feeds"]) or health["failed_polls"] > 0


def health_critical(health):
    return any(f["stale"] or f["status"] == "error" for f in health["feeds"])


def health_current(health):
    return any(feed_current_problem(f) for f in health["feeds"])


def determine_risk(stats):
    det, dlp, usage, health = stats["detections"], stats["dlp"], stats["usage_alerts"], stats["health"]
    if det["critical"] > 0 or dlp["critical"] > 0:
        return "Critical"
    if det["high"] > 0 or dlp["high"] > 0 or usage["critical"] > 0 or health_critical(health):
        return "High"
    if det["medium"] > 0 or dlp["medium"] > 0 or usage["warn"] > 0 or health_problem(health):
        return "Medium"
    return "Low"


def detection_categories(stats, minimum_rank=3):
    return {r["category"] for r in stats["detections"]["rows"] if r["rank"] >= minimum_rank}


def build_posture_label(stats):
    risk, det, dlp = stats["risk"], stats["detections"], stats["dlp"]
    cats = detection_categories(stats)
    if risk == "Critical":
        if "audit_off" in cats:
            return "Critical - Audit Logging Disabled"
        if dlp["critical"] > 0 and det["critical"] == 0:
            return "Critical - Sensitive Data Exposure"
        return "Critical - Immediate SOC Action Required"
    if risk == "High":
        if det["high"] > 0:
            if cats & {"exfil", "cover_tracks", "data_export"}:
                return "High - Data Exfiltration Risk"
            if cats & {"api_key", "identity", "auth_attack"}:
                return "High - Identity and Key Misuse"
            return "High - Security Detections Open"
        if dlp["high"] > 0:
            return "High - Sensitive Data in Prompts"
        if stats["usage_alerts"]["critical"] > 0:
            return "High - Usage Limit Reached"
        return "High - Monitoring Gap"
    if risk == "Medium":
        if det["medium"] > 0:
            return "Medium - Security Review Required"
        if dlp["medium"] > 0:
            return "Medium - Sensitive Data Review"
        if stats["usage_alerts"]["warn"] > 0:
            return "Medium - Usage Attention"
        return "Medium - Collection Attention Required"
    return "Low - Stable Claude Posture"


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


def health_issue_lines(health):
    lines = []
    for feed in health["feeds"]:
        if feed["stale"]:
            age = f"{feed['age_minutes']} minutes" if feed["age_minutes"] is not None else "an unknown time"
            lines.append(f"{feed['label']}: no sync heartbeat for {age} (limit {CLAUDE_SYNC_STALE_MINUTES} minutes)")
        elif feed["status"] not in ("ok", "unknown") or feed["error"]:
            lines.append(f"{feed['label']}: sync reports {feed['status'] or 'a problem'}" + (f" - {feed['error'][:120]}" if feed["error"] else ""))
        if feed["errors_in_period"] > 0:
            lines.append(f"{feed['label']}: {feed['errors_in_period']} sync error cycle(s) in the period" + ("" if feed_current_problem(feed) else " (reporting normally again)"))
    if health["failed_polls"] > 0:
        lines.append(f"The sync service's Compliance API poll failed {health['failed_polls']} time(s)")
    return lines


def build_rule_based_soc_assessment(stats):
    det, dlp, usage, health = stats["detections"], stats["dlp"], stats["usage_alerts"], stats["health"]
    risk = stats["risk"]
    findings, actions = [], []

    for row in det["rows"]:
        if row["rank"] >= 2:
            who = ", ".join(row["users"] or row["keys"])
            findings.append(f"{row['title']} (rule {row['rule']}, {row['count']}x)" + (f" - {who}" if who else ""))
            actions.append(row["action"])
    if dlp["critical"] or dlp["high"]:
        top = ", ".join(u["user"] for u in dlp["users"][:2] if u["severity"] in ("critical", "high"))
        findings.append(f"{dlp['critical']} critical and {dlp['high']} high sensitive-data finding(s) in Claude content" + (f" ({top})" if top else ""))
        actions.append(DLP_ACTION)
    for row in usage["rows"][:2]:
        if row["level"] == "critical":
            findings.append(f"{row['user']} reached {row['percent']:.0f}% of the {row['scope'].replace('_', ' ')} limit")
            actions.append(USAGE_ACTION)
    for line in health_issue_lines(health)[:2]:
        findings.append(line)
        actions.append(HEALTH_ACTION_NOW if health_current(health) else HEALTH_ACTION_PAST)

    findings, actions = unique_items(findings, 3), unique_items(actions, 3)

    reasons = []
    if det["critical"]:
        reasons.append(f"{det['critical']} critical security detection(s)")
    if dlp["critical"]:
        reasons.append(f"{dlp['critical']} critical sensitive-data finding(s) in Claude content")
    if det["high"]:
        reasons.append(f"{det['high']} high-severity detection(s)")
    if dlp["high"]:
        reasons.append(f"{dlp['high']} high-severity sensitive-data finding(s)")
    if usage["critical"]:
        reasons.append(f"{usage['critical']} user(s) at a spend or token limit")
    if det["medium"]:
        reasons.append(f"{det['medium']} medium-severity detection(s)")
    if dlp["medium"] and not (dlp["critical"] or dlp["high"]):
        reasons.append(f"{dlp['medium']} medium sensitive-data finding(s)")
    if usage["warn"]:
        reasons.append(f"{usage['warn']} usage warning(s)")
    if health_current(health):
        reasons.append("log collection that is not reporting normally")
    elif health_problem(health):
        reasons.append("sync error cycle(s) that have since recovered")
    reasons = reasons[:3]
    if risk == "Low":
        narrative = "The Claude posture is stable, with no condition requiring SOC action during the reporting period."
    else:
        lead = {"Critical": "The Claude posture is critical", "High": "The Claude posture is high", "Medium": "The Claude posture needs attention"}[risk]
        narrative = f"{lead}: {', '.join(reasons)}."
        if risk == "Critical":
            narrative += " Confirm each one with the user or administrator involved and act before the exposure grows."
        elif risk == "High":
            narrative += " Validate each with its owner and remove any unapproved access or data."
        elif health_problem(health) and not (det["medium"] or dlp["medium"] or usage["warn"]):
            narrative += " Nothing here indicates compromise; the sync log should be reviewed."
        else:
            narrative += " None indicates confirmed compromise, but each should be reviewed and closed."

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

    det, dlp, usage = stats["detections"], stats["dlp"], stats["usage_alerts"]
    prompt_data = {
        "period": {"type": report_type, "from": time_from, "to": time_to},
        "risk": stats["risk"],
        "critical_detections": det["critical"], "high_detections": det["high"], "medium_detections": det["medium"],
        "sensitive_data_findings": {"critical": dlp["critical"], "high": dlp["high"], "medium": dlp["medium"],
                                    "categories": [c for c, _n in dlp["categories"]]},   # categories and counts only, never content
        "usage_alerts": {"critical": usage["critical"], "warning": usage["warn"]},
        "collection_healthy": not health_problem(stats["health"]),
        "important_detections": [
            {"severity": severity_name(r["rank"]), "rule": r["rule"], "title": r["title"], "count": r["count"], "users": r["users"][:2]}
            for r in det["rows"][:5]
        ],
    }
    prompt = f"""You are Athena-AI acting as a senior SOC analyst reviewing Claude Enterprise audit, usage and data-loss telemetry.

Create a concise, decision-oriented SOC narrative from this JSON:
{json.dumps(prompt_data, ensure_ascii=False)}

Strict rules:
- Do not mention any metric whose value is zero.
- Do not mention normal, successful, or routine activity.
- Do not restate the complete dataset.
- Explain the current posture (account and key misuse, data exposure, admin changes, usage) and what requires action.
- Keep the narrative to a maximum of 3 short sentences.
- Provide no more than 3 key findings and no more than 3 prioritized recommendations.
- Recommendations must be specific to the supplied detections.
- Do not invent evidence, root cause, compromise, or business impact. Never reproduce sensitive content.

Return only valid JSON:
{{
  "overall_posture": "short label such as High - Data Exfiltration Risk",
  "narrative": "maximum 3 short sentences",
  "key_findings": ["maximum 3 concise actionable findings"],
  "recommended_actions": ["maximum 3 prioritized actions"]
}}"""
    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": "You are a senior SOC analyst specializing in AI-assistant security. Return only concise, valid JSON."},
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
    det, dlp, usage, health = stats["detections"], stats["dlp"], stats["usage_alerts"], stats["health"]
    if det["critical"] == 0 and det["high"] == 0:
        observations.append("No critical or high-severity Claude security detections were raised in the reporting period.")
    if dlp["findings"] == 0:
        observations.append("No sensitive data was found in Claude chats or files.")
    elif dlp["critical"] == 0 and dlp["high"] == 0:
        observations.append("Sensitive-data findings were low or medium severity only.")
    if not health_problem(health) and all(f["seen"] for f in health["feeds"]):
        observations.append("Claude log collection is healthy across the activity, usage and sensitive-data feeds.")
    if usage["critical"] == 0 and usage["warn"] == 0 and len(observations) < 3:
        observations.append("No token or spend limit alerts were raised.")
    if stats["overview"]["total"] > 0 and len(observations) < 3:
        observations.append(f"{stats['overview']['total']:,} Claude activity events were collected and reviewed.")
    return observations[:3]


def build_recommendations(stats, assessment):
    prioritized = []

    def add(category, text):
        if text and not any(existing == category for existing, _ in prioritized):
            prioritized.append((category, text))

    for row in stats["detections"]["rows"]:      # already ordered by severity, then count
        if row["category"] in CATEGORY_RECOMMENDATIONS:
            add(row["category"], CATEGORY_RECOMMENDATIONS[row["category"]])
    dlp = stats["dlp"]
    if dlp["critical"] or dlp["high"] or dlp["medium"]:
        add("dlp", CATEGORY_RECOMMENDATIONS["dlp"])
    if stats["usage_alerts"]["total"] > 0:
        add("usage", CATEGORY_RECOMMENDATIONS["usage"])
    if health_problem(stats["health"]):
        add("sync", "Restore or repair the Claude sync service and confirm fresh heartbeats on all three feeds so activity is monitored."
            if health_current(stats["health"]) else HEALTH_ACTION_PAST)

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


def fmt_tokens(value):
    value = as_int(value)
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.1f}B"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
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
    det, dlp, usage = stats["detections"], stats["dlp"], stats["usage_alerts"]
    cards = []
    if det["critical"] > 0:
        cards.append(metric_card("Critical Detections", fmt_num(det["critical"]), "#991b1b"))
    if det["high"] > 0:
        cards.append(metric_card("High Detections", fmt_num(det["high"]), "#dc2626"))
    if det["medium"] > 0:
        cards.append(metric_card("Medium Detections", fmt_num(det["medium"]), "#d97706"))
    if dlp["findings"] > 0:
        color = "#991b1b" if dlp["critical"] else "#dc2626" if dlp["high"] else "#d97706"
        cards.append(metric_card("Sensitive Data Findings", fmt_num(dlp["findings"]), color))
    if usage["total"] > 0:
        cards.append(metric_card("Usage Alerts", fmt_num(usage["total"]), "#dc2626" if usage["critical"] else "#d97706"))
    if health_problem(stats["health"]):
        cards.append(metric_card("Collection Issue", "Yes", "#dc2626"))
    if not cards:
        cards.append(metric_card("Detections Requiring Action", "0", "#059669"))
    width = max(1, min(len(cards), 6))
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


def note(text):
    return f"<p style='margin:8px 0 0 0;color:#64748b;font-size:12px;'>{esc(text)}</p>"


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


def detection_who(row):
    who = ", ".join(row["users"]) or ", ".join(f"API key {k[:22]}" for k in row["keys"]) or "N/A"
    extra = f"{row['ips']} IP(s)" if row["ips"] > 1 else (row["country"] or "")
    return who, extra


def rows_by_rank(stats, rank):
    return [r for r in stats["detections"]["rows"] if r["rank"] == rank]


def build_detection_table(rows):
    out = []
    for row in rows[:MAX_DETAIL_ROWS]:
        who, extra = detection_who(row)
        out.append([
            esc(format_timestamp(row["last"])),
            f"<b>{esc(row['title'])}</b><div style='color:#64748b;'>Rule {esc(row['rule'])} &middot; level {esc(row['level'])}</div>",
            esc(row["count"]),
            esc(who) + (f"<div style='color:#64748b;'>{esc(extra)}</div>" if extra else ""),
            esc(row["action"]),
        ])
    more = len(rows) - MAX_DETAIL_ROWS
    return table(["Latest", "Detection", "Count", "User / Source", "Required Action"], out) + (note(f"+ {more} more rule(s) not shown.") if more > 0 else "")


def build_dlp_html(dlp):
    sev = [(name, dlp[name]) for name in ("critical", "high", "medium", "low") if dlp[name] > 0]
    summary = " &middot; ".join(f"{esc(name.title())} {fmt_num(count)}" for name, count in sev)
    cats = ", ".join(f"{name} {fmt_num(count)}" for name, count in dlp["categories"])
    users = []
    for user in dlp["users"][:MAX_DETAIL_ROWS]:
        color = {"critical": "#991b1b", "high": "#dc2626", "medium": "#d97706"}.get(user["severity"], "#64748b")
        users.append([esc(user["user"]), esc(user["count"]), esc(", ".join(user["categories"]) or "N/A"),
                      f"<span style='color:{color};font-weight:700;'>{esc(user['severity'].title())}</span>"])
    return (f"<p style='margin:0 0 10px 0;color:#475569;font-size:13px;'>{fmt_num(dlp['findings'])} distinct finding(s): {summary}. "
            f"Categories: {esc(cats)}.</p>"
            + table(["User", "Findings", "Categories", "Highest severity"], users)
            + f"<p style='margin:10px 0 0 0;font-size:12px;'><b>Required action:</b> {esc(DLP_ACTION)}</p>"
            + note("Counts, users and categories only; the sensitive content is never included in this report."))


def build_usage_html(stats):
    usage, alerts, spend = stats["usage"], stats["usage_alerts"], stats["spend"]
    parts = []
    if alerts["rows"]:
        rows = []
        for row in alerts["rows"][:MAX_DETAIL_ROWS]:
            color = "#dc2626" if row["level"] == "critical" else "#d97706"
            what = "Spend limit" if row["scope"] == "user_spend" else f"Token usage ({row['scope'].replace('_', ' ')})"
            value = (f"${row['value'] / 100:,.2f} of ${row['limit'] / 100:,.2f}" if row["metric"] == "spend_cents"
                     else f"{fmt_tokens(row['value'])} of {fmt_tokens(row['limit'])} tokens")
            rows.append([f"<span style='color:{color};font-weight:700;'>{esc(row['level'].title())}</span>", esc(what), esc(row["user"] or "N/A"),
                         esc(f"{value} ({row['percent']:.0f}%)"), esc(row["count"]), esc(format_timestamp(row["last"]))])
        parts.append(table(["Level", "Alert", "User / scope", "Reached", "Alerts", "Latest"], rows)
                     + f"<p style='margin:10px 0 0 0;font-size:12px;'><b>Required action:</b> {esc(USAGE_ACTION)}</p>")
    if usage["tokens"] > 0:
        rows = [[esc(u["user"]), esc(fmt_tokens(u["tokens"])), esc(fmt_num(u["requests"]))] for u in usage["users"]]
        models = ", ".join(f"{name} {fmt_tokens(tokens)}" for name, tokens in usage["models"])
        parts.append(f"<div style='margin:{'14px' if parts else '0'} 0 6px 0;font-weight:700;font-size:13px;'>Top users by tokens "
                     f"({esc(fmt_tokens(usage['tokens']))} tokens, {esc(fmt_num(usage['requests']))} requests in the period; top models: {esc(models)})</div>"
                     + table(["User", "Tokens", "Requests"], rows))
    if spend["rows"] and (alerts["rows"] or usage["tokens"] > 0):
        rows = [[esc(r["user"]), esc(f"${r['spent']:,.2f}"), esc(f"${r['limit']:,.2f}" if r["limit"] else "no limit"),
                 esc(f"{r['percent']:.0f}%" if r["limit"] else "n/a")] for r in spend["rows"]]
        parts.append(f"<div style='margin:14px 0 6px 0;font-weight:700;font-size:13px;'>Spend, month to date ({esc(spend['month'])})</div>"
                     + table(["User", "Spent", "Monthly limit", "Of limit"], rows))
    if usage["truncated"]:
        parts.append(note("The usage list hit the row cap; token totals may be incomplete."))
    return "".join(parts)


def build_admin_table(changes):
    rows = [[esc(c["event"]), esc(c["count"]), esc(", ".join(c["users"]) or "N/A"), esc(format_timestamp(c["last"]))] for c in changes]
    return table(["Admin / access change", "Count", "Performed by", "Latest"], rows)


def build_glance_html(stats):
    ov, usage, dlp = stats["overview"], stats["usage"], stats["dlp"]
    types = ", ".join(f"{name} {fmt_num(count)}" for name, count in ov["types"][:5]) or "none"
    countries = ", ".join(f"{name} {fmt_num(count)}" for name, count in ov["countries"][:5]) or "none"
    cells = [("Activity events", fmt_num(ov["total"])), ("Active users", fmt_num(ov["active_users"]))]
    if ov["kinds"].get("chats"):
        cells.append(("Chats created", fmt_num(ov["kinds"]["chats"])))
    if ov["kinds"].get("uploads"):
        cells.append(("Files uploaded", fmt_num(ov["kinds"]["uploads"])))
    if usage["tokens"]:
        cells.append(("Tokens used", f"{fmt_tokens(usage['tokens'])} by {fmt_num(usage['active_users'])} user(s)"))
    cells += [("Top event types", types), ("Source countries", countries)]
    rows = "".join(
        f"<tr><td style='padding:6px 8px;color:#64748b;font-size:12px;width:150px;'>{esc(k)}</td>"
        f"<td style='padding:6px 8px;font-size:13px;color:#0f172a;'>{esc(v)}</td></tr>"
        for k, v in cells
    )
    return section(
        "Activity at a Glance",
        f"<table width='100%' cellpadding='0' cellspacing='0'>{rows}</table>"
        + note("Routine activity is summarised only; the sections above list exceptions. The sync service's own polls are excluded."),
        "#475569",
    )


def build_collection_html(health):
    feeds = health["feeds"]
    if not health_problem(health):
        last = max((f["last"] for f in feeds if f["last"]), default=None)
        return (
            "<table width='100%' cellpadding='0' cellspacing='0' style='background:#ecfdf5;border:1px solid #a7f3d0;border-radius:8px;margin:14px 0;'>"
            "<tr><td style='padding:12px 18px;color:#065f46;font-size:13px;font-weight:700;'>"
            f"Log collection healthy - all three feeds report; last heartbeat {esc(format_timestamp(last))}.</td></tr></table>"
        )
    rows = []
    for feed in feeds:
        if not feed["seen"]:
            state, color = "No heartbeat ever seen", "#dc2626"
        elif feed["stale"]:
            state, color = f"Stale ({feed['age_minutes']} min)", "#dc2626"
        elif feed_current_problem(feed):
            state, color = (feed["status"] or "warning").title(), "#dc2626"
        elif feed_problem(feed):
            state, color = "Reporting (earlier errors)", "#d97706"
        else:
            state, color = "Healthy", "#059669"
        detail = feed["error"] or (f"{feed['errors_in_period']} error cycle(s) in the period" if feed["errors_in_period"] else "")
        rows.append([esc(feed["label"]), f"<span style='color:{color};font-weight:700;'>{esc(state)}</span>",
                     esc(format_timestamp(feed["last"])), esc(detail or "-")])
    body = table(["Feed", "State", "Last heartbeat", "Detail"], rows)
    if health["failed_polls"] > 0:
        body += note(f"The sync service's Compliance API poll failed {health['failed_polls']} time(s) in the period.")
    return section("Log Collection Needs Attention", body, "#dc2626")


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
        <div style="font-weight:700;font-size:16px;color:#134e4a;margin-bottom:12px;">Claude Security &amp; Operational Recommendations</div>
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


def has_exceptions(stats):
    return bool(stats["detections"]["rows"] or stats["dlp"]["findings"] or stats["usage_alerts"]["total"])


def build_html_report(report_type, time_from, time_to, stats, assessment):
    from_date = parse_datetime(time_from).strftime("%B %d, %Y %H:%M UTC")
    to_date = parse_datetime(time_to).strftime("%B %d, %Y %H:%M UTC")

    sections = []
    for rank, accent in ((4, "#991b1b"), (3, "#dc2626"), (2, "#d97706")):
        rows = rows_by_rank(stats, rank)
        if rows:
            sections.append(section(f"{severity_name(rank)} Security Detections", build_detection_table(rows), accent))
    if stats["dlp"]["findings"] > 0:
        sections.append(section("Sensitive Data (DLP) Findings", build_dlp_html(stats["dlp"]), "#7c2d12"))
    usage_html = build_usage_html(stats)
    if usage_html:
        sections.append(section("Usage Insights", usage_html, "#6d28d9"))
    if stats["admin"]["changes"]:
        sections.append(section("Admin and Access Changes", build_admin_table(stats["admin"]["changes"]), "#0d47a1"))

    top = ""
    if not has_exceptions(stats):
        top = """
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#ecfdf5;border:1px solid #a7f3d0;border-radius:8px;margin:14px 0;">
          <tr><td style="padding:15px 18px;color:#065f46;font-size:14px;font-weight:700;">
            No Claude detections, sensitive-data findings or usage alerts require action in this reporting period.
          </td></tr>
        </table>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:Arial,sans-serif;color:#334155;">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:1100px;background:#f8fafc;">
      <tr><td style="background:#0d47a1;color:#fff;padding:16px 22px;">
        <div style="font-size:20px;font-weight:700;">{esc(ATHENA_NAME)} &mdash; Claude Enterprise Security Report</div>
        <div style="font-size:12px;margin-top:5px;">Tenant: {esc(TENANT_NAME)} &nbsp;|&nbsp; {esc(report_type.title())} &nbsp;|&nbsp; Overall Risk: {esc(stats['risk'])}</div>
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
        {build_collection_html(stats['health'])}
        {build_glance_html(stats)}
        {build_recommendations_html(stats, assessment)}
      </td></tr>
    </table>
  </td></tr></table>
</body>
</html>"""


def build_plain_report(report_type, time_from, time_to, stats, assessment):
    lines = [
        f"{ATHENA_NAME} - {report_type.upper()} CLAUDE ENTERPRISE REPORT",
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
        rows = rows_by_rank(stats, rank)
        if rows:
            lines.extend(["", f"{severity_name(rank).upper()} SECURITY DETECTIONS"])
            for row in rows[:MAX_DETAIL_ROWS]:
                who, extra = detection_who(row)
                lines.append(
                    f"- {format_timestamp(row['last'])} | {row['title']} (rule {row['rule']}, level {row['level']}) x{row['count']} | "
                    f"{who}{' / ' + extra if extra else ''} | Action: {row['action']}"
                )

    dlp = stats["dlp"]
    if dlp["findings"] > 0:
        sev = ", ".join(f"{name} {dlp[name]}" for name in ("critical", "high", "medium", "low") if dlp[name] > 0)
        lines.extend(["", "SENSITIVE DATA (DLP) FINDINGS",
                      f"- {fmt_num(dlp['findings'])} distinct finding(s): {sev}",
                      "- Categories: " + ", ".join(f"{n} {c}" for n, c in dlp["categories"])])
        for user in dlp["users"][:MAX_DETAIL_ROWS]:
            lines.append(f"- {user['user']} | {user['count']} finding(s) | {', '.join(user['categories'])} | highest {user['severity']}")
        lines.append(f"- Action: {DLP_ACTION}")
        lines.append("- (Counts, users and categories only; the sensitive content is never included.)")

    usage, alerts, spend = stats["usage"], stats["usage_alerts"], stats["spend"]
    if alerts["rows"] or usage["tokens"] > 0:
        lines.extend(["", "USAGE INSIGHTS"])
        for row in alerts["rows"][:MAX_DETAIL_ROWS]:
            what = "spend limit" if row["scope"] == "user_spend" else f"token usage ({row['scope'].replace('_', ' ')})"
            lines.append(f"- {row['level'].upper()} {what}: {row['user'] or 'N/A'} at {row['percent']:.0f}% (x{row['count']}, latest {format_timestamp(row['last'])})")
        if alerts["rows"]:
            lines.append(f"- Action: {USAGE_ACTION}")
        if usage["tokens"] > 0:
            lines.append(f"- Tokens in period: {fmt_tokens(usage['tokens'])} across {fmt_num(usage['requests'])} requests")
            lines.extend(f"- Top user: {u['user']} | {fmt_tokens(u['tokens'])} tokens | {fmt_num(u['requests'])} requests" for u in usage["users"][:3])
        for r in spend["rows"][:3]:
            lines.append(f"- Spend {spend['month']}: {r['user']} ${r['spent']:,.2f}" + (f" of ${r['limit']:,.2f} ({r['percent']:.0f}%)" if r["limit"] else ""))

    if stats["admin"]["changes"]:
        lines.extend(["", "ADMIN AND ACCESS CHANGES"])
        for change in stats["admin"]["changes"]:
            lines.append(f"- {change['event']} x{change['count']} by {', '.join(change['users']) or 'N/A'} (latest {format_timestamp(change['last'])})")

    health = stats["health"]
    lines.extend(["", "LOG COLLECTION"])
    if health_problem(health):
        lines.extend(f"- {line}" for line in health_issue_lines(health))
    else:
        last = max((f["last"] for f in health["feeds"] if f["last"]), default=None)
        lines.append(f"- Healthy on all three feeds, last heartbeat {format_timestamp(last)}.")

    ov = stats["overview"]
    glance = [f"- Activity events: {fmt_num(ov['total'])} | Active users: {fmt_num(ov['active_users'])}"]
    kinds = " | ".join(f"{label}: {fmt_num(ov['kinds'][key])}" for key, label in (("chats", "Chats created"), ("uploads", "Files uploaded")) if ov["kinds"].get(key))
    if kinds:
        glance.append("- " + kinds)
    if stats["usage"]["tokens"]:
        glance.append(f"- Tokens used: {fmt_tokens(stats['usage']['tokens'])} by {fmt_num(stats['usage']['active_users'])} user(s)")
    glance.append("- Top event types: " + (", ".join(f"{n} {fmt_num(c)}" for n, c in ov["types"][:5]) or "none"))
    glance.append("- Source countries: " + (", ".join(f"{n} {fmt_num(c)}" for n, c in ov["countries"][:5]) or "none"))
    lines.extend(["", "ACTIVITY AT A GLANCE"] + glance)

    lines.extend(["", "CLAUDE SECURITY & OPERATIONAL RECOMMENDATIONS", "Positive Observations:"])
    positives = build_positive_observations(stats)
    lines.extend(f"- {i}" for i in positives) if positives else lines.append("- No positive operational observation is available for this period.")
    lines.append("Prioritized Recommendations:")
    recs = build_recommendations(stats, assessment)
    lines.extend(f"- {i}" for i in recs) if recs else lines.append("- No priority remediation action is required for this period.")

    if not has_exceptions(stats) and not health_problem(health):
        lines.extend(["", "No Claude condition requiring SOC action was identified."])
    lines.extend(["", f"Report version: {REPORT_VERSION}"])
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Output, delivery, entry point
# -----------------------------------------------------------------------------
def save_report_files(report_type, time_from, html_body, plain_body):
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
    date_label = parse_datetime(time_from).strftime("%Y%m%d")
    base = os.path.join(REPORT_OUTPUT_DIR, f"claude_{report_type}_{date_label}")
    with open(f"{base}.html", "w", encoding="utf-8") as handle:
        handle.write(html_body)
    with open(f"{base}.txt", "w", encoding="utf-8") as handle:
        handle.write(plain_body)
    log(f"Saved Claude report files: {base}.html, {base}.txt")


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
        log(f"Claude report sent successfully to {recipients}")
        return True
    except Exception as exc:
        log(f"Error sending Claude report email: {exc}")
        return False


def generate_report(report_type, time_from, time_to, recipients):
    log(f"Generating {report_type} Claude report from {time_from} to {time_to}")
    stats = collect_stats(time_from, time_to)
    assessment = get_ai_soc_assessment(stats, report_type, time_from, time_to) or build_rule_based_soc_assessment(stats)
    log("Athena-AI Insights section prepared for Claude report")

    html_body = build_html_report(report_type, time_from, time_to, stats, assessment)
    plain_body = build_plain_report(report_type, time_from, time_to, stats, assessment)
    date_label = parse_datetime(time_from).strftime("%b %d, %Y")
    subject = f"[{TENANT_NAME}] Athena SOC {report_type.title()} Claude Enterprise Report - {date_label}"

    delivered, saved = False, False
    if REPORT_CLAUDE_SEND_EMAIL:
        delivered = send_email(recipients, subject, plain_body, html_body)
        if not delivered:
            log("Email delivery failed; saving a local copy of the generated Claude report")
            save_report_files(report_type, time_from, html_body, plain_body)
            saved = True
    else:
        log("REPORT_CLAUDE_SEND_EMAIL=false; email delivery skipped")
    if REPORT_CLAUDE_SAVE_OUTPUT and not saved:
        save_report_files(report_type, time_from, html_body, plain_body)
    return delivered if REPORT_CLAUDE_SEND_EMAIL else True


def resolve_period(args):
    if len(args) < 2:
        raise ValueError("Usage: reports_claude.py <daily|weekly|monthly|custom> [start_time] [end_time]")
    report_type = args[1].lower()
    now = datetime.now(timezone.utc)
    spans = {"daily": 1, "weekly": 7, "monthly": 30}
    if report_type in spans:
        return (report_type,
                (now - timedelta(days=spans[report_type])).isoformat().replace("+00:00", "Z"),
                now.isoformat().replace("+00:00", "Z"))
    if report_type == "custom":
        if len(args) < 4:
            raise ValueError("Custom report requires: reports_claude.py custom <start_time> <end_time>")
        start, end = parse_datetime(args[2]), parse_datetime(args[3])
        if not start or not end:
            raise ValueError("Custom start_time and end_time must be valid ISO-8601 timestamps")
        if start >= end:
            raise ValueError("Custom start_time must be earlier than end_time")
        return report_type, args[2], args[3]
    raise ValueError(f"Unknown report type: {report_type}")


def validate_runtime_configuration(recipients):
    if not REPORT_CLAUDE_SEND_EMAIL:
        return
    missing = [name for name, ok in (("SMTP_RECIPIENT", recipients), ("SMTP_USERNAME", SMTP_USERNAME), ("SMTP_PASSWORD", SMTP_PASSWORD)) if not ok]
    if missing:
        raise ReportConfigurationError("Missing required email configuration: " + ", ".join(missing))


def main(args):
    if not REPORT_CLAUDE_ENABLED:
        log("REPORT_CLAUDE_ENABLED=false; skipping Claude report")
        return 0
    try:
        report_type, time_from, time_to = resolve_period(args)
        validate_runtime_configuration(SMTP_RECIPIENT)
        log(f"Claude report version: {REPORT_VERSION}")
        log(f"Recipients: {SMTP_RECIPIENT}")
        success = generate_report(report_type, time_from, time_to, SMTP_RECIPIENT)
    except (ReportConfigurationError, ReportDataError, ValueError) as exc:
        log(f"Claude report aborted: {exc}")
        return 1
    if not success:
        log("Claude report generation or delivery did not complete successfully")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:
        log(f"Unhandled exception: {exc}")
        sys.exit(1)
