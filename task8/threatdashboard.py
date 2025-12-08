#!/usr/bin/env python3
"""
Unified Threat Intelligence & Hunting Dashboard
- Pull IOCs (example/test IPs/domains/hashes)
- Normalize them
- Enrich (optional)
- Score and correlate
- Generate a simple Plotly HTML dashboard
- Save JSONL output
"""

import json, uuid
import pandas as pd
from plotly.subplots import make_subplots
import plotly.graph_objs as go
from datetime import datetime, timedelta


try:
    import whois
    ENABLE_WHOIS = True
except:
    ENABLE_WHOIS = False

ENABLE_GEOIP = False  # placeholder

# ============================================================
# TEST DATA 
# ============================================================

# Sample IOCs
sample_iocs = [
    # OTX-like IP
    {
        "ioc_id": str(uuid.uuid4()),
        "ioc_type": "ip",
        "ioc_value": "8.8.8.8",
        "source": "otx",
        "first_seen": "2025-12-01T12:00:00Z",
        "last_seen": "2025-12-06T12:00:00Z",
        "observed_count": 12,
        "tags": ["c2"],
        "enrichment": {"otx_pulses": ["pulse1","pulse2"]},
        "correlation": {}
    },
    # AbuseIPDB-like IP
    {
        "ioc_id": str(uuid.uuid4()),
        "ioc_type": "ip",
        "ioc_value": "203.0.113.5",
        "source": "abuseipdb",
        "first_seen": "2025-11-25T09:00:00Z",
        "last_seen": None,
        "observed_count": 7,
        "tags": [],
        "enrichment": {"abuse_score": 78},
        "correlation": {}
    },
    # MISP-like domain
    {
        "ioc_id": str(uuid.uuid4()),
        "ioc_type": "domain",
        "ioc_value": "bad-domain.example",
        "source": "misp",
        "first_seen": "2025-11-20T10:00:00Z",
        "last_seen": None,
        "observed_count": 5,
        "tags": ["phishing"],
        "enrichment": {},
        "correlation": {}
    },
]

def enrich_whois(domain):
    if not ENABLE_WHOIS:
        return {}
    try:
        w = whois.whois(domain)
        return {"registrar": w.registrar, "created": str(w.creation_date)}
    except:
        return {}

# ============================================================
# Compute simple score
# ============================================================
def compute_score(df):
    df["observed_count"] = df["observed_count"].fillna(0).astype(int)
    df["abuse_score"] = df["enrichment"].apply(lambda e: e.get("abuse_score", 0) if isinstance(e, dict) else 0)
    df["otx_count"] = df["enrichment"].apply(lambda e: len(e.get("otx_pulses",[])) if isinstance(e, dict) else 0)

    max_obs = df["observed_count"].max() or 1
    max_otx = df["otx_count"].max() or 1

    df["score"] = (
        0.4 * (df["observed_count"] / max_obs) +
        0.4 * (df["abuse_score"] / 100) +
        0.2 * (df["otx_count"] / max_otx)
    )
    return df

# ============================================================
# Build Plotly dashboard
# ============================================================
def build_dashboard(df):
    # Fix last_seen NaT by filling from first_seen or now
    df["last_seen"] = pd.to_datetime(df["last_seen"], errors="coerce")
    df["first_seen"] = pd.to_datetime(df["first_seen"], errors="coerce")
    df["last_seen"] = df["last_seen"].fillna(df["first_seen"])
    df["last_seen"] = df["last_seen"].fillna(pd.Timestamp.now())

    # Time series: count per day
    ts = df.groupby(pd.Grouper(key="last_seen", freq="D")).size().rename("count").reset_index()

    # Top IPs
    ip_counts = df[df["ioc_type"]=="ip"].groupby("ioc_value")["observed_count"].sum().nlargest(15)

    # Plot
    fig = make_subplots(rows=2, cols=1, subplot_titles=("IOC Trend (per day)","Top IP Observed Count"))
    fig.add_trace(go.Scatter(x=ts["last_seen"], y=ts["count"], name="Daily IOC Count"), row=1, col=1)
    fig.add_trace(go.Bar(x=ip_counts.index, y=ip_counts.values, name="Top IPs"), row=2, col=1)

    fig.update_layout(height=700, title="Unified Threat Intelligence Dashboard")
    fig.write_html("dashboard.html")
    print("✔ Dashboard generated: dashboard.html")

# ============================================================
# Main
# ============================================================
def main():
    print("\n=== Threat Dashboard Starting ===")
    iocs = sample_iocs

    # Optional enrichment for domains
    for idx, row in enumerate(iocs):
        if row["ioc_type"]=="domain" and ENABLE_WHOIS:
            iocs[idx]["enrichment"].update(enrich_whois(row["ioc_value"]))

    # Build DataFrame
    df = pd.DataFrame(iocs)

    # Compute scores
    df = compute_score(df)

    # Save JSONL
    with open("iocs_enriched.jsonl","w") as f:
        for _, row in df.iterrows():
            f.write(json.dumps(row.to_dict())+"\n")
    print("✔ Enriched IOCs saved: iocs_enriched.jsonl")

    # Build dashboard
    build_dashboard(df)

    print("\n=== Done ===\n")

if __name__ == "__main__":
    main()
