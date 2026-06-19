import streamlit as st
import pandas as pd
import requests
import time

# =========================================================
# UI HEADER
# =========================================================
st.set_page_config(page_title="RetrieverLabs", layout="wide")

st.markdown(
    """
    <div style="text-align: left; padding-bottom: 10px;">
        <h1 style="margin-bottom: 0px;">Package Exposure Analyzer</h1>
        <div style="font-size: 14px; color: #888;">
            RetrieverLabs • Supply Chain Intelligence
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# =========================================================
# TOGGLES
# =========================================================
show_deps = st.checkbox("Enable Dependency View (1-level only)")
expand_ioc = st.checkbox("Expand IOC with dependencies")

st.caption("OSV + npm registry + exposure signals + dependency surface + IOC export")

# =========================================================
# HELPERS
# =========================================================
def format_number(n):
    if n is None:
        return "0"
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)


def risk_score(osv, downloads, exists):
    score = 0

    if osv["is_malicious"]:
        score += 70

    if downloads > 1_000_000:
        score += 15
    elif downloads > 100_000:
        score += 10
    elif downloads > 10_000:
        score += 5

    if not exists:
        score += 15

    return min(score, 100)


def risk_label(score):
    if score >= 70:
        return "🔴 HIGH"
    if score >= 40:
        return "🟠 MEDIUM"
    return "🟢 LOW"


def normalize_packages(raw_text):
    raw_text = raw_text.replace("\n", ",")
    return [p.strip() for p in raw_text.split(",") if p.strip()]


def chunk_list(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


# =========================================================
# OSV
# =========================================================
@st.cache_data(ttl=3600)
def check_osv(package):
    url = "https://api.osv.dev/v1/query"

    payload = {
        "package": {
            "name": package,
            "ecosystem": "npm"
        }
    }

    try:
        r = requests.post(url, json=payload, timeout=10)
        data = r.json()

        vulns = data.get("vulns", [])

        if not vulns:
            return {
                "is_malicious": False,
                "id": None,
                "published": "-",
                "summary": "-",
                "aliases": [],
                "references": [],
                "affected": [],
                "fixed": []
            }

        v = vulns[0]

        affected = []
        fixed = []

        for aff in v.get("affected", []):
            affected += aff.get("versions", [])

            for rge in aff.get("ranges", []):
                for ev in rge.get("events", []):
                    if "fixed" in ev:
                        fixed.append(ev["fixed"])

        refs = []
        for r_item in v.get("references", []):
            if r_item.get("url"):
                refs.append(r_item["url"])

        return {
            "is_malicious": True,
            "id": v.get("id"),
            "published": v.get("published", "-"),
            "summary": v.get("summary") or v.get("details") or "-",
            "aliases": v.get("aliases", []),
            "references": refs,
            "affected": list(set(affected)),
            "fixed": list(set(fixed))
        }

    except Exception:
        return {
            "is_malicious": False,
            "id": None,
            "published": "-",
            "summary": "-",
            "aliases": [],
            "references": [],
            "affected": [],
            "fixed": []
        }


# =========================================================
# NPM REGISTRY (with dependencies)
# =========================================================
@st.cache_data(ttl=3600)
def check_npm(package):
    try:
        r = requests.get(f"https://registry.npmjs.org/{package}", timeout=10)

        if r.status_code != 200:
            return {
                "exists": False,
                "latest": None,
                "dependencies": {}
            }

        data = r.json()
        latest = data.get("dist-tags", {}).get("latest")

        deps = {}
        try:
            deps = data.get("versions", {}).get(latest, {}).get("dependencies", {}) or {}
        except Exception:
            deps = {}

        return {
            "exists": True,
            "latest": latest,
            "dependencies": deps
        }

    except Exception:
        return {
            "exists": False,
            "latest": None,
            "dependencies": {}
        }


# =========================================================
# DOWNLOADS
# =========================================================
@st.cache_data(ttl=3600)
def check_downloads(package):
    try:
        r = requests.get(
            f"https://api.npmjs.org/downloads/point/last-month/{package}",
            timeout=10
        )

        if r.status_code != 200:
            return {"downloads": 0}

        return {"downloads": r.json().get("downloads", 0)}

    except Exception:
        return {"downloads": 0}


# =========================================================
# IOC EXPORTER
# =========================================================
def splunk_ioc_export(packages, npm_cache):
    iocs = set()

    for p in packages:
        iocs.add(f"{p}*")

        if expand_ioc and p in npm_cache:
            deps = npm_cache[p].get("dependencies", {})
            for d in list(deps.keys()):
                iocs.add(f"{d}*")

    return "\n".join(sorted(iocs))


# =========================================================
# INPUT
# =========================================================
raw = st.text_area("Paste npm packages (comma or newline, 100–400+)")

if raw:

    packages = normalize_packages(raw)
    packages = list(set(packages))

    rows = []
    npm_cache = {}

    total_downloads = 0
    high_risk = 0

    BATCH_SIZE = 20
    DELAY = 0.15

    batches = list(chunk_list(packages, BATCH_SIZE))

    progress = st.progress(0)
    status = st.empty()

    processed = 0
    total = len(packages)

    # =====================================================
    # PROCESSING
    # =====================================================
    for i, batch in enumerate(batches):

        status.text(f"Processing batch {i+1}/{len(batches)}")

        for pkg in batch:

            osv = check_osv(pkg)
            npm = check_npm(pkg)
            dl = check_downloads(pkg)

            npm_cache[pkg] = npm

            downloads = dl["downloads"]
            total_downloads += downloads

            score = risk_score(osv, downloads, npm["exists"])

            if score >= 70:
                high_risk += 1

            dep_list = ""
            if show_deps and npm["dependencies"]:
                dep_list = ", ".join(list(npm["dependencies"].keys())[:15])

            rows.append({
                "Package": pkg,
                "Risk": risk_label(score),
                "Score": score,

                "OSV ID": osv["id"] or "-",
                "Published": osv["published"],
                "Summary": osv["summary"],

                "Aliases": ", ".join(osv["aliases"]) if osv["aliases"] else "-",

                "References": "\n".join(osv["references"]) if osv["references"] else "-",

                "npm Exists": "YES" if npm["exists"] else "NO",
                "Latest Version": npm["latest"] or "-",

                "Downloads (30d)": format_number(downloads),

                "Dependencies (1-level)": dep_list if show_deps else "-",

                "Affected Versions": "\n".join(osv["affected"]) if osv["affected"] else "-",
                "Fixed Versions": "\n".join(osv["fixed"]) if osv["fixed"] else "-"
            })

            processed += 1
            progress.progress(processed / total)

        time.sleep(DELAY)

    status.text("Analysis complete")

    df = pd.DataFrame(rows)

    # =====================================================
    # METRICS
    # =====================================================
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Packages", len(packages))

    with col2:
        st.metric("High Risk", high_risk)

    with col3:
        st.metric("Total Exposure (30d)", format_number(total_downloads))

    st.divider()

    st.dataframe(df, use_container_width=True, height=650)

    # =====================================================
    # IOC EXPORT
    # =====================================================
    st.divider()
    st.subheader("Splunk IOC Export (Wildcard)")

    st.code(splunk_ioc_export(packages, npm_cache), language="text")