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

st.caption("OSV + npm + PyPI registry + exposure signals + dependency surface + IOC export")

# =========================================================
# HELPERS
# =========================================================

def normalize_packages(raw_text):
    raw_text = raw_text.replace("\n", ",")
    pkgs = [p.strip() for p in raw_text.split(",") if p.strip()]
    return list(dict.fromkeys(pkgs))  # preserve order


def risk_label(score):
    if score >= 70:
        return "🔴 HIGH"
    if score >= 40:
        return "🟠 MEDIUM"
    return "🟢 LOW"


def risk_score(osv, exists):
    score = 0

    if osv["has_findings"]:
        score += 70

    if not exists:
        score += 15

    return min(score, 100)


# =========================================================
# REGISTRY DETECTION
# =========================================================

def detect_ecosystem(package):

    npm = False
    pypi = False

    try:
        npm = requests.get(
            f"https://registry.npmjs.org/{package}",
            timeout=5
        ).status_code == 200
    except:
        pass

    try:
        pypi = requests.get(
            f"https://pypi.org/pypi/{package}/json",
            timeout=5
        ).status_code == 200
    except:
        pass

    if npm and pypi:
        return "Both"
    if npm:
        return "npm"
    if pypi:
        return "PyPI"
    return "Unknown"


# =========================================================
# NPM
# =========================================================

@st.cache_data(ttl=3600)
def check_npm(package):

    try:
        r = requests.get(f"https://registry.npmjs.org/{package}", timeout=10)

        if r.status_code != 200:
            return {"exists": False, "latest": None, "dependencies": {}}

        data = r.json()
        latest = data.get("dist-tags", {}).get("latest")
        deps = data.get("versions", {}).get(latest, {}).get("dependencies", {}) or {}

        return {
            "exists": True,
            "latest": latest,
            "dependencies": deps
        }

    except:
        return {"exists": False, "latest": None, "dependencies": {}}


# =========================================================
# PYPI
# =========================================================

@st.cache_data(ttl=3600)
def check_pypi(package):

    try:
        r = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=10)

        if r.status_code != 200:
            return {"exists": False, "latest": None, "summary": None}

        data = r.json()["info"]

        return {
            "exists": True,
            "latest": data.get("version"),
            "summary": data.get("summary"),
            "url": f"https://pypi.org/project/{package}/"
        }

    except:
        return {"exists": False, "latest": None, "summary": None}


# =========================================================
# OSV CHECK
# =========================================================

@st.cache_data(ttl=3600)
def check_osv(package, ecosystem):

    try:
        r = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package, "ecosystem": ecosystem}},
            timeout=10
        )

        data = r.json()
        vulns = data.get("vulns", [])

        if not vulns:
            return {
                "has_findings": False,
                "id": None,
                "published": "-",
                "summary": "-",
                "aliases": [],
                "affected": [],
                "fixed": [],
                "references": []
            }

        v = vulns[0]

        affected = []
        fixed = []
        refs = []

        for aff in v.get("affected", []):
            affected += aff.get("versions", [])

            for rge in aff.get("ranges", []):
                for ev in rge.get("events", []):
                    if "fixed" in ev:
                        fixed.append(ev["fixed"])

        for r_item in v.get("references", []):
            url = r_item.get("url")
            if url:
                refs.append(url)

        return {
            "has_findings": True,
            "id": v.get("id"),
            "published": v.get("published", "-"),
            "summary": v.get("summary") or v.get("details") or "-",
            "aliases": v.get("aliases", []),
            "affected": list(set(affected)),
            "fixed": list(set(fixed)),
            "references": refs
        }

    except:
        return {
            "has_findings": False,
            "id": None,
            "published": "-",
            "summary": "-",
            "aliases": [],
            "affected": [],
            "fixed": [],
            "references": []
        }


# =========================================================
# OSV MERGE
# =========================================================

def merge_osv(osv_list):

    merged = {
        "has_findings": False,
        "id": [],
        "published": [],
        "aliases": [],
        "affected": [],
        "fixed": [],
        "references": [],
        "summary": []
    }

    for o in osv_list:

        if o["has_findings"]:
            merged["has_findings"] = True

        merged["id"].append(o.get("id"))
        merged["published"].append(o.get("published"))
        merged["aliases"].extend(o.get("aliases", []))
        merged["affected"].extend(o.get("affected", []))
        merged["fixed"].extend(o.get("fixed", []))
        merged["references"].extend(o.get("references", []))
        merged["summary"].append(o.get("summary", ""))

    return {
        "has_findings": merged["has_findings"],
        "id": ", ".join([x for x in merged["id"] if x]),
        "published": ", ".join([x for x in merged["published"] if x and x != "-"]),
        "aliases": list(set(merged["aliases"])),
        "affected": list(set(merged["affected"])),
        "fixed": list(set(merged["fixed"])),
        "references": list(set(merged["references"])),
        "summary": " | ".join([s for s in merged["summary"] if s and s != "-"]) or "-"
    }


# =========================================================
# INPUT
# =========================================================

raw = st.text_area("Paste package names (comma or newline)")

if raw:

    packages = normalize_packages(raw)

    rows = []
    progress = st.progress(0)
    status = st.empty()

    high_risk = 0
    total = len(packages)

    for i, pkg in enumerate(packages):

        status.text(f"Processing {i+1}/{total}")

        ecosystem = detect_ecosystem(pkg)

        npm = check_npm(pkg) if ecosystem in ["npm", "Both"] else {"exists": False, "latest": None, "dependencies": {}}
        pypi = check_pypi(pkg) if ecosystem in ["PyPI", "Both"] else {"exists": False, "latest": None, "summary": None}

        osv_results = []

        if ecosystem in ["npm", "Both"]:
            osv_results.append(check_osv(pkg, "npm"))

        if ecosystem in ["PyPI", "Both"]:
            osv_results.append(check_osv(pkg, "PyPI"))

        osv = merge_osv(osv_results)

        score = risk_score(osv, npm["exists"] or pypi["exists"])

        if score >= 70:
            high_risk += 1

        rows.append({
            "Package": pkg,
            "Ecosystem": ecosystem,

            "Risk": risk_label(score),
            "Score": score,

            "OSV ID": osv["id"],
            "Published": osv["published"],
            "Aliases": ", ".join(osv["aliases"]) if osv["aliases"] else "-",

            "OSV Summary": osv["summary"],

            "References": "\n".join(osv["references"]) if osv["references"] else "-",

            "Affected Versions": "\n".join(osv["affected"]) if osv["affected"] else "-",
            "Fixed Versions": "\n".join(osv["fixed"]) if osv["fixed"] else "-",

            "npm Exists": "YES" if npm["exists"] else "-",
            "npm Latest": npm["latest"] or "-",

            "PyPI Exists": "YES" if pypi["exists"] else "-",
            "PyPI Latest": pypi["latest"] or "-",

            "PyPI Summary": pypi["summary"] or "-"
        })

        progress.progress((i + 1) / total)
        time.sleep(0.05)

    status.text("Complete")

    df = pd.DataFrame(rows)

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Packages", len(packages))

    with col2:
        st.metric("High Risk", high_risk)

    st.divider()

    st.dataframe(df, use_container_width=True, height=650)

    st.divider()
    st.subheader("Splunk IOC Export")

    st.code("\n".join([f"{p}*" for p in packages]), language="text")