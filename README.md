# 🧠 RetrieverLabs Package Exposure Analyzer
A simple security tool that analyzes npm packages for supply chain risk and exposure.

## 🌐 Live Tool
👉 [https://package-intel.streamlit.app/](https://package-intel.streamlit.app/)

Use it directly in your browser — no install needed.

## 🔍 What it does
Paste a list of npm packages and the tool will:

- Check OSV vulnerability data
- Pull npm registry metadata
- Measure download exposure (last 30 days)
- Identify dependencies (optional 1-level view)
- Generate Splunk IOC wildcards
- Calculate a simple risk score (High / Medium / Low)

## 🧪 Example input
lodash, express, react, axios, @tanstack/react-router

## ⚡ Output
For each package you get:

- Risk level
- OSV vulnerability info (if any)
- Published date
- Summary description
- Aliases (if available)
- References (OSV links)
- Latest npm version
- Download volume (30 days)
- Dependencies (optional)

## 🎯 Purpose
To speed up software supply chain investigations by quickly identifying:

- Vulnerable npm packages
- Widely used/high exposure libraries
- Dependency-based attack surface
- Ready-to-use Splunk hunting indicators

## 🔮 Future improvements
- Dependency graph view (multi-level)
- CSV / JSON export
- Async bulk processing
- Top-risk clustering dashboard
- Scheduled scanning mode

## ⚠️ Disclaimer
For defensive security and authorized use only.

## 🏷️ Built by
RetrieverLabs
