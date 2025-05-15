# DRAXOR FT HELPER - Forensic Platform

![Forensics](https://img.shields.io/badge/Forensic-Tool-blue)
![Status](https://img.shields.io/badge/status-Active-brightgreen)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

## 🔍 Overview

**DRAXOR FT HELPER** is a tactical forensic platform designed for advanced memory artifact analysis, anomaly detection, and stealth injection discovery. Built for investigators, red team analysts, and forensic researchers, this tool empowers analysts with machine learning models, driver mapping, and live artifact analysis in an intuitive GUI.

> Developed by **Anonymous S7 (Jay)** — founding member of the **World Forensic Tool Team**.

---

## ✨ Features

- 🧠 **AI-Powered Anomaly Detection** (Isolation Forest)
- 📦 **Driver & Module Analysis** (modscan, driverscan)
- 💥 **Memory Injection & Manual Mapping Detection**
- 🔒 **Hash Integrity Checks** for executables and drivers
- ⚠️ **Stealth Detection**: Hidden processes, ghost services, and RWX regions
- 🧩 **UI Toolkit**: Built with `tkinter`, logs findings live with severity tags
- 📤 **Report Export**: Save findings as XML and TXT forensic reports

---

## 📁 File Structure

- `2.py` - Main forensic platform GUI and core analysis engine
- `output/` - Loaded memory artifacts
- `Findings/` - Exported tactical reports
- `Hashes/` - Stored SHA256 fingerprints for integrity validation

---

## 🚀 Getting Started

### 🔧 Prerequisites

- Python 3.8+
- Install dependencies:
  ```bash
  pip install pefile numpy scikit-learn lief capstone
