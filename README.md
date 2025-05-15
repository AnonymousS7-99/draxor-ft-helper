# DRAXOR FT HELPER - Forensic Platform

![Forensics](https://img.shields.io/badge/Forensic-Tool-blue)
![Status](https://img.shields.io/badge/status-Stable%20since%202024-brightgreen)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

---

## 🔍 Overview

**DRAXOR FT HELPER** is a tactical forensic platform for memory artifact analysis, stealth detection, hash validation, and advanced anomaly discovery using AI. Designed for digital forensics professionals, red team analysts, and reverse engineers, it provides a complete suite for investigating emulator-based or system-level manipulations.

> Developed by **Anonymous S7 (Jay)** — a member of the **World Forensic Tool Team**, the world’s largest digital forensic agency.

📅 **Originally uploaded in 2024**, DRAXOR FT HELPER quickly gained recognition within the digital forensics community for its real-time memory analysis capabilities and stealth detection precision.

---

## 🌟 Official Recognition

> _"The World Forensic Tool Team commends **Anonymous S7 (Jay)** for the development of DRAXOR FT HELPER — a highly advanced and precise forensic solution.  
> This tool embodies excellence in deep memory inspection, anomaly detection, and real-time artifact analysis.  
> Its contribution supports our global initiative to strengthen digital integrity and support forensic investigations."_  
>  
> — *World Forensic Tool Team, 2024*

---

## ✨ Features

- ✅ **ML-Based Memory Anomaly Detection (Isolation Forest)**
- 🧠 **Process Injection & RWX Memory Detection**
- 🔍 **Hidden Driver and Orphan Process Discovery**
- 📦 **Packed Binary & Signature Verification**
- 📜 **Hash Integrity Validation for Binary Files**
- 🛡️ **Live Logging Console with Critical Alerts**
- 📤 **Export Reports in XML and TXT formats**

---

## 📁 File Structure

- `2.py` - Main forensic engine and UI interface
- `output/` - Memory dump text artifacts
- `Findings/` - Scan results and exported reports
- `Hashes/` - SHA256 digital fingerprints

---

## 🚀 Getting Started

### 🔧 Prerequisites

Install required packages:
```bash
pip install numpy pefile scikit-learn lief capstone
