# ⚡ Layton — A Lightweight ML-Based NIDS for Flow Classification

Layton is a **NOVEL** machine learning-powered **Network Intrusion Detection System (NIDS)** designed for real-time **flow-level TCP/IP traffic classification**.

Written in C, it captures packets, extracts features trying to mimic **CIC-FlowMeter**, and uses a trained **XGBoost model** on the CIC-BCCC-TabularIoT-2024 data to classify flows as **benign or malicious** — all in one lightweight pipeline. (Model nor data included)

---

## 🚀 Features

- 🕵️‍♂️ Real-time packet sniffing (TCP/IP)
- 🔍 Flow extraction & feature engineering (CIC-FlowMeter-style)
- 🤖 XGBoost-based binary classification (benign / malicious)

---

## 🔧 How It Works

1. **Sniffing** — Captures live packets using pcap.h.
2. **Flow Aggregation** — Groups packets into bidirectional flows.
3. **Feature Extraction** — Computes statistical features per flow (duration, packet size, flags, etc.).
4. **Classification** — Runs flow features through a pre-trained `XGBoost` model with ONNX.
5. **Output** — Labels each flow.

---
