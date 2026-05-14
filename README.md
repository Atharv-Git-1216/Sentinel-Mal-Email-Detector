# 📧 Sentinel Phase 3: Email NLP Threat Analyzer

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Hugging Face](https://img.shields.io/badge/AI-Hugging_Face-yellow.svg)](https://huggingface.co/)
[![Transformers](https://img.shields.io/badge/Library-Transformers-green.svg)](https://github.com/huggingface/transformers)

## 🌌 The Sentinel Series (Phase 3)
This project is the **third module** of the **Sentinel Cyber AI** architecture. While Phase 1 handles Identity and Phase 2 handles Network Traffic, Phase 3 gives Sentinel the ability to **"read"** using Natural Language Processing (NLP).

1. ✅ Password Strength & Security Logic 
2. ✅ Suspicious URL Detector (Machine Learning)
3. 👉 **Phishing Email Analyzer (NLP/Zero-Shot)** (Current)
4. 🤖 AI Chatbot for Cyber Awareness (Planned)

---

## 📝 Project Overview
Unlike basic spam filters that just look for "bad words," this microservice uses an advanced **Transformer AI (DistilBERT)** to perform Deep Context Analysis. It understands the *psychological intent* of an email to catch sophisticated attacks like CEO Fraud, Business Email Compromise (BEC), and Extortion.

### 🛡️ Core Features
* **Zero-Shot AI Classification:** Dynamically categorizes emails into threats like `credential harvesting`, `invoice fraud`, or `urgent action required` using a pre-trained Transformer model.
* **Subtle Threat Engine:** Detects highly contextual, "silent" attacks (e.g., gift card requests, wire transfers) that bypass traditional filters.
* **Technical IOC Extraction:** Automatically parses emails to scrape hidden URLs, raw IP addresses, and Cryptocurrency wallets.
* **Weighted Risk Scoring:** Combines AI confidence intervals with hardcoded heuristic flags to generate a final, enterprise-grade Threat Report.

---

## 🚀 Getting Started

### Installation
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/sentinel-email-nlp-analyzer.git](https://github.com/YOUR_USERNAME/sentinel-email-nlp-analyzer.git)
   cd sentinel-email-nlp-analyzer