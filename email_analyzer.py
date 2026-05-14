from transformers import pipeline
import re
from bs4 import BeautifulSoup
from urlextract import URLExtract
import requests  # <-- NEW: Allows Phase 3 to talk to Phase 2

print("🧠 Booting up Sentinel Phase 3: Advanced Orchestrator...")

nlp_classifier = pipeline("zero-shot-classification", model="typeform/distilbert-base-uncased-mnli")
url_extractor = URLExtract()

# Phase 2 API Configuration
PHASE2_URL_API = "http://127.0.0.1:5001/api/scan-url"

def extract_iocs(text):
    return {
        "links": url_extractor.find_urls(text),
        "emails": re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text),
        "crypto_wallets": re.findall(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$", text)
    }

def check_subtle_keywords(text):
    text_lower = text.lower()
    subtle_flags = []
    bec_keywords = ["gift card", "wire transfer", "are you at your desk", "quick favor", "confidential task"]
    invoice_keywords = ["attached invoice", "overdue payment", "remittance advice"]
    
    for word in bec_keywords:
        if word in text_lower: subtle_flags.append(f"Suspicious BEC phrasing: '{word}'")
    for word in invoice_keywords:
        if word in text_lower: subtle_flags.append(f"Suspicious Invoice phrasing: '{word}'")
            
    return subtle_flags

def clean_html(raw_html):
    soup = BeautifulSoup(raw_html, "html.parser")
    return soup.get_text(separator=" ")

def scan_link_with_phase2(url):
    """Bridge Function: Sends the URL to Phase 2 for ML analysis"""
    try:
        # Increased timeout from 5 to 15 seconds to allow WHOIS lookups to finish
        response = requests.post(PHASE2_URL_API, json={"url": url}, timeout=15)
        if response.status_code == 200:
            return response.json().get("threat_assessment")
            
    except requests.exceptions.ConnectionError:
        return {"error": "Phase 2 Server Offline (Connection Refused)"}
    except requests.exceptions.Timeout:
        return {"error": "Phase 2 Server Timeout (WHOIS lookup took too long)"}
        
    return None

def analyze_email(email_text):
    clean_text = clean_html(email_text)
    iocs = extract_iocs(clean_text)
    subtle_flags = check_subtle_keywords(clean_text)
    
    threat_categories = ["business email compromise", "credential harvesting", "invoice fraud", "urgent action required", "safe corporate communication"]
    
    print("🔍 AI is performing deep psychological analysis...")
    ai_results = nlp_classifier(clean_text, threat_categories)
    top_tactic = ai_results['labels'][0]
    tactic_confidence = round(ai_results['scores'][0] * 100, 2)
    
    red_flags = subtle_flags.copy()
    risk_score = 0
    url_reports = []
    
    # 1. NLP Psychological Scoring
    if top_tactic != "safe corporate communication":
        risk_score += tactic_confidence
        red_flags.append(f"Primary Threat: {top_tactic.upper()} ({tactic_confidence}%)")
    
    if subtle_flags: risk_score += 40
    if iocs["crypto_wallets"]:
        risk_score += 100
        red_flags.append("CRITICAL: Cryptocurrency wallet address detected!")

    # 2. ORCHESTRATION: Talk to Phase 2 URL Scanner
    if iocs["links"]:
        print(f"📡 Found {len(iocs['links'])} link(s). Sending to Phase 2 URL Scanner (Port 5001)...")
        for link in iocs["links"]:
            url_result = scan_link_with_phase2(link)
            if url_result:
                if "error" in url_result:
                    red_flags.append(f"Could not scan URL {link} (Phase 2 Server Offline)")
                else:
                    severity = url_result.get("severity")
                    verdict = url_result.get("verdict")
                    url_reports.append(f"  🔗 {link} -> {severity} ({verdict})")
                    
                    # If Phase 2 says the link is bad, increase the Email risk!
                    if severity == "HIGH":
                        risk_score += 100
                        red_flags.append(f"Phase 2 Flagged Malicious URL: {link}")
                    elif severity == "MEDIUM":
                        risk_score += 40
                        
    # 3. Final Verdict
    if risk_score >= 70: risk_level = "HIGH"
    elif risk_score >= 40: risk_level = "MEDIUM"
    else: risk_level = "LOW"

    return {
        "risk_level": risk_level,
        "red_flags": red_flags,
        "url_reports": url_reports
    }

if __name__ == "__main__":
    print("\n" + "="*60)
    print("📧 Sentinel Orchestrator: NLP + ML URL Analysis")
    print("="*60)
    print("\nPaste a suspicious email below (Press Enter twice when done):")
    
    lines = []
    while True:
        line = input()
        if line: lines.append(line)
        else: break
    
    sample_email = "\n".join(lines)
    
    if sample_email.strip():
        result = analyze_email(sample_email)
        print("\n📊 --- MASTER THREAT REPORT ---")
        print(f"Risk Level : {result['risk_level']}")
        print("Red Flags  :")
        for flag in result['red_flags']: print(f"  ❌ {flag}")
        if result['url_reports']:
            print("\nPhase 2 URL Scan Results:")
            for report in result['url_reports']: print(report)
        if not result['red_flags']:
             print("  ✅ No significant threats detected.")
    else:
        print("No text provided.")