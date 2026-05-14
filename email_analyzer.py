from transformers import pipeline
import re
from bs4 import BeautifulSoup
from urlextract import URLExtract

print("🧠 Booting up Sentinel Phase 3: Advanced NLP Engine...")
print("⏳ (If this is your first run, downloading the AI model will take a minute or two...)")

# Load a Zero-Shot Classification model
# This allows us to define our own custom threat categories!
nlp_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
url_extractor = URLExtract()

def extract_iocs(text):
    """Extracts Indicators of Compromise (IOCs) like links and crypto wallets."""
    iocs = {
        "links": url_extractor.find_urls(text),
        "emails": re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text),
        # Basic Regex for Bitcoin wallet addresses
        "crypto_wallets": re.findall(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$", text)
    }
    return iocs

def clean_html(raw_html):
    """Removes HTML tags if the email is forwarded in raw HTML format."""
    soup = BeautifulSoup(raw_html, "html.parser")
    return soup.get_text(separator=" ")

def analyze_email(email_text):
    # 1. Clean the text
    clean_text = clean_html(email_text)
    
    # 2. Extract Technical IOCs
    iocs = extract_iocs(clean_text)
    
    # 3. Psychological AI Analysis (Zero-Shot)
    # We define the exact tactics hackers use
    threat_categories = [
        "credential harvesting", 
        "financial threat", 
        "urgent action required", 
        "blackmail or extortion",
        "safe corporate communication"
    ]
    
    print("🔍 AI is reading the email...")
    ai_results = nlp_classifier(clean_text, threat_categories)
    
    # Get the top detected tactic and its confidence score
    top_tactic = ai_results['labels'][0]
    tactic_confidence = round(ai_results['scores'][0] * 100, 2)
    
    # 4. Calculate Final Risk
    red_flags = []
    if top_tactic != "safe corporate communication" and tactic_confidence > 60:
        red_flags.append(f"Psychological Tactic: {top_tactic.upper()} ({tactic_confidence}% match)")
        risk_level = "HIGH"
    else:
        risk_level = "LOW"
        
    if iocs["links"]:
        red_flags.append(f"Found {len(iocs['links'])} hidden URLs to scan.")
    if iocs["crypto_wallets"]:
        red_flags.append("CRITICAL: Cryptocurrency wallet address detected!")
        risk_level = "CRITICAL"

    return {
        "risk_level": risk_level,
        "primary_tactic": top_tactic,
        "ai_confidence": tactic_confidence,
        "iocs_found": iocs,
        "red_flags": red_flags
    }

# --- Interactive Terminal Test ---
if __name__ == "__main__":
    print("\n" + "="*50)
    print("📧 Sentinel Email NLP Threat Analyzer")
    print("="*50)
    
    print("\nPaste a suspicious email below (Press Enter twice when done):")
    
    lines = []
    while True:
        line = input()
        if line:
            lines.append(line)
        else:
            break
    
    sample_email = "\n".join(lines)
    
    if sample_email.strip():
        result = analyze_email(sample_email)
        print("\n📊 --- SENTINEL THREAT REPORT ---")
        print(f"Risk Level : {result['risk_level']}")
        print(f"AI Verdict : {result['primary_tactic']} ({result['ai_confidence']}%)")
        print("Red Flags  :")
        for flag in result['red_flags']:
            print(f"  ❌ {flag}")
        if result['iocs_found']['links']:
            print(f"Links Extracted: {result['iocs_found']['links']}")
    else:
        print("No text provided.")