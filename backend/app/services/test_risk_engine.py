from app.services.feature_extractor import extract_features
from app.services.risk_engine import calculate_risk


test_urls = [
    "https://google.com",
    "https://paypal-login-secure.xyz",
    "http://192.168.1.100/login",
    "https://secure-login-bank-account.com",
    "https://bit.ly/example"
]


for url in test_urls:
    features = extract_features(url)
    result = calculate_risk(features)

    print("=" * 70)
    print("URL:", url)
    print("Risk Score:", result["risk_score"])
    print("Verdict:", result["verdict"])
    print("Reasons:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print(" -", reason)
    else:
        print(" - No suspicious indicators detected")

print("=" * 70)