from app.services.scanner import scan_url


test_url = "https://paypal-login-secure.xyz"

result = scan_url(test_url)

print("Sentinel AI Scan Result")
print("=" * 50)

print("URL:", result["url"])
print("Risk Score:", result["risk_score"])
print("Verdict:", result["verdict"])

print("\nReasons:")

for reason in result["reasons"]:
    print("-", reason)

print("\nFeatures:")
print(result["features"])