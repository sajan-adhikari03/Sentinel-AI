import sys
from pathlib import Path

# Add backend directory to Python path
BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


from app.services.scanner import scan_url


print("========================================")
print("Sentinel ML Prediction Test")
print("========================================")

url = input("Enter URL: ").strip()

print()
print("URL received:", repr(url))

result = scan_url(url)

print()
print("========================================")
print("RESULT")
print("========================================")

print("URL:", result["url"])
print("Rule Score:", result["risk_score"])
print("Rule Verdict:", result["verdict"])
print("ML Probability:", result["ml_probability"])
print("ML Prediction:", result["ml_prediction"])
print("ML Verdict:", result["ml_verdict"])

print()
print("Features:")

for key, value in result["features"].items():
    print(f"{key}: {value}")