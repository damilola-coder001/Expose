import urllib.request
import json

def main():
    payload = json.dumps({
        "target": "https://kayoluhayerogroup.net.ng/",
        "authorized": True,
        "allow_private": False
    }).encode("utf-8")

    req = urllib.request.Request(
        "http://localhost:3000/api/v1/scans",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    
    print("Sending scan request to http://localhost:3000/api/v1/scans...")
    with urllib.request.urlopen(req, timeout=45) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        print(f"Status: {resp.status}")
        print(f"Scan ID: {data.get('id')}")
        score_card = data.get("score_card", {})
        print(f"Score: {score_card.get('overall_score')}/100 (Grade {score_card.get('letter_grade')})")
        print(f"Findings Count: {len(data.get('findings', []))}")
        print(f"Duration: {data.get('duration_seconds')}s")
        risk = data.get("risk_assessment", {})
        print(f"Posture Summary: {risk.get('posture_summary')}")

if __name__ == "__main__":
    main()
