from detector import IDSDetector
from normalize_helpers import normalize_record
import time

def test_inference():
    det = IDSDetector("model/production.joblib")
    
    # Raw malicious lines (SSH brute force)
    raw_lines = [
        "Jun 14 15:16:01 combo sshd[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4",
        "Jun 14 15:16:02 combo sshd[19937]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4",
        "Jun 14 15:16:03 combo sshd[19940]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4",
        "Jun 14 15:16:04 combo sshd[19941]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4",
        "Jun 14 15:16:05 combo sshd[19942]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4"
    ]
    
    # Normalize them just like the monitor does
    window = [normalize_record({"msg": ln}, domain="ssh") for ln in raw_lines]
    
    # Force some fields that normalize_record might miss without a full parser
    for r in window:
        r["src_ip"] = "218.188.2.4"
        r["event_type"] = "failed_password" 

    print("\n[Test] Running inference on malicious window...")
    is_attack, stage, conf = det.predict(window)
    print(f"Result: Attack={is_attack}, Stage={stage}, Confidence={conf:.2%}")

if __name__ == "__main__":
    test_inference()
