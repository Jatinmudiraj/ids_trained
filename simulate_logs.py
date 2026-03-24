import time
import json
import random

LOG_FILE = "/raid/home/geeta/geeta/Trained_IDS/test_logs.txt"

NORMAL_LOGS = [
    "Jul  1 09:01:05 authorMacBook-Pro com.apple.CDScheduler[43]: Thermal pressure state: 1 Memory pressure state: 0",
    "Jul  1 09:02:26 calvisitor-10-105-160-95 kernel[0]: ARPT: 620701.011328: AirPort_Brcm43xx::syncPowerState: WWEN[enabled]",
    "Jun 15 04:06:18 combo su(pam_unix)[21416]: session opened for user cyrus by (uid=0)",
    "Dec 10 06:55:46 LabSZ sshd[24200]: Connection closed by 112.91.230.3",
    "Sun Dec 04 04:47:44 2005 [info] [client 127.0.0.1] File does not exist: /var/www/favicon.ico"
]

ATTACK_LOGS = [
    "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4",
    "Jun 14 15:16:02 combo sshd(pam_unix)[19937]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4",
    "Jun 14 15:16:03 combo sshd(pam_unix)[19940]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4",
    "2017-05-16 00:00:01.001 1234 ERROR nova.api.openstack [req-999] [instance: 1] Exploit attempt: buffer overflow detected",
    "2016-09-28 04:30:30, Warning CBS [req-888] Unauthorized registry access attempt from 192.168.1.50"
]

def simulate():
    print(f"Simulating logs into {LOG_FILE}...")
    with open(LOG_FILE, "a") as f:
        while True:
            # Randomly pick normal or attack
            if random.random() > 0.85:
                # Malicious burst
                print("Injecting malicious burst...")
                for _ in range(3):
                    line = random.choice(ATTACK_LOGS)
                    # For our detector.py logic which tries json.loads first:
                    # We can use raw or json.
                    # Since we want to test the 'fallback' to raw:
                    f.write(line + "\n")
                    f.flush()
                    time.sleep(0.5)
            else:
                line = random.choice(NORMAL_LOGS)
                f.write(line + "\n")
                f.flush()
                print(f"Logged: {line[:50]}...")
            
            time.sleep(random.uniform(1.0, 3.0))

if __name__ == "__main__":
    simulate()
