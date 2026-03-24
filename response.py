import subprocess
import os
import threading
import time

class ResponseManager:
    """Manages active defense actions like IP blocking via iptables."""
    
    def __init__(self, block_duration=3600):
        self.block_duration = block_duration
        self.blocked_ips = {} # ip: expiry_time
        self._lock = threading.Lock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def block_ip(self, ip):
        """Blocks an IP using iptables if it's not already blocked."""
        if not ip or ip == "unknown" or ip == "127.0.0.1":
            return False

        with self._lock:
            if ip in self.blocked_ips:
                self.blocked_ips[ip] = time.time() + self.block_duration
                return True

            try:
                # Check if already in iptables (idempotency)
                check = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], 
                                    capture_output=True)
                if check.returncode == 0:
                    print(f"[Response] IP {ip} already blocked in iptables. Tracking only.")
                    self.blocked_ips[ip] = time.time() + self.block_duration
                    return True

                print(f"[Response] BLOCKING IP: {ip}")
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                self.blocked_ips[ip] = time.time() + self.block_duration
                return True
            except Exception as e:
                print(f"[Response] Failed to block {ip}: {e}")
                return False

    def unblock_ip(self, ip):
        """Unblocks an IP."""
        try:
            print(f"[Response] UNBLOCKING IP: {ip}")
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            return True
        except Exception as e:
            print(f"[Response] Failed to unblock {ip}: {e}")
            return False

    def _cleanup_loop(self):
        """Background thread to remove expired blocks."""
        while True:
            time.sleep(60)
            now = time.time()
            to_remove = []
            
            with self._lock:
                for ip, expiry in self.blocked_ips.items():
                    if now >= expiry:
                        to_remove.append(ip)
                
                for ip in to_remove:
                    self.unblock_ip(ip)
                    del self.blocked_ips[ip]

# Singleton instance
responder = ResponseManager()
