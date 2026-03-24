import os
import time
import json
import threading
from collections import deque
from normalize_helpers import normalize_record
from detector import IDSDetector

class MultiLogMonitor(threading.Thread):
    """Refactored monitor supporting multiple log sources and rotation."""
    def __init__(self, config, callback):
        super().__init__()
        self.config = config
        self.callback = callback
        self.running = True
        self.detector = IDSDetector(config['detection']['model_path'])
        
        # Windows stored per source path
        self.windows = {} 
        self.sources = [s for s in config['monitoring']['sources'] if s['enabled']]
        
        for s in self.sources:
            self.windows[s['path']] = deque(maxlen=config['monitoring'].get('window_size', 20))

    def _tail_file(self, source_cfg):
        path = source_cfg['path']
        domain = source_cfg['domain']
        
        print(f"[Monitor] Thread started for {path} ({domain})")
        
        # Wait for file
        while self.running and not os.path.exists(path):
            time.sleep(2)
            
        with open(path, "r", errors="ignore") as f:
            # Start at end
            f.seek(0, os.SEEK_END)
            last_ino = os.fstat(f.fileno()).st_ino
            
            while self.running:
                # Check for rotation
                try:
                    curr_stat = os.stat(path)
                    if curr_stat.st_ino != last_ino:
                        print(f"[Monitor] Log rotation detected for {path}. Re-opening...")
                        f.close()
                        f = open(path, "r", errors="ignore")
                        last_ino = curr_stat.st_ino
                except FileNotFoundError:
                    time.sleep(2)
                    continue

                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                line = line.strip()
                if not line: continue

                # Process line
                try:
                    record = json.loads(line)
                except:
                    record = {"msg": line, "ts": time.ctime()}
                
                norm = normalize_record(record, domain=domain)
                self.windows[path].append(norm)

                # Inference
                min_lines = self.config['monitoring'].get('min_lines_for_inference', 5)
                if len(self.windows[path]) >= min_lines:
                    is_attack, stage, conf = self.detector.predict(list(self.windows[path]), domain=domain)
                    
                    data = {
                        "raw": line,
                        "norm": norm,
                        "is_attack": is_attack,
                        "stage": stage,
                        "confidence": conf,
                        "timestamp": time.time(),
                        "blocked": False,
                        "source": path
                    }
                    
                    if is_attack:
                        from storage import log_incident
                        log_incident(data)
                        
                        block_thresh = self.config['detection'].get('confidence_blocking_threshold', 0.4)
                        if conf >= block_thresh and self.config['response'].get('enabled'):
                            from response import responder
                            # Use configured duration
                            responder.block_duration = self.config['response'].get('block_duration_seconds', 3600)
                            if responder.block_ip(norm.get('src_ip')):
                                data["blocked"] = True
                    
                    self.callback(data)

    def run(self):
        threads = []
        for s in self.sources:
            t = threading.Thread(target=self._tail_file, args=(s,), daemon=True)
            t.start()
            threads.append(t)
            
        while self.running:
            time.sleep(1)

    def stop(self):
        self.running = False
