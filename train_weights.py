import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.calibration import CalibratedClassifierCV
from scipy.sparse import hstack
from normalize_helpers import load_normalized_jsonl, extract_numeric_features

def train_ids_v3(base_data_dir="/raid/home/geeta/geeta/generated_logs", output_path="/raid/home/geeta/geeta/Trained_IDS/model/trained_ids.joblib"):
    print("[Trainer] Starting IDS v3 Universal Training...")
    
    # Domains to crawl
    domains = ["ssh", "apache", "openstack", "hdfs", "linux", "hadoop", "android", "windows", "mac", "thunderbird"]
    
    X_text = []
    X_numeric = []
    y_attack = []
    y_stage = []
    WINDOW_SIZE = 20

    for domain in domains:
        norm_dir = os.path.join(base_data_dir, domain, "normalized")
        report_dir = os.path.join(base_data_dir, domain, "reports")
        
        if not os.path.exists(norm_dir): continue
        
        print(f"[Trainer] Processing domain: {domain}")
        files = [f for f in os.listdir(norm_dir) if f.endswith(".jsonl")]
        
        for filename in files:
            # Match norm_123.jsonl -> 123.json
            timestamp_id = filename.replace("norm_", "").replace(".jsonl", "")
            report_path = os.path.join(report_dir, f"{timestamp_id}.json")
            
            if not os.path.exists(report_path): continue
            
            try:
                with open(report_path, "r") as f:
                    report = json.load(f)
            except: continue
            
            # Labeling logic
            is_attack = report.get("final_score", 0) > 0.45
            counts = report.get("counts", {})
            # Explicit heuristics for security logs
            if domain in ["ssh", "linux", "windows"]:
                if any(k in counts for k in ["auth_failure", "failed_password", "invalid_user", "unauthorized"]):
                    is_attack = True
            
            stage = "recon" if is_attack else "none"
            if is_attack and report.get("final_score", 0) > 0.65:
                stage = "impact"

            logs = load_normalized_jsonl(os.path.join(norm_dir, filename), domain=domain)
        
        # Chunk into moving windows
        for i in range(0, len(logs), 5): 
            window = logs[i : i + WINDOW_SIZE]
            if len(window) < 5: break
            
            # Text
            combined_text = " ".join([l.get('msg', "") for l in window])
            X_text.append(combined_text)
            
            # Numeric
            feat_dict = extract_numeric_features(window)
            # Match 25 feature count used in detector.py
            for f in ["num_hosts", "num_domains", "host_transition_count", 
                      "stage_transition_count", "n_component_windows"]:
                if f not in feat_dict:
                    feat_dict[f] = 0.0
            X_numeric.append(feat_dict)
            
            y_attack.append(1 if is_attack else 0)
            y_stage.append(stage)

    if not X_text:
        print("[Trainer] No valid training pairs (log+report) found!")
        return

    # Ensure we have both classes for binary classification
    # Scikit-learn requires at least n_splits (3) examples per class for stratified CV
    unique_classes = set(y_attack)
    counts = {c: y_attack.count(c) for c in unique_classes}
    
    if len(unique_classes) < 2 or any(v < 5 for v in counts.values()):
        print("[Trainer] Imbalanced or missing classes. Synthesizing balancing baseline...")
        # Normal baseline
        for _ in range(5):
            X_text.append("Dec 10 06:55:46 server sshd[123]: session opened for user geeta")
            X_numeric.append(extract_numeric_features([]))
            y_attack.append(0)
            y_stage.append("none")
        # Attack baseline
        for _ in range(5):
            X_text.append("Dec 10 06:55:46 server sshd[123]: auth failure; logname= uid=0 euid=0 rhost=1.2.3.4")
            X_numeric.append(extract_numeric_features([{"msg": "auth failure", "event_type": "failed_password"}]))
            y_attack.append(1)
            y_stage.append("recon")

    print(f"[Trainer] Data loaded: {len(y_attack)} samples.")

    # 2. Vectorization
    print("[Trainer] Fitting Vectorizers...")
    word_tfidf = TfidfVectorizer(max_features=500, stop_words='english')
    char_tfidf = TfidfVectorizer(max_features=200, analyzer='char', ngram_range=(3,5))
    
    X_word = word_tfidf.fit_transform(X_text)
    X_char = char_tfidf.fit_transform(X_text)
    
    df_num = pd.DataFrame(X_numeric)
    numeric_feature_names = df_num.columns.tolist()
    
    X_final = hstack([X_word, X_char, df_num.values])

    # 3. Model Training
    print("[Trainer] Training Random Forest Classifiers (Calibrated)...")
    base_clf = RandomForestClassifier(n_estimators=100, random_state=42)
    
    # In Scikit-learn 1.4+, 'prefit' is deprecated as a string, must be handled differently
    # or just use standard CV to get better weights
    calibrated_attack = CalibratedClassifierCV(base_clf, cv=3)
    calibrated_attack.fit(X_final.toarray(), y_attack)

    # Stage Model
    le = LabelEncoder()
    y_stage_enc = le.fit_transform(y_stage)
    stage_model = RandomForestClassifier(n_estimators=50, random_state=42)
    stage_model.fit(X_final.toarray(), y_stage_enc)

    # 4. Save to model directory
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    payload = {
        "word_tfidf": word_tfidf,
        "char_tfidf": char_tfidf,
        "numeric_feature_names": numeric_feature_names,
        "attack_model": calibrated_attack,
        "stage_model": stage_model,
        "stage_encoder": le,
        "thresholds": {"_global": {"attack_threshold": 0.4}},
        "metadata": {"trained_at": pd.Timestamp.now().isoformat()}
    }
    
    joblib.dump(payload, output_path)
    print(f"[Trainer] Weights updated! New model saved to {output_path}")

if __name__ == "__main__":
    train_ids_v3()
