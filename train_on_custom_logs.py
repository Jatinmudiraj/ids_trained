import os
import json
import joblib
import pandas as pd
import numpy as np
import argparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.calibration import CalibratedClassifierCV
from scipy.sparse import hstack
from normalize_helpers import normalize_record, extract_numeric_features

def load_simple_logs(filepath, label, stage="recon"):
    """
    Load logs from a simple text file or JSONL file.
    Each line is treated as a log message.
    """
    X_text = []
    X_numeric = []
    y_attack = []
    y_stage = []
    
    WINDOW_SIZE = 20
    
    records = []
    if not os.path.exists(filepath):
        print(f"[Trainer] Warning: File {filepath} not found.")
        return [], [], [], []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                # Try to parse as JSON first
                r = json.loads(line)
                norm_r = normalize_record(r)
            except:
                # Fallback to raw text
                norm_r = normalize_record({"msg": line})
            records.append(norm_r)

    # Chunk into windows
    for i in range(0, len(records), 5):
        window = records[i : i + WINDOW_SIZE]
        if len(window) < 5: break
        
        combined_text = " ".join([l.get('msg', "") for l in window])
        X_text.append(combined_text)
        
        feat_dict = extract_numeric_features(window)
        # Ensure consistency with 25 feature expectation
        for f in ["num_hosts", "num_domains", "host_transition_count", 
                  "stage_transition_count", "n_component_windows"]:
            if f not in feat_dict:
                feat_dict[f] = 0.0
        X_numeric.append(feat_dict)
        
        y_attack.append(1 if label == "attack" else 0)
        y_stage.append(stage if label == "attack" else "none")
        
    return X_text, X_numeric, y_attack, y_stage

def main():
    parser = argparse.ArgumentParser(description="Train Trained_IDS on custom log data.")
    parser.add_argument("--attack_logs", type=str, nargs='+', help="Path to one or more logs containing attacks")
    parser.add_argument("--normal_logs", type=str, nargs='+', help="Path to one or more logs containing normal activity")
    parser.add_argument("--output", type=str, default="/raid/home/geeta/geeta/Trained_IDS/model/trained_ids.joblib", help="Where to save the weights")
    
    args = parser.parse_args()

    X_text_total = []
    X_numeric_total = []
    y_attack_total = []
    y_stage_total = []

    if args.attack_logs:
        for al in args.attack_logs:
            print(f"[Trainer] Loading attack logs from {al}...")
            xt, xn, ya, ys = load_simple_logs(al, "attack")
            X_text_total.extend(xt)
            X_numeric_total.extend(xn)
            y_attack_total.extend(ya)
            y_stage_total.extend(ys)

    if args.normal_logs:
        for nl in args.normal_logs:
            print(f"[Trainer] Loading normal logs from {nl}...")
            xt, xn, ya, ys = load_simple_logs(nl, "normal")
            X_text_total.extend(xt)
            X_numeric_total.extend(xn)
            y_attack_total.extend(ya)
            y_stage_total.extend(ys)

    if not X_text_total:
        print("[Trainer] Error: No logs loaded. Please provide --attack_logs and/or --normal_logs.")
        # Synthesize fallback if absolutely nothing
        print("[Trainer] Synthesizing minimal baseline for initialization...")
        for _ in range(5):
            X_text_total.append("normal system activity log message")
            X_numeric_total.append(extract_numeric_features([]))
            y_attack_total.append(0)
            y_stage_total.append("none")
        for _ in range(5):
            X_text_total.append("CRITICAL: security breach detected auth failure")
            X_numeric_total.append(extract_numeric_features([{"msg": "auth failure", "event_type": "failed_password"}]))
            y_attack_total.append(1)
            y_stage_total.append("recon")

    print(f"[Trainer] Total samples: {len(y_attack_total)}")

    # 1. Vectorization
    print("[Trainer] Fitting Vectorizers...")
    word_tfidf = TfidfVectorizer(max_features=500, stop_words='english')
    char_tfidf = TfidfVectorizer(max_features=200, analyzer='char', ngram_range=(3,5))
    
    X_word = word_tfidf.fit_transform(X_text_total)
    X_char = char_tfidf.fit_transform(X_text_total)
    
    df_num = pd.DataFrame(X_numeric_total)
    numeric_feature_names = df_num.columns.tolist()
    
    X_final = hstack([X_word, X_char, df_num.values])

    # 2. Training with Evaluation
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, f1_score
    
    X_arr = X_final.toarray()
    X_train, X_test, y_train, y_test = train_test_split(X_arr, y_attack_total, test_size=0.2, random_state=42)

    print(f"[Trainer] Training Classifiers (Train set: {len(y_train)}, Test set: {len(y_test)})...")
    base_clf = RandomForestClassifier(n_estimators=100, random_state=42)
    calibrated_attack = CalibratedClassifierCV(base_clf, cv=3)
    calibrated_attack.fit(X_train, y_train)

    # Evaluate
    y_pred = calibrated_attack.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    print(f"[Trainer] Attack Detection Accuracy: {acc:.2%}")
    print(f"[Trainer] Attack Detection F1-Score: {f1:.2%}")

    # Retrain on full data for production
    print("[Trainer] Retraining on full dataset...")
    calibrated_attack.fit(X_arr, y_attack_total)

    le = LabelEncoder()
    y_stage_enc = le.fit_transform(y_stage_total)
    stage_model = RandomForestClassifier(n_estimators=50, random_state=42)
    stage_model.fit(X_arr, y_stage_enc)

    # 3. Save
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
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
    
    joblib.dump(payload, args.output)
    print(f"[Trainer] SUCCESS! Weights saved to {args.output}")

if __name__ == "__main__":
    main()
