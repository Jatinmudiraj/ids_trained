import joblib
import pandas as pd
import numpy as np
from normalize_helpers import extract_numeric_features

class IDSDetector:
    def __init__(self, model_path="/raid/home/geeta/geeta/Trained_IDS/model/trained_ids.joblib"):
        print(f"[IDS] Loading model from {model_path}...")
        try:
            loaded = joblib.load(model_path)
            if isinstance(loaded, dict):
                self.attack_model = loaded.get("attack_model")
                self.stage_model = loaded.get("stage_model")
                self.stage_encoder = loaded.get("stage_encoder")
                self.word_tfidf = loaded.get("word_tfidf")
                self.char_tfidf = loaded.get("char_tfidf")
                self.feature_names = loaded.get("numeric_feature_names", [])
                self.thresholds = loaded.get("thresholds", {})
                print(f"[IDS] V2 Full Pipeline loaded. Thresholds: {len(self.thresholds)}")
            else:
                self.attack_model = loaded
                self.thresholds = {}
                self.feature_names = []
            
            print("[IDS] Detector initialized.")
        except Exception as e:
            print(f"[IDS] Critical Error: {e}")
            self.attack_model = None

    def _prepare_features(self, window_lines):
        # 1. Numeric features
        # Normalize Helpers provides some, we fill the rest to match 25 count
        numeric_dict = extract_numeric_features(window_lines)
        
        # Add training-specific placeholders if missing
        for f in ["num_hosts", "num_domains", "host_transition_count", 
                  "stage_transition_count", "n_component_windows"]:
            if f not in numeric_dict:
                numeric_dict[f] = 0.0

        df_num = pd.DataFrame([numeric_dict])
        
        if self.feature_names:
            # Reorder and filter
            for col in self.feature_names:
                if col not in df_num.columns:
                    df_num[col] = 0.0
            df_num = df_num[self.feature_names]

        # 2. Text features (TF-IDF)
        combined_text = " ".join([l.get("msg", "") for l in window_lines])
        
        from scipy.sparse import hstack, csr_matrix
        X = csr_matrix(df_num.values)
        
        if self.word_tfidf and self.char_tfidf:
            v_word = self.word_tfidf.transform([combined_text])
            v_char = self.char_tfidf.transform([combined_text])
            # Order: word, char, numeric
            X = hstack([v_word, v_char, X])
            
        return X

    def predict(self, window_lines, domain="ssh"):
        if not self.attack_model or not window_lines:
            return False, "none", 0.0

        try:
            # 1. Preprocess
            X = self._prepare_features(window_lines)
            
            # 2. Probability-based Inference
            proba = float(self.attack_model.predict_proba(X)[0, 1])
            
            # 3. Apply Threshold
            thresh_cfg = self.thresholds.get(domain, self.thresholds.get("_global", {}))
            threshold = thresh_cfg.get("attack_threshold", 0.5)
            
            is_attack = proba >= threshold
            stage = "unknown"
            
            if is_attack and self.stage_model and self.stage_encoder:
                stage_idx = self.stage_model.predict(X)[0]
                stage = self.stage_encoder.inverse_transform([stage_idx])[0]

            return is_attack, stage, proba
        except Exception as e:
            print(f"[IDS] Predict Error: {e}")
            return False, "error", 0.0
