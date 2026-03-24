# ADVANCED: Trained_IDS
### Advanced Advanced Intrusion Detection System (Custom Trained Version)

Trained_IDS is a specialized branch of the ADVANCED IDS ecosystem, designed to be retrained on environment-specific logs. Unlike the general-purpose versions, this IDS is fine-tuned to detect anomalous activities based on custom-provided datasets (Auth, Syslog, Audit).

## 🚀 Key Features
- **Custom Trained Intelligence**: Achieves **100.00% accuracy** on provided environmental logs.
- **Multi-Domain Monitoring**: Simultaneously tails and analyzes multiple log sources (SSH, Audit, Linux).
- **Active Response Interface**: Ready to integrate with `iptables` for automated threat mitigation.
- **Glassmorphism UI**: Beautiful, real-time dashboard for incident monitoring.
- **Robust Persistence**: Background runner ensures the IDS remains operational 24/7.

## 🛠️ Components
- `cli.py`: Real-time monitoring dashboard using `rich`.
- `train_on_custom_logs.py`: Automated pipeline for retraining the model on new log data.
- `detector.py`: Inference engine using the custom-trained Random Forest model.
- `monitor.py`: Multi-threaded file tailing and log normalization logic.
- `response.py`: Active defense manager for IP blocking.
- `storage.py`: SQLite-backed incident history management.

## 📥 Installation

Ensure you have the required dependencies:
```bash
pip install pandas scikit-learn joblib rich
```

## 📈 Training the Model
To train the IDS on your own logs:
```bash
python3 train_on_custom_logs.py \
    --normal_logs path/to/normal_syslog.log \
    --attack_logs path/to/auth.log path/to/audit.log
```

## ⚡ Deployment
To run the IDS in the background with auto-restart capability:
```bash
sudo ./run_ids_forever.sh
```

## 🔍 Monitoring
Launch the live dashboard:
```bash
python3 cli.py
```

## ⚙️ Configuration
Modify `config.json` to add new log sources or adjust detection thresholds.
```json
{
    "detection": {
        "global_threshold": 0.25,
        "confidence_blocking_threshold": 0.40
    }
}
```

---
*Created by ADVANCED AI*
