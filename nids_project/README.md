# Network Intrusion Detection System (NIDS)
**Authors:** Muhammad Tayyab (BSSE23018) | Tehreem Mazhar (BSSE23086)

---

## Project Structure

```
nids_project/
├── app.py                  # Flask web application (main entry point)
├── model_trainer.py        # ML training pipeline (5 models + HPO)
├── predictor.py            # Inference engine
├── download_data.py        # NSL-KDD dataset downloader
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container definition
├── Procfile                # EB start command
├── .ebextensions/          # AWS Elastic Beanstalk config
│   └── 01_flask.config
├── templates/
│   └── index.html          # Web UI dashboard
├── data/                   # Dataset directory (auto-created)
└── models/                 # Trained model .pkl files (auto-created)
```

---

## Local Setup & Run

### 1. Create Virtual Environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Download Dataset (optional — synthetic data used if absent)
```bash
python download_data.py
```

### 4. Run the Application
```bash
python app.py
```
Open `http://localhost:5000` in your browser.

### 5. Train Models
- Click the **TRAIN** tab in the UI
- Click **⚡ START TRAINING**
- Wait ~2–5 minutes for all 5 models to train

### 6. Run Predictions
- Go to **PREDICT** tab
- Select a quick scenario or enter custom features
- Click **▶ ANALYZE**

---

## Models Implemented

| Model | Type | Selection Rationale |
|---|---|---|
| **Random Forest** ⭐ | Supervised | **Primary model** — highest F1, handles imbalance, explainable |
| SVM (RBF) | Supervised | High-dimensional robust classifier |
| Logistic Regression | Supervised | Fast interpretable baseline |
| Isolation Forest | **Unsupervised** | Label-free anomaly detection |
| K-Means (k=2) | **Unsupervised** | Clustering-based detection |

---

## Docker

```bash
# Build image
docker build -t nids-app .

# Run container
docker run -p 5000:5000 nids-app

# Open http://localhost:5000
```

---

## AWS Elastic Beanstalk Deployment

See the step-by-step deployment guide provided separately.

Quick summary:
1. Install EB CLI: `pip install awsebcli`
2. `eb init -p docker nids-app --region us-east-1`
3. `eb create nids-env`
4. `eb open`
