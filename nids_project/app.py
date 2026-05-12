"""
Network Intrusion Detection System (NIDS)
Flask Web Application - Main Entry Point
Authors: Muhammad Tayyab (BSSE23018), Tehreem Mazhar (BSSE23086)
"""

from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
import os
import json
from model_trainer import ModelTrainer
from predictor import Predictor

# Initialize Flask app
app = Flask(__name__)

# Global predictor instance (loaded once at startup)
predictor = None

def initialize_predictor():
    """Load trained models into memory when the app starts."""
    global predictor
    model_path = "models/"
    if os.path.exists(model_path) and len(os.listdir(model_path)) > 0:
        predictor = Predictor(model_path)
        print("[INFO] Models loaded successfully.")
    else:
        print("[WARNING] No trained models found. Please train models first via /train endpoint.")

@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")

@app.route("/train", methods=["POST"])
def train():
    """
    Train all ML models on the NSL-KDD dataset.
    Returns training results including accuracy metrics for each model.
    """
    try:
        trainer = ModelTrainer(data_path="data/KDDTrain+.txt")
        results = trainer.train_all_models()
        # Re-initialize predictor after training
        initialize_predictor()
        return jsonify({"status": "success", "results": results})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/predict", methods=["POST"])
def predict():
    """
    Predict whether network traffic is normal or an intrusion.
    Accepts JSON with network traffic features.
    Returns prediction label and confidence score.
    """
    global predictor
    if predictor is None:
        return jsonify({"status": "error", "message": "Models not loaded. Please train first."}), 400

    try:
        data = request.get_json()
        features = data.get("features", {})
        result = predictor.predict(features)
        return jsonify({"status": "success", "prediction": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/predict_csv", methods=["POST"])
def predict_csv():
    """
    Batch prediction: accepts a CSV file upload and returns predictions for each row.
    Useful for evaluating large traffic logs.
    """
    global predictor
    if predictor is None:
        return jsonify({"status": "error", "message": "Models not loaded. Please train first."}), 400

    try:
        file = request.files.get("file")
        if not file:
            return jsonify({"status": "error", "message": "No file uploaded."}), 400

        df = pd.read_csv(file, header=None)
        results = predictor.predict_batch(df)
        return jsonify({"status": "success", "predictions": results})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/metrics", methods=["GET"])
def metrics():
    """
    Return saved model evaluation metrics (accuracy, precision, recall, F1).
    Used by the dashboard to display comparison charts.
    """
    try:
        with open("models/metrics.json", "r") as f:
            data = json.load(f)
        return jsonify({"status": "success", "metrics": data})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "No metrics found. Train models first."}), 404

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint required by AWS Elastic Beanstalk."""
    return jsonify({"status": "healthy", "models_loaded": predictor is not None})

# Application entry point
if __name__ == "__main__":
    os.makedirs("models", exist_ok=True)
    os.makedirs("data", exist_ok=True)
    initialize_predictor()
    # Use port 5000 locally; Elastic Beanstalk uses PORT env var
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
