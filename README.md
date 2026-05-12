Academic Project — Information Technology University (ITU), Punjab, Pakistan
Dr. Ahmed Raza
Machine Learning — Final Year Project (6th Semester)
Team
Name	Roll Number
Muhammad Tayyab Nasir	BSSE23018-A
Tehreem Mazhar	BSSE23086-A
Supervisor


Overview

CyberShield is a production-style Network Intrusion Detection System (NIDS) built using a 2-Tier Cascade Machine Learning architecture. It is designed to detect both common and ultra-rare cyberattacks in real-time using a combination of Random Forest (fast detection) and XGBoost (deep anomaly scanning).

Built on the CICIDS2017 dataset, CyberShield focuses on:

High-accuracy intrusion detection
Extreme class imbalance handling
Real-time inference (<2ms edge latency)
Hybrid Edge + Cloud deployment
System Architecture
Network Traffic
      │
      ▼
┌────────────────────┐
│  Tier B (Random    │
│  Forest Classifier) │
└─────────┬──────────┘
          │ High Confidence
          ▼
     Final Prediction
          │ Low Confidence
          ▼
┌────────────────────┐
│ Tier C (XGBoost    │
│ Deep Scanner)      │
└────────────────────┘
          ▼
   Final Threat Label
Core Design Philosophy

CyberShield is built on three engineering principles:

Separation of Concerns → Fast detection vs deep analysis
Class Imbalance Engineering → Cost-sensitive learning
Hybrid Deployment → Edge + Cloud execution
Dataset — CICIDS2017
2,520,798 cleaned network flows
78 extracted flow-based features
14 attack categories
Data Engineering Fixes
Removed 307,078 duplicate records
Eliminated data leakage (Is_Attack)
Fixed corrupted label mappings
Fully sanitized ML-ready dataset
Model Architecture
Tier B — Random Forest (Fast Detector)
75 estimators
Balanced class weights
Handles majority traffic classification
Acts as first-line defense
Tier C — XGBoost (Deep Scanner)
200 estimators
Histogram-based training
Sample-weighted loss function
Detects rare & stealth attacks
Performance Benchmark
Model	Accuracy	Macro F1	Heartbleed	Infiltration
MLP (Leaky)	99.99%*	0.0669	0.00	0.00
MLP (Clean)	82.41%	0.1134	0.00	0.00
Tier B (RF)	99.83%	0.8605	0.50	1.00
Tier C (XGB)	99.86%	0.8821	1.00	1.00

Leaky model inflated due to dataset contamination

 Deployment Architecture
Edge AI (Android)
C++ ONNX Runtime engine
Direct memory inference
Fully offline execution
< 2ms latency
Cloud AI (AWS)
FastAPI microservice
Elastic Beanstalk deployment
REST API endpoint /classify
Scalable inference layer
Tech Stack

Machine Learning

Scikit-learn
XGBoost
NumPy / Pandas

Edge Deployment

C++
ONNX Runtime
Flutter FFI

Cloud Backend

FastAPI
AWS Elastic Beanstalk
Project Structure
CyberShield/
│
├── training/         # ML training pipeline
├── models/           # RF + XGBoost models
├── edge/             # C++ ONNX Android engine
├── cloud/            # FastAPI backend (AWS)
├── data/             # CICIDS2017 processed dataset
└── clean_data_final.py
 Why CyberShield Works

Traditional deep learning fails due to:

Severe class imbalance
 Majority-class collapse
Dataset leakage issues

CyberShield solves this using:

 Ensemble tree models (RF + XGBoost)
Cost-sensitive learning
Cascade decision logic
Strict data sanitization pipeline

 Key Highlights
 Real-time intrusion detection system
 Hybrid ML architecture (Cascade design)
Mobile edge AI deployment
Cloud-based scalable inference
Strong performance on imbalanced dataset
Future Work
Federated learning for distributed IDS
Real-time packet streaming integration
Adversarial attack robustness testing
Online adaptive learning system
