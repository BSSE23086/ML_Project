# CyberShield — 2-Tier Cascade Network Intrusion Detection System (NIDS)

<p align="center">
  <img src="https://img.shields.io/badge/Machine%20Learning-Cybersecurity-black?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Architecture-2--Tier%20Cascade-grey?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Edge%20AI-ONNX%20Runtime-black?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Cloud-GCP%20%7C%20FastAPI-grey?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Frontend-Netlify-black?style=for-the-badge" />
</p>

<p align="center">
  <b>Intelligent Real-Time Intrusion Detection using Hybrid Edge and Cloud AI</b>
</p>

---

# Live Demo

## Web Application

[CyberShield Live Demo](https://coruscating-halva-63dfce.netlify.app/?utm_source=chatgpt.com)

---

# Overview

CyberShield is a production-oriented Network Intrusion Detection System (NIDS) built using a 2-Tier Cascade Machine Learning Architecture designed for real-world cybersecurity environments.

The system combines:

* Random Forest for ultra-fast general intrusion detection
* XGBoost deep scanning for rare and stealth attack analysis

CyberShield was engineered specifically to overcome the major limitations of traditional IDS pipelines:

* Extreme class imbalance
* Dataset contamination and leakage
* High-latency inference systems
* Mobile deployment constraints

The project is trained on the CICIDS2017 benchmark dataset and deployed using a Hybrid Edge and Cloud Architecture.

---

# Academic Information

| Field        | Details                           |
| ------------ | --------------------------------- |
| Subject      | Machine Learning                  |
| Project Type | Final Project                     |
| Semester     | 6th Semester                      |
| Supervisor   | Dr. Ahmed Raza                    |
| University   | Information Technology University |

---

# Team

| Name                  | Roll Number |
| --------------------- | ----------- |
| Muhammad Tayyab Nasir | BSSE23018-A |
| Tehreem Mazhar        | BSSE23086-A |

---

# System Architecture

```text
                    Network Traffic
                           │
                           ▼
              ┌─────────────────────────┐
              │   Tier B — Random       │
              │   Forest Classifier     │
              └──────────┬──────────────┘
                         │
          High Confidence│
                         ▼
                  Final Prediction
                         │
           Low Confidence│
                         ▼
              ┌─────────────────────────┐
              │   Tier C — XGBoost      │
              │   Deep Scanner          │
              └─────────────────────────┘
                         ▼
                 Final Threat Label
```

---

# Core Design Philosophy

CyberShield is built on three major engineering principles:

| Principle                   | Purpose                             |
| --------------------------- | ----------------------------------- |
| Separation of Concerns      | Fast detection vs deep analysis     |
| Class-Imbalance Engineering | Cost-sensitive rare attack learning |
| Hybrid Deployment           | Edge AI and Cloud scalability       |

---

# Dataset — CICIDS2017

CyberShield uses the CICIDS2017 benchmark dataset containing modern network traffic and attack scenarios.

## Dataset Statistics

| Metric                | Value              |
| --------------------- | ------------------ |
| Total Clean Records   | 2,520,798          |
| Features              | 78                 |
| Attack Categories     | 14                 |
| Original Dataset Size | 2.83 Million Flows |

---

# Data Engineering and Leak Remediation

A complete forensic audit of the original dataset pipeline revealed several critical issues that artificially inflated model performance.

## Critical Issues Identified

### Data Leakage

An engineered feature (`Is_Attack`) directly exposed the ground-truth label.

### Duplicate Contamination

Exactly 307,078 duplicate rows inflated validation scores.

### Label Mapping Corruption

Misaligned integer mappings between models caused inconsistent predictions.

---

## Remediation Pipeline

The dataset pipeline was rebuilt using:

* Unicode sanitization
* Hardcoded universal label mapping
* Duplicate elimination
* Leakage removal
* Parquet optimization pipeline

Result: a mathematically pure dataset ready for production ML training.

---

# Model Architecture

## Tier B — Random Forest (Fast Detector)

The first stage acts as a fast generalized intrusion detector.

### Configuration

* 75 estimators
* Max depth = 25
* Balanced class weighting
* Parallel execution

### Responsibilities

* Handles majority traffic classification
* Detects common attacks quickly
* Minimizes computational overhead

---

## Tier C — XGBoost (Deep Scanner)

The second stage acts as a specialized anomaly scanner.

### Configuration

* 200 estimators
* Histogram-based training
* Sample-weighted optimization
* Cost-sensitive learning

### Responsibilities

* Detects ultra-rare attacks
* Handles stealth intrusion patterns
* Acts as the final security layer

---

# Performance Benchmark

| Model                  | Accuracy | Macro F1 | Heartbleed Recall | Infiltration Recall |
| ---------------------- | -------- | -------- | ----------------- | ------------------- |
| MLP (Leaky)            | 99.99%*  | 0.0669   | 0.00              | 0.00                |
| MLP (Clean)            | 82.41%   | 0.1134   | 0.00              | 0.00                |
| Tier B (Random Forest) | 99.83%   | 0.8605   | 0.50              | 1.00                |
| Tier C (XGBoost)       | 99.86%   | 0.8821   | 1.00              | 1.00                |

*Leaky model performance was artificially inflated due to dataset contamination.*

---

# Deployment Architecture

CyberShield is deployed using a Hybrid Edge and Cloud Infrastructure.

---

## Edge AI Deployment (Android)

### Stack

* C++
* ONNX Runtime
* Flutter FFI

### Features

* Fully offline execution
* Direct memory inference
* Ultra-lightweight engine
* Sub-2ms latency

---

## Cloud Deployment (GCP)

### Backend Infrastructure

* FastAPI Microservice
* Google Cloud Platform (GCP)
* f4 Compute Instance
* 1GB RAM optimized deployment

### Features

* REST API endpoint (`/classify`)
* Cloud inference pipeline
* Scalable architecture
* Browser-compatible deployment

---

# Tech Stack

## Machine Learning

* Scikit-learn
* XGBoost
* NumPy
* Pandas

## Edge Deployment

* C++
* ONNX Runtime
* Flutter FFI

## Cloud Infrastructure

* FastAPI
* Google Cloud Platform (GCP)
* Netlify Frontend Hosting

---

# Project Structure

```text
CyberShield/
│
├── training/              # ML training pipeline
├── models/                # RF + XGBoost trained models
├── edge/                  # C++ ONNX Android inference engine
├── cloud/                 # FastAPI backend
├── data/                  # CICIDS2017 processed dataset
├── clean_data_final.py    # Data sanitization pipeline
└── README.md
```

---

# Why CyberShield Works

Traditional deep learning pipelines fail on CICIDS2017 because of:

* Severe class imbalance
* Majority-class collapse
* Data leakage contamination
* Rare attack underrepresentation

CyberShield solves these issues through:

* Ensemble tree architectures
* Cost-sensitive learning
* Cascade decision systems
* Strict data sanitization
* Hybrid edge and cloud execution

---

# Key Highlights

* Real-time intrusion detection
* Hybrid ML cascade architecture
* Edge AI deployment
* Cloud-based scalable inference
* Strong rare-attack detection
* Production-oriented security design

---

# Future Work

* Federated learning integration
* Real-time packet streaming
* Adversarial robustness testing
* Online adaptive learning
* Distributed IDS architecture

---

# License

This project was developed as an academic final project at
Information Technology University.

---

<p align="center">
  <b>CyberShield — Intelligent Network Defense through Cascade AI</b>
</p>
