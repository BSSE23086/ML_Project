# ── Base Image ──────────────────────────────────────────────────
# Python 3.11 slim for a lightweight production container
FROM python:3.11-slim

# ── Metadata ────────────────────────────────────────────────────
LABEL maintainer="Muhammad Tayyab BSSE23018, Tehreem Mazhar BSSE23086"
LABEL description="Network Intrusion Detection System - NIDS"

# ── Environment Variables ────────────────────────────────────────
# Prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Flask app entry point
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# ── Working Directory ────────────────────────────────────────────
WORKDIR /app

# ── Install Dependencies ─────────────────────────────────────────
# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Copy Application Code ─────────────────────────────────────────
COPY . .

# ── Create Required Directories ──────────────────────────────────
# models/ stores trained .pkl files; data/ stores NSL-KDD dataset
RUN mkdir -p models data

# ── Expose Port ──────────────────────────────────────────────────
# AWS Elastic Beanstalk expects port 5000 by default for Python apps
EXPOSE 5000

# ── Health Check ─────────────────────────────────────────────────
# EB uses this to verify the container is running correctly
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# ── Start Command ─────────────────────────────────────────────────
# Gunicorn is the production WSGI server (better than Flask dev server)
# 4 workers handle concurrent requests efficiently on a t2.micro
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "app:app"]
