FROM python:3.12-slim

WORKDIR /app

# OCR prerequisites — Tesseract + fonts only. No ImageMagick.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies (pinned in requirements.txt)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY agent.py sanitize.py ./

# Non-root user
RUN useradd -m -u 1000 agent && \
    mkdir -p /tmp/search-ocr && \
    chown -R agent:agent /tmp/search-ocr
USER agent

EXPOSE 8000

CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
