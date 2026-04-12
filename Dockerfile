FROM python:3.12-slim

WORKDIR /app

# OCR prerequisites: ImageMagick (text→image) + Tesseract (image→text)
# DejaVu fonts for monospace rendering
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng \
        imagemagick \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Relax ImageMagick policy to allow text rendering and @file reads
# Default policy blocks these for "security" — we need them for OCR sanitization
RUN sed -i 's/<policy domain="coder" rights="none" pattern="TEXT"/<!-- <policy domain="coder" rights="none" pattern="TEXT"/' \
      /etc/ImageMagick-6/policy.xml 2>/dev/null || true && \
    sed -i 's/<policy domain="path" rights="none" pattern="@\*"/<!-- <policy domain="path" rights="none" pattern="@\*"/' \
      /etc/ImageMagick-6/policy.xml 2>/dev/null || true && \
    # Also allow reading from caption: and label:
    sed -i '/<policy domain="coder" rights="none" pattern="LABEL"/d' \
      /etc/ImageMagick-6/policy.xml 2>/dev/null || true

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY agent.py sanitize.py ./

# Non-root user
RUN useradd -m -u 1000 agent
# Temp dir for OCR working files
RUN mkdir -p /tmp/search-ocr && chown agent:agent /tmp/search-ocr
USER agent

EXPOSE 8000

CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
