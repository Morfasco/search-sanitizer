FROM python:3.12-slim

WORKDIR /app

# OCR prerequisites
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng \
        imagemagick \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Replace ImageMagick policy entirely — container is network-isolated,
# permissive policy is acceptable. The default policy blocks caption:@file
# which is required for OCR text rendering.
RUN set -eux; \
    if [ -d /etc/ImageMagick-7 ]; then \
      POLICY_PATH=/etc/ImageMagick-7/policy.xml; \
    elif [ -d /etc/ImageMagick-6 ]; then \
      POLICY_PATH=/etc/ImageMagick-6/policy.xml; \
    else \
      POLICY_PATH=/etc/ImageMagick/policy.xml; \
    fi; \
    mkdir -p "$(dirname "$POLICY_PATH")"; \
    cat > "$POLICY_PATH" <<'POLICY'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policymap [
  <!ELEMENT policymap (policy)*>
  <!ATTLIST policymap xmlns CDATA #FIXED "">
  <!ELEMENT policy EMPTY>
  <!ATTLIST policy xmlns CDATA #FIXED "" domain NMTOKEN #REQUIRED
    name NMTOKEN #IMPLIED pattern CDATA #IMPLIED rights NMTOKEN #IMPLIED
    stealth NMTOKEN #IMPLIED value CDATA #IMPLIED>
]>
<policymap>
  <policy domain="resource" name="memory" value="512MiB"/>
  <policy domain="resource" name="map" value="512MiB"/>
  <policy domain="resource" name="width" value="8KP"/>
  <policy domain="resource" name="height" value="8KP"/>
  <policy domain="resource" name="area" value="64MP"/>
  <policy domain="resource" name="disk" value="1GiB"/>
  <policy domain="coder" rights="read|write" pattern="*" />
  <policy domain="path" rights="read|write" pattern="@*" />
</policymap>
POLICY

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY agent.py sanitize.py ./
COPY docker-entrypoint.sh /usr/local/bin/

# Pre-generate fontconfig cache during build (filesystem is writable here)
RUN fc-cache -f -v
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Non-root user
RUN useradd -m -u 1000 agent
# Writable dirs for OCR temp files + fontconfig cache
RUN mkdir -p /tmp/search-ocr /home/agent/.cache/fontconfig && \
    chown -R agent:agent /tmp/search-ocr /home/agent/.cache/fontconfig
USER agent

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Fontconfig needs a writable cache
ENV XDG_CACHE_HOME=/home/agent/.cache
ENV FONTCONFIG_PATH=/etc/fonts

EXPOSE 8000

CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
