FROM python:3.10-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt \
    # drain3 cố ý không nằm trong requirements.txt vì metadata của nó pin
    # cachetools==4.2.1 (xung đột phiên bản). Cài riêng với --no-deps để dùng
    # cachetools hiện đại; jsonpickle là runtime-dep duy nhất cần bổ sung.
    && pip install --no-cache-dir --user --no-deps drain3==0.9.11 \
    && pip install --no-cache-dir --user "jsonpickle>=1.5.1"

# ---- Production Stage ----
FROM python:3.10-slim

# Security: Metadata labels
LABEL maintainer="Nguyen Duc Binh <binhchuoizzz@github>"
LABEL description="SENTINEL SOC - Autonomous AI Security Agent"
LABEL version="1.0.0"

# Install Trivy for Vulnerability Scanning (modern GPG key method)
# --no-install-recommends: giảm attack surface + kích thước image (đồng bộ builder stage)
RUN apt-get update && apt-get install -y --no-install-recommends wget apt-transport-https gnupg \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | tee /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y --no-install-recommends trivy \
    && rm -rf /var/lib/apt/lists/*

# Security: Create non-root user
RUN groupadd -r sentinel && useradd --no-log-init -r -g sentinel sentinel

WORKDIR /app

# Copy installed packages from builder — CRITICAL: chown to sentinel to fix exec permission
COPY --from=builder --chown=sentinel:sentinel /root/.local /home/sentinel/.local
ENV PATH=/home/sentinel/.local/bin:$PATH

# Copy application code
COPY --chown=sentinel:sentinel . .

# Security: Make knowledge_base read-only to prevent RAG poisoning
RUN chmod -R 555 /app/knowledge_base/ 2>/dev/null || true

# Ensure sentinel's pip binaries are executable
RUN chmod -R u+x /home/sentinel/.local/bin/ 2>/dev/null || true

# Expose Streamlit port
EXPOSE 8501

# Security: Run as non-root user
USER sentinel

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

ENTRYPOINT ["streamlit", "run", "src/ui/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
