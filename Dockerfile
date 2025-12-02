# ===============================
# Stage 1: Builder
# ===============================
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install system build tools (if needed for cryptography)
RUN apt-get update && \
    apt-get install -y build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copy requirement file first (for caching)
COPY requirements.txt .

# Install dependencies into /install directory
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ===============================
# Stage 2: Runtime
# ===============================
FROM python:3.11-slim

# Set timezone to UTC
ENV TZ=UTC

# Install cron + timezone data
RUN apt-get update && \
    apt-get install -y cron tzdata && \
    rm -rf /var/lib/apt/lists/*

# Set timezone correctly
RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo "UTC" > /etc/timezone

# Working directory
WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy app code
COPY app ./app
COPY student_private.pem .
COPY student_public.pem .
COPY instructor_public.pem .

# Create required volume paths
RUN mkdir -p /data && mkdir -p /cron

# Set permissions (best-effort)
RUN chmod -R 755 /data && chmod -R 755 /cron

# Expose API port
EXPOSE 8080

# Copy cron job file into container (will create later in Step 8)
COPY cron/2fa-cron /etc/cron.d/2fa-cron

# Set permissions for cron job
RUN chmod 0644 /etc/cron.d/2fa-cron

# Apply cron job
RUN crontab /etc/cron.d/2fa-cron

# Start cron and API server
CMD cron & uvicorn app.main:app --host 0.0.0.0 --port 8080
