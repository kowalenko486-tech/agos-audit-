# AGOS 4.1 Standalone External Validation Container
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AGOS_PROVENANCE_SECRET=agos-4-1-docker-validation-secret-minimum-32b!

WORKDIR /app

# Install git for repo and commit safety tests
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    git config --global user.name "AGOS Docker Runner" && \
    git config --global user.email "docker@agos.internal" && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt requirements-test.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt -r requirements-test.txt

# Copy source code and test runner
COPY . .

# Run validation runner by default
ENTRYPOINT ["python", "run_validation.py"]
CMD []
