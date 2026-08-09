FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN useradd -m -u 1000 -s /bin/bash hunter

WORKDIR /app

# Install dependencies before copying source for better layer caching
COPY pyproject.toml README.md ./
COPY athf/ ./athf/

RUN pip install --no-cache-dir -e ".[all]"

# Persistent workspace for hunt data (mounted as a volume)
RUN mkdir -p /workspace && chown hunter:hunter /workspace

USER hunter
WORKDIR /workspace

CMD ["/bin/bash"]
