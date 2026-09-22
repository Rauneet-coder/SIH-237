# ── Stage 1: Build liboqs C library ─────────────────────────────────
FROM python:3.11-slim AS liboqs-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    libssl-dev \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Clone and build liboqs
RUN git clone --depth=1 --branch main \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs

RUN cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
    -DOQS_DIST_BUILD=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_OPENSSL=ON && \
    ninja -C /tmp/liboqs/build && \
    ninja -C /tmp/liboqs/build install

# ── Stage 2: Python App ───────────────────────────────────────────────
FROM python:3.11-slim

# Copy compiled liboqs shared library from builder
COPY --from=liboqs-builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=liboqs-builder /usr/local/include/oqs /usr/local/include/oqs

# Needed runtime libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && ldconfig

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
