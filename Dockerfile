# -----------------------------
# Stage 1: builder
# -----------------------------
FROM python:3.11-slim AS builder

WORKDIR /app

# Copy project files
COPY . /app

# Install build dependencies
RUN pip install --upgrade pip setuptools wheel

# Build wheel
RUN python -m build -w -n

# -----------------------------
# Stage 2: runtime
# -----------------------------
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install runtime dependencies (wheel from builder)
COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Default execution
ENTRYPOINT ["file-hunter"]
CMD ["-h"]
