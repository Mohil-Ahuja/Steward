# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

# Fail fast and keep the image small.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependency layer first so source edits do not invalidate the install cache.
COPY pyproject.toml README.md ./
COPY steward/__init__.py ./steward/
RUN pip install --no-cache-dir ".[postgres]"

COPY steward ./steward
COPY alembic ./alembic
COPY alembic.ini ./

# Never run as root: a proxy that holds every agent credential is a poor
# candidate for an unnecessary privilege.
RUN useradd --create-home --uid 10001 steward \
    && chown -R steward:steward /app
USER steward

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"

CMD ["uvicorn", "steward.main:app", "--host", "0.0.0.0", "--port", "8000"]
