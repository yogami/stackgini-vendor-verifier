FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libatomic1 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project \
    && /app/.venv/bin/playwright install chromium --with-deps

COPY src ./src
COPY specs ./specs

EXPOSE 8000

CMD ["sh", "-c", "/app/.venv/bin/uvicorn src.api.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
