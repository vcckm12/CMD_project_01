FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
# fonts-nanum: embedded Korean font for the audit PDF report (AUDIT-04).
RUN useradd --system --uid 10001 --home-dir /srv app \
    && apt-get update \
    && apt-get install -y --no-install-recommends fonts-nanum \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM base AS dev
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY . .
USER app

FROM base AS runtime
COPY app ./app
COPY migrations ./migrations
USER app
