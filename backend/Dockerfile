FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
RUN useradd --system --uid 10001 --home-dir /srv app
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
