# Browser E2E runner: the Playwright image ships browsers; the Python package version matches it.
#   docker build -t ag-e2e -f scripts/e2e.Dockerfile scripts
FROM mcr.microsoft.com/playwright/python:v1.49.1-noble
RUN pip install --no-cache-dir --break-system-packages playwright==1.49.1
