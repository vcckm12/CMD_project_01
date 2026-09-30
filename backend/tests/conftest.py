"""Pytest Configuration and Common Fixtures."""

import pytest_asyncio
from app.guardrails.rule_manager import rule_manager
from app.main import app
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture(autouse=True)
async def initialize_test_rules():
    """Ensure rule manager is initialized before tests."""
    await rule_manager.initialize()


@pytest_asyncio.fixture
async def async_client():
    """Create an async test client for the FastAPI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
