"""Tests for Health, Liveness, Readiness, and Request Correlation endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint_structure(async_client: AsyncClient) -> None:
    """Verify GET /api/v1/health returns standardized APIResponse envelope."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()

    # Verify Envelope Structure
    assert "data" in body
    assert "meta" in body
    assert "error" in body
    assert body["error"] is None

    # Verify Metadata
    assert "timestamp" in body["meta"]
    assert "request_id" in body["meta"]
    assert response.headers.get("X-Request-ID") == body["meta"]["request_id"]

    # Verify Payload
    data = body["data"]
    assert data["version"] == "0.1.0"
    assert data["status"] in {"healthy", "degraded"}
    assert data["database"] in {"ready", "unreachable"}


@pytest.mark.asyncio
async def test_liveness_probe(async_client: AsyncClient) -> None:
    """Verify GET /api/v1/health/live responds with 200 and live status."""
    response = await async_client.get("/api/v1/health/live")
    assert response.status_code == 200
    body = response.json()
    assert body["data"] == {"status": "live"}
    assert body["error"] is None


@pytest.mark.asyncio
async def test_request_id_header_propagation(async_client: AsyncClient) -> None:
    """Verify that incoming X-Request-ID is preserved and echoed back."""
    custom_id = "req-client-custom-778899"
    response = await async_client.get("/api/v1/health/live", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == custom_id
    body = response.json()
    assert body["meta"]["request_id"] == custom_id


@pytest.mark.asyncio
async def test_standardized_404_error_envelope(async_client: AsyncClient) -> None:
    """Verify that unknown routes return standardized error envelope without stack traces."""
    response = await async_client.get("/api/v1/non-existent-route")
    assert response.status_code == 404
    body = response.json()
    assert body["data"] is None
    assert body["error"]["code"] == "NOT_FOUND"
    assert "meta" in body
    assert "request_id" in body["meta"]
