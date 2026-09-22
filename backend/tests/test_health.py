import pytest


def test_health_check(client):
    """Health endpoint must return 200 and correct service name."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "SIH26237-Backend"
    assert "version" in data


def test_openapi_schema_available(client):
    """Swagger/OpenAPI schema must be accessible."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "SIH26237" in schema["info"]["title"]


def test_docs_page_available(client):
    """Swagger UI docs page must load."""
    response = client.get("/docs")
    assert response.status_code == 200
