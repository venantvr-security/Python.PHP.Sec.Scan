"""BDD step definitions for API tests."""

import json
import time
from behave import given, when, then
import requests
from fastapi.testclient import TestClient


@given('que l\'API est démarrée')
def step_start_api(context):
    """Start API for testing."""
    from api.app import app
    context.client = TestClient(app)
    context.api_base = "http://localhost:8000"


@given('que l\'API est accessible sur "{url}"')
def step_set_api_url(context, url):
    """Set API URL."""
    context.api_base = url


@given('un scan en cours avec l\'ID "{scan_id}"')
def step_create_running_scan(context, scan_id):
    """Create a running scan."""
    context.scan_id = scan_id
    # TODO: Create actual running scan


@given('un scan terminé avec l\'ID "{scan_id}"')
def step_create_completed_scan(context, scan_id):
    """Create a completed scan."""
    context.scan_id = scan_id
    # TODO: Create actual completed scan


@given('que la limite est de {limit:d} requêtes par minute')
def step_set_rate_limit(context, limit):
    """Set rate limit."""
    context.rate_limit = limit


@when('j\'appelle GET "{endpoint}"')
def step_call_get(context, endpoint):
    """Call GET endpoint."""
    url = f"{context.api_base}{endpoint}"
    context.response = context.client.get(url)


@when('j\'appelle POST "{endpoint}" avec les données')
def step_call_post_with_data(context, endpoint):
    """Call POST endpoint with data."""
    data = json.loads(context.text)
    url = f"{context.api_base}{endpoint}"
    context.response = context.client.post(url, json=data)


@when('j\'appelle POST "{endpoint}" avec des données invalides')
def step_call_post_invalid_data(context, endpoint):
    """Call POST with invalid data."""
    data = json.loads(context.text)
    url = f"{context.api_base}{endpoint}"
    context.response = context.client.post(url, json=data)


@when('j\'appelle DELETE "{endpoint}"')
def step_call_delete(context, endpoint):
    """Call DELETE endpoint."""
    url = f"{context.api_base}{endpoint}"
    context.response = context.client.delete(url)


@when('j\'envoie {count:d} requêtes en moins d\'une minute')
def step_send_multiple_requests(context, count):
    """Send multiple requests rapidly."""
    context.responses = []

    for i in range(count):
        response = context.client.get("/api/v1/health")
        context.responses.append(response)
        time.sleep(0.1)


@when('j\'envoie une requête OPTIONS à "{endpoint}"')
def step_send_options(context, endpoint):
    """Send OPTIONS request."""
    url = f"{context.api_base}{endpoint}"
    context.response = context.client.options(url)


@then('le code de réponse devrait être {code:d}')
def step_verify_status_code(context, code):
    """Verify response status code."""
    assert context.response.status_code == code, \
        f"Expected {code}, got {context.response.status_code}"


@then('la réponse devrait contenir "{key}": "{value}"')
def step_verify_response_contains(context, key, value):
    """Verify response contains key-value."""
    data = context.response.json()
    assert key in data, f"Key {key} not in response"
    assert str(data[key]) == value, f"Expected {value}, got {data[key]}"


@then('la réponse devrait contenir un "{key}"')
def step_verify_response_has_key(context, key):
    """Verify response has key."""
    data = context.response.json()
    assert key in data, f"Key {key} not in response"


@then('le statut devrait être "{status}"')
def step_verify_status(context, status):
    """Verify scan status."""
    data = context.response.json()
    assert data.get('status') == status, \
        f"Expected status {status}, got {data.get('status')}"


@then('la {nth:d}ème requête devrait retourner {code:d}')
def step_verify_nth_request_status(context, nth, code):
    """Verify specific request status code."""
    response = context.responses[nth - 1]
    assert response.status_code == code, \
        f"Request {nth}: expected {code}, got {response.status_code}"


@then('la réponse devrait contenir le texte "{text}"')
def step_verify_response_text(context, text):
    """Verify response contains text."""
    if hasattr(context.response, 'json'):
        data = context.response.json()
        assert text in str(data), f"Text '{text}' not in response"
    else:
        assert text in context.response.text, f"Text '{text}' not in response"


@then('la réponse devrait contenir une erreur de validation')
def step_verify_validation_error(context):
    """Verify validation error in response."""
    data = context.response.json()
    assert 'error' in data or 'detail' in data, "No error in response"


@then('le scan devrait être annulé')
def step_verify_scan_cancelled(context):
    """Verify scan was cancelled."""
    # TODO: Verify actual scan cancellation
    pass


@then('les headers devraient contenir "{header}"')
def step_verify_header(context, header):
    """Verify response header."""
    assert header in context.response.headers, \
        f"Header {header} not in response"


@then('la page devrait contenir la documentation Swagger UI')
def step_verify_swagger_ui(context):
    """Verify Swagger UI page."""
    assert 'swagger' in context.response.text.lower() or \
           'openapi' in context.response.text.lower(), \
           "Swagger UI not found in response"
