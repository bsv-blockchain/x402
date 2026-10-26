from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

V1_REQUIREMENTS = {
    "scheme": "exact",
    "network": "base-sepolia",
    "maxAmountRequired": "1000",
    "resource": "http://127.0.0.1/x",
    "description": "",
    "mimeType": "application/json",
    "payTo": "0x0000000000000000000000000000000000000002",
    "maxTimeoutSeconds": 60,
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "extra": {"name": "USDC", "version": "2"},
}

V1_PAYLOAD = {
    "x402Version": 1,
    "scheme": "exact",
    "network": "base-sepolia",
    "payload": {
        "signature": "0x" + "00" * 65,
        "authorization": {
            "from": "0x0000000000000000000000000000000000000001",
            "to": "0x0000000000000000000000000000000000000003",
            "value": "1000",
            "validAfter": "0",
            "validBefore": "9999999999",
            "nonce": "0x" + "00" * 32,
        },
    },
}


def test_verify_v1_request_returns_invalid_response():
    response = client.post(
        "/verify",
        json={"paymentPayload": V1_PAYLOAD, "paymentRequirements": V1_REQUIREMENTS},
    )

    assert response.status_code == 200
    assert response.json()["isValid"] is False


def test_verify_malformed_requirements_returns_400():
    requirements = {k: v for k, v in V1_REQUIREMENTS.items() if k != "maxAmountRequired"}

    response = client.post(
        "/verify",
        json={"paymentPayload": V1_PAYLOAD, "paymentRequirements": requirements},
    )

    assert response.status_code == 400
