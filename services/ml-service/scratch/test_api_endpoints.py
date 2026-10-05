import sys
sys.path.insert(0, 'services/ml-service')
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

for endpoint in ['/analyze/media', '/internal/analyze/media', '/api/v1/analyze/media']:
    # Audio
    r_aud = client.post(endpoint, json={
        'media_type': 'audio',
        'file_url': 'datasets/audio-dfd-benchmark/dataset/100.wav'
    })
    assert r_aud.status_code == 200, f'{endpoint} audio failed: {r_aud.status_code}'
    data = r_aud.json()
    assert 'risk_score' in data
    assert 'risk_level' in data
    assert 'explanation' in data
    assert 'recommended_actions' in data
    assert data['signals']['media_type'] == 'audio'
    print(f"{endpoint} AUDIO -> 200 OK, risk={data['risk_score']}, class={data['signals']['classification']}")

    # Image
    r_img = client.post(endpoint, json={
        'media_type': 'image',
        'file_url': 'datasets/FaceForensics/images/ex_deepfakes.png'
    })
    assert r_img.status_code == 200, f'{endpoint} image failed: {r_img.status_code}'
    data_img = r_img.json()
    assert 'risk_score' in data_img
    assert data_img['signals']['media_type'] == 'image'
    print(f"{endpoint} IMAGE -> 200 OK, risk={data_img['risk_score']}, class={data_img['signals']['classification']}")

print("ALL FASTAPI MEDIA ENDPOINTS VERIFIED 100% OPERATIONAL!")
