import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_weather_valid_city(client, monkeypatch):
    """Mock WeatherAPI for a valid city"""
    
    # Fake API response
    fake_api_response = {
        'location': {'name': 'London', 'country': 'UK'},
        'current': {
            'temp_c': 20,
            'feelslike_c': 19,
            'condition': {'text': 'Sunny', 'icon': 'icon.png'},
            'humidity': 50,
            'pressure_mb': 1012,
            'wind_kph': 10,
            'vis_km': 10
        }
    }

    # Replace get_weather_data() with a fake function
    def fake_get_weather_data(city):
        return fake_api_response

    monkeypatch.setattr("app.get_weather_data", fake_get_weather_data)

    # Now call your endpoint
    response = client.post("/weather", data={'city': 'London'})
    
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['city'] == 'London'
    assert json_data['temperature'] == 20
    assert json_data['description'] == 'Sunny'
