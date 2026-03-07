from flask import Flask, render_template, request, jsonify
import requests
import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging safely
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = Flask(__name__)

API_KEY = os.getenv("WEATHER_API_KEY")
BASE_URL = "http://api.weatherapi.com/v1/current.json"


def get_weather_data(city: str):
    """Fetch weather data safely from WeatherAPI."""
    if not city:
        return None

    try:
        params = {"key": API_KEY, "q": city, "aqi": "no"}
        response = requests.get(BASE_URL, params=params, timeout=5)  # timeout prevents hang
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error("Weather API request failed: %s", e)
        return None


def format_weather_data(data: dict):
    """Return safe, formatted weather information."""
    if not data:
        return None

    return {
        "city": data.get("location", {}).get("name"),
        "country": data.get("location", {}).get("country"),
        "temperature": round(data.get("current", {}).get("temp_c", 0)),
        "feels_like": round(data.get("current", {}).get("feelslike_c", 0)),
        "description": data.get("current", {}).get("condition", {}).get("text", ""),
        "icon": data.get("current", {}).get("condition", {}).get("icon", ""),
        "humidity": data.get("current", {}).get("humidity", 0),
        "pressure": data.get("current", {}).get("pressure_mb", 0),
        "wind_speed": round(data.get("current", {}).get("wind_kph", 0), 1),
        "visibility": data.get("current", {}).get("vis_km", 0),
        "sunrise": "N/A",
        "sunset": "N/A",
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/weather", methods=["POST"])
def weather():
    city = request.form.get("city", "").strip()

    # Validate input: allow only letters, spaces, hyphens, apostrophes
    if not city or not all(c.isalpha() or c in " -'" for c in city):
        return jsonify({"error": "Please enter a valid city name"}), 400

    raw_data = get_weather_data(city)
    if not raw_data:
        return jsonify({"error": f"Could not retrieve weather data for '{city}'"}), 404

    weather_data = format_weather_data(raw_data)
    return jsonify(weather_data)


if __name__ == "__main__":
    # Always run with debug=False in production
    app.run(host="127.0.0.1", port=5000, debug=False)