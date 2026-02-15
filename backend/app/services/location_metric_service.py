from geopy.distance import geodesic
from datetime import datetime, timezone
from app.models.login_event import LoginEvent

def compute_location_metric(last_login: LoginEvent, current_lat: float, current_lon: float) -> float:

    if not last_login.device_last_seen_at or not last_login.location_latitude or not last_login.location_longitude:
        return 0  # insufficient data

    last_coords = (last_login.location_latitude, last_login.location_longitude)
    current_coords = (current_lat, current_lon)

    distance_km = geodesic(last_coords, current_coords).km
    time_diff_hours = (datetime.now(timezone.utc) - last_login.device_last_seen_at).total_seconds() / 3600

    return distance_km / time_diff_hours if time_diff_hours > 0 else 0
