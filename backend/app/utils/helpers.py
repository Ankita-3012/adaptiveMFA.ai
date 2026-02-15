import json
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path
import numpy as np
import hashlib
from app.utils.logger import logger


def load_login_events(filepath: str) -> List[Dict[str, Any]]:
 
    try:
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"File {filepath} not found")
            return []
        
        with open(path, 'r') as f:
            data = json.load(f)
        
        logger.info(f"Loaded {len(data)} login events from {filepath}")
        return data
    except Exception as e:
        logger.error(f"Error loading login events: {e}")
        return []


def save_login_events(events: List[Dict[str, Any]], filepath: str) -> bool:
   
    try:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            json.dump(events, f, indent=2, default=str)
        
        logger.info(f"Saved {len(events)} login events to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error saving login events: {e}")
        return False


def extract_features(login_event: Dict[str, Any]) -> np.ndarray:
  
    features = []
    
    try:
        #Time features
        timestamp = datetime.fromisoformat(login_event.get('timestamp', ''))
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        features.extend([hour, day_of_week])
        
        #IP reputation (placeholder - 0.5 = neutral)
        ip_reputation = login_event.get('ip_reputation', 0.5)
        features.append(ip_reputation)
        
        #Device seen before (0 = new, 1 = familiar)
        device_familiar = 1.0 if login_event.get('device_seen_before', False) else 0.0
        features.append(device_familiar)
        
        #Location changed (0 = same, 1 = different)
        location_changed = 1.0 if login_event.get('location_changed', False) else 0.0
        features.append(location_changed)
        
        return np.array(features, dtype=np.float32)
    
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        #Return neutral features if extraction fails
        return np.array([12, 3, 0.5, 0.5, 0.0], dtype=np.float32)


def calculate_time_difference_hours(timestamp1: str, timestamp2: str) -> float:
  
    try:
        dt1 = datetime.fromisoformat(timestamp1)
        dt2 = datetime.fromisoformat(timestamp2)
        diff = abs((dt2 - dt1).total_seconds() / 3600)
        return diff
    except Exception as e:
        logger.error(f"Error calculating time difference: {e}")
        return 0.0


def calculate_geo_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    from math import radians, cos, sin, asin, sqrt
    
    try:
        lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
        
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        km = 6371 * c
        
        return km
    except Exception as e:
        logger.error(f"Error calculating geo distance: {e}")
        return 0.0


def generate_device_fingerprint(user_agent: str, accept_language: str) -> str:
    try:
        fingerprint_str = f"{user_agent}:{accept_language}"
        hash_val = hashlib.sha256(fingerprint_str.encode()).hexdigest()
        return hash_val
    except Exception as e:
        logger.error(f"Error generating device fingerprint: {e}")
        return "unknown"



def format_timestamp(dt: datetime = None) -> str:
    """Format datetime to ISO format string"""
    if dt is None:
        dt = datetime.utcnow()
    return dt.isoformat()


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse ISO format timestamp string to datetime"""
    try:
        return datetime.fromisoformat(timestamp_str)
    except Exception as e:
        logger.error(f"Error parsing timestamp: {e}")
        return datetime.utcnow()


def chunk_list(items: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split list into chunks of specified size"""
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input"""
    if not isinstance(text, str):
        return ""
    
    text = ''.join(char for char in text if ord(char) >= 32 or char == '\n')
    
    return text[:max_length].strip()