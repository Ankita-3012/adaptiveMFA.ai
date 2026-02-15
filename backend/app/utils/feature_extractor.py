
import json
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path
import numpy as np
from app.utils.logger import logger

import hashlib
import math

class FeatureExtractor:
    
    KNOWN_BROWSERS = ['chrome', 'firefox', 'safari', 'edge', 'opera']
    KNOWN_OS = ['windows', 'mac', 'linux', 'android', 'ios']
    
    def __init__(self):
        pass
    
    def extract_features(self, event: Dict) -> List[float]:
        """Extract comprehensive features from a login event"""
        features = []
        
        #Temporal
        features.extend(self._extract_temporal_features(event))
        
        #Location
        features.extend(self._extract_location_features(event))
        
        #Device
        features.extend(self._extract_device_features(event))
        
        #Behavioural
        features.extend(self._extract_behavioral_features(event))
        
        #Advanced
        features.extend(self._extract_advanced_features(event))
        
        return features
    
    def _extract_temporal_features(self, event: Dict) -> List[float]:
        """Extract time-based features"""
        features = []
        
        try:
            timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            
            features.append(float(timestamp.hour))
            features.append(float(timestamp.weekday()))
            features.append(1.0 if timestamp.weekday() >= 5 else 0.0)
            
            features.append(1.0 if 9 <= timestamp.hour < 17 else 0.0)
        
            features.append(1.0 if timestamp.hour >= 23 or timestamp.hour < 5 else 0.0)
            
            hour_rad = 2 * math.pi * timestamp.hour / 24
            features.append(math.sin(hour_rad))
            features.append(math.cos(hour_rad))
            
            day_rad = 2 * math.pi * timestamp.weekday() / 7
            features.append(math.sin(day_rad))
            features.append(math.cos(day_rad))
            
        except Exception as e:
            logger.error(f"Temporal features error: {e}")
            features.extend([12.0, 3.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0])
        
        return features
    
    def _extract_location_features(self, event: Dict) -> List[float]:
        """Extract location-based features"""
        features = []
        
        # IP octets
        ip = event.get('ip_address', '0.0.0.0')
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) == 4:
                features.extend([float(o) for o in octets])
            else:
                features.extend([0.0, 0.0, 0.0, 0.0])
        except:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        # IP variance
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) == 4:
                mean = sum(octets) / 4
                variance = sum((x - mean) ** 2 for x in octets) / 4
                features.append(variance)
            else:
                features.append(0.0)
        except:
            features.append(0.0)
        
        # Is private IP?
        features.append(1.0 if self._is_private_ip(ip) else 0.0)
        
        # Country hash
        country = event.get('location_country', 'unknown')
        features.append(self._hash_to_bounded_int(country, 1000))
        
        # City hash
        city = event.get('location_city', 'unknown')
        features.append(self._hash_to_bounded_int(city, 10000))
        
        # Timezone
        timezone = event.get('timezone', 'UTC')
        tz_offset = self._extract_timezone_offset(timezone)
        features.append(tz_offset)
        
        return features
    
    def _extract_device_features(self, event: Dict) -> List[float]:
        """Extract device and user agent features"""
        features = []
        
        user_agent = event.get('user_agent', '').lower()
        
        # Browser detection (5 features)
        for browser in self.KNOWN_BROWSERS:
            features.append(1.0 if browser in user_agent else 0.0)
        
        # OS detection (5 features)
        for os in self.KNOWN_OS:
            features.append(1.0 if os in user_agent else 0.0)
        
        # Is mobile?
        is_mobile = 1.0 if any(x in user_agent for x in ['mobile', 'android', 'iphone']) else 0.0
        features.append(is_mobile)
        
        # User agent complexity
        features.append(float(len(user_agent)))
        features.append(float(len(set(user_agent))) if user_agent else 0.0)
        features.append(float(user_agent.count(' ')))
        features.append(float(user_agent.count('/')))
        
        # User agent hash
        features.append(self._hash_to_bounded_int(user_agent, 100000))
        
        return features
    
    def _extract_behavioral_features(self, event: Dict) -> List[float]:
        """Extract behavioral features"""
        features = []
        
        # Login success
        success = 1.0 if event.get('success', True) else 0.0
        features.append(success)
        
        # MFA used
        mfa_used = 1.0 if event.get('mfa_used', False) else 0.0
        features.append(mfa_used)
        
        # Success without MFA
        features.append(1.0 if (success and not event.get('mfa_used', False)) else 0.0)
        
        # Failure with MFA
        features.append(1.0 if (not success and event.get('mfa_used', False)) else 0.0)
        
        return features
    
    def _extract_advanced_features(self, event: Dict) -> List[float]:
        """Extract advanced composite features"""
        features = []
        
        # User ID hash
        user_id = event.get('user_id', 'unknown')
        features.append(self._hash_to_bounded_int(user_id, 10000))
        
        # Location signature
        country = event.get('location_country', 'unknown')
        city = event.get('location_city', 'unknown')
        location_sig = f"{country}_{city}"
        features.append(self._hash_to_bounded_int(location_sig, 50000))
        
        # Device signature
        user_agent = event.get('user_agent', '')
        device_sig = user_agent[:50] if len(user_agent) > 50 else user_agent
        features.append(self._hash_to_bounded_int(device_sig, 50000))
        
        # IP + User combination
        ip = event.get('ip_address', '0.0.0.0')
        ip_user_sig = f"{ip}_{user_id}"
        features.append(self._hash_to_bounded_int(ip_user_sig, 100000))
        
        # Location + Time combination
        try:
            timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            hour = timestamp.hour
            location_time_sig = f"{country}_{hour}"
            features.append(self._hash_to_bounded_int(location_time_sig, 50000))
        except:
            features.append(0.0)
        
        return features
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return False
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
            if octets[0] == 127:
                return True
        except:
            pass
        return False
    
    def _hash_to_bounded_int(self, text: str, max_val: int) -> float:
        """Convert text to bounded integer using hash"""
        if not text:
            return 0.0
        hash_val = int(hashlib.md5(text.encode()).hexdigest(), 16)
        return float(hash_val % max_val)
    
    def _extract_timezone_offset(self, timezone: str) -> float:
        """Extract timezone offset as hour value"""
        try:
            if '+' in timezone:
                offset = int(timezone.split('+')[1])
                return float(offset)
            elif '-' in timezone and timezone.count('-') == 1:
                offset = -int(timezone.split('-')[1])
                return float(offset)
        except:
            pass
        return 0.0

feature_extractor = FeatureExtractor()

def extract_features(login_event: Dict[str, Any]) -> np.ndarray:
    """
    Returns: numpy array
    """
    try:
        features = feature_extractor.extract_features(login_event)
        
        if len(features) != 39:
            logger.warning(f"got {len(features)}")
        
        return np.array(features, dtype=np.float32)
    
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        return np.zeros(39, dtype=np.float32)
