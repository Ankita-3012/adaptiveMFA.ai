import json
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.anomaly_service import AnomalyService
from app.utils.helpers import extract_features
from app.utils.logger import logger
import numpy as np

def debug_data():
    """Check if data is properly formatted and diverse"""
    logger.info("\n" + "="*60)
    logger.info("DATA VALIDATION")
    logger.info("="*60)
    
    try:
        with open('data/train_data.json') as f:
            train_events = json.load(f)
        
        logger.info(f"Loaded {len(train_events)} events")
        
        # Check distribution
        normal = [e for e in train_events if not e['is_anomalous']]
        anomalous = [e for e in train_events if e['is_anomalous']]
        
        logger.info(f"Normal: {len(normal)} ({len(normal)/len(train_events)*100:.1f}%)")
        logger.info(f"Anomalous: {len(anomalous)} ({len(anomalous)/len(train_events)*100:.1f}%)")
        
        # Check diversity
        normal_ips = set(e['ip_address'] for e in normal)
        anomalous_ips = set(e['ip_address'] for e in anomalous)
        
        logger.info(f"\n Diversity Check:")
        logger.info(f"Normal IPs: {len(normal_ips)} unique")
        logger.info(f"Anomalous IPs: {len(anomalous_ips)} unique")
        
        normal_locs = set(e['location'] for e in normal)
        anomalous_locs = set(e['location'] for e in anomalous)
        
        logger.info(f"Normal Locations: {normal_locs}")
        logger.info(f"Anomalous Locations: {anomalous_locs}")
        
        if len(normal_locs) < 2 or len(anomalous_locs) < 2:
            logger.warning("Low diversity in locations!")
        
        return train_events
        
    except Exception as e:
        logger.error(f"Error loading data: {e}")
        return None


def debug_features(train_events):
    """Check if features are being extracted properly"""
    logger.info("\n" + "="*60)
    logger.info("FEATURE EXTRACTION")
    logger.info("="*60)
    
    try:
        normal_events = [e for e in train_events if not e['is_anomalous']]
        anomaly_events = [e for e in train_events if e['is_anomalous']]
        
        # Extract features
        logger.info("Extracting features...")
        normal_features = []
        anomaly_features = []
        
        for e in normal_events[:10]:
            f = extract_features(e)
            normal_features.append(f)
        
        for e in anomaly_events[:10]:
            f = extract_features(e)
            anomaly_features.append(f)
        
        normal_features = np.array(normal_features)
        anomaly_features = np.array(anomaly_features)
        
        logger.info(f"Normal features shape: {normal_features.shape}")
        logger.info(f"Anomaly features shape: {anomaly_features.shape}")
        
        logger.info(f"\n Feature Statistics:")
        logger.info(f"Normal mean: {normal_features.mean(axis=0)}")
        logger.info(f"Anomaly mean: {anomaly_features.mean(axis=0)}")
        
        # Check if features are different
        feature_diff = np.abs(normal_features.mean(axis=0) - anomaly_features.mean(axis=0))
        logger.info(f"   Difference: {feature_diff}")
        
        if feature_diff.sum() < 0.5:
            logger.warning("Features are very similar! Model can't distinguish!")
            return False
        else:
            logger.info("Features are different enough")
            return True
        
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        import traceback
        traceback.print_exc()
        return False


def debug_model_training(train_events):
    """Test if model trains and can distinguish"""
    logger.info("\n" + "="*60)
    logger.info("MODEL TRAINING")
    logger.info("="*60)
    
    try:
        logger.info("Training model...")
        anomaly_svc = AnomalyService()
        
        success = anomaly_svc.train(train_events)
        logger.info(f"Training success: {success}")
        logger.info(f"Model trained: {anomaly_svc.is_trained}")
        
        if not success:
            logger.error("Model training failed!")
            return False
        
        return anomaly_svc
        
    except Exception as e:
        logger.error(f"Error training model: {e}")
        import traceback
        traceback.print_exc()
        return None


def debug_predictions(train_events, anomaly_svc):
    """Test if model can distinguish normal from anomalous"""
    logger.info("\n" + "="*60)
    logger.info("MODEL PREDICTIONS")
    logger.info("="*60)
    
    try:
        normal_events = [e for e in train_events if not e['is_anomalous']]
        anomaly_events = [e for e in train_events if e['is_anomalous']]
        
        # Test on first event of each type
        logger.info("Testing on sample events...")
        
        normal_scores = []
        anomaly_scores = []
        
        for i in range(min(20, len(normal_events))):
            score = anomaly_svc.detect_anomaly(normal_events[i])
            normal_scores.append(score)
        
        for i in range(min(20, len(anomaly_events))):
            score = anomaly_svc.detect_anomaly(anomaly_events[i])
            anomaly_scores.append(score)
        
        normal_mean = np.mean(normal_scores)
        anomaly_mean = np.mean(anomaly_scores)
        
        logger.info(f"Normal events mean score: {normal_mean:.3f}")
        logger.info(f"Anomaly events mean score: {anomaly_mean:.3f}")
        logger.info(f"Difference: {abs(anomaly_mean - normal_mean):.3f}")
        
        logger.info(f"\n Score Distribution:")
        logger.info(f"   Normal: min={min(normal_scores):.3f}, max={max(normal_scores):.3f}")
        logger.info(f"   Anomaly: min={min(anomaly_scores):.3f}, max={max(anomaly_scores):.3f}")
        
        if anomaly_mean > normal_mean:
            logger.info(" MODEL IS LEARNING! Anomalies score higher")
            return True
        else:
            logger.error(" MODEL NOT LEARNING! Scores are same")
            return False
        
    except Exception as e:
        logger.error(f"Error testing predictions: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all debug checks"""
    
    # Step 1: Check data
    train_events = debug_data()
    if not train_events:
        logger.error("Cannot proceed without data")
        return False
    
    # Step 2: Check features
    features_ok = debug_features(train_events)
    if not features_ok:
        logger.error("Features not diverse enough for model to learn")
        return False
    
    # Step 3: Train model
    anomaly_svc = debug_model_training(train_events)
    if not anomaly_svc:
        logger.error("Cannot proceed without trained model")
        return False
    
    # Step 4: Test predictions
    predictions_ok = debug_predictions(train_events, anomaly_svc)
    
    # Summary
    logger.info("\n" + "="*60)
    logger.info("SUMMARY")
    logger.info("="*60)
    
    if predictions_ok:
        logger.info("Model is working correctly!")
        logger.info("   If full training still shows 50% accuracy:")
        logger.info("   1. Check if test data is ALSO balanced 50/50")
        logger.info("   2. Delete model.pkl and retrain completely")
    else:
        logger.error("Model not learning. Possible causes:")
        logger.error("   1. Features too similar between normal/anomalous")
        logger.error("   2. Data quality issue")
        logger.error("   3. Model hyperparameter issue")
    
    return predictions_ok


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)