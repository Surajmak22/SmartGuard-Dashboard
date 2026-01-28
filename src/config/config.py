# Configuration settings for SmartGuard AI

import os

# Data paths - using user's home directory to avoid permission issues
DATA_PATHS = {
    'raw_data': os.path.join(os.path.expanduser('~'), 'SmartGuardAI', 'data', 'raw'),
    'processed_data': os.path.join(os.path.expanduser('~'), 'SmartGuardAI', 'data', 'processed'),
}

# Model parameters
MODEL_CONFIG = {
    'isolation_forest': {
        'n_estimators': 100,
        'contamination': 0.1,
        'random_state': 42
    },
    'threshold': 0.5  # Decision threshold for anomaly classification
}

# Feature engineering parameters
FEATURE_CONFIG = {
    'window_size': 10,  # For time-based features
    'min_packet_length': 20,  # Minimum packet length to consider
    'max_packet_length': 1500  # Maximum packet length to consider
}

# Network parameters
NETWORK_CONFIG = {
    'interface': 'Ethernet',  # Default network interface to monitor
    'timeout': 30,  # Sniffing timeout in seconds
    'packet_count': 1000  # Number of packets to capture per session
}
