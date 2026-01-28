import pandas as pd
import numpy as np
from typing import Tuple, Dict, List, Optional
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FeatureEngineer:
    """
    A class for extracting and engineering features from network packet data.
    """
    
    def __init__(self, window_size: int = 10):
        """
        Initialize the FeatureEngineer.
        
        Args:
            window_size: Size of the sliding window for time-based features
        """
        self.window_size = window_size
        self.protocol_mapping = {
            'TCP': 1,
            'UDP': 2,
            'HTTP': 3,
            'HTTPS': 4,
            'DNS': 5,
            'ICMP': 6,
            None: 0  # For unknown protocols
        }
    
    def preprocess_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess the raw packet data.
        
        Args:
            df: DataFrame containing raw packet data
            
        Returns:
            Preprocessed DataFrame
        """
        if df.empty:
            return df
            
        # Make a copy to avoid modifying the original
        df = df.copy()
        
        # Convert timestamp to datetime if it's a string
        if 'timestamp' in df.columns and isinstance(df['timestamp'].iloc[0], str):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Sort by timestamp
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp').reset_index(drop=True)
        
        # Encode protocol
        if 'protocol' in df.columns:
            df['protocol_encoded'] = df['protocol'].map(
                lambda x: self.protocol_mapping.get(x, 0)
            )
        
        # Convert IP addresses to numerical representation
        for ip_col in ['src_ip', 'dst_ip']:
            if ip_col in df.columns:
                df[f'{ip_col}_encoded'] = df[ip_col].apply(
                    lambda x: self._ip_to_int(x) if pd.notnull(x) else 0
                )
        
        return df
    
    def extract_basic_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract basic statistical features from packet data.
        
        Args:
            df: Preprocessed DataFrame
            
        Returns:
            DataFrame with extracted features
        """
        if df.empty:
            return pd.DataFrame()
            
        features = {}
            
        # Basic packet statistics
        if 'length' in df.columns:
            features['packet_length_mean'] = df['length'].mean()
            features['packet_length_std'] = df['length'].std()
            features['packet_length_min'] = df['length'].min()
            features['packet_length_max'] = df['length'].max()
            
        # Protocol distribution
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts(normalize=True)
            for proto in self.protocol_mapping:
                if proto and proto in protocol_counts:
                    features[f'protocol_{proto.lower()}_ratio'] = protocol_counts[proto]
        
        # Port statistics
        for port in ['sport', 'dport']:
            if port in df.columns:
                # Count unique ports
                features[f'unique_{port}_count'] = df[port].nunique()
                
                # Common port statistics
                port_counts = df[port].value_counts(normalize=True)
                features[f'{port}_entropy'] = self._calculate_entropy(port_counts)
        
        # Time-based features
        if 'timestamp' in df.columns and len(df) > 1:
            time_diffs = df['timestamp'].diff().dt.total_seconds().dropna()
            if not time_diffs.empty:
                features['packet_interval_mean'] = time_diffs.mean()
                features['packet_interval_std'] = time_diffs.std()
                features['packets_per_second'] = len(df) / (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
        
        return pd.DataFrame([features])
    
    def extract_time_series_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract time-series based features using sliding window.
        
        Args:
            df: Preprocessed DataFrame with timestamp index
            
        Returns:
            DataFrame with time-series features
        """
        if df.empty or 'timestamp' not in df.columns:
            return pd.DataFrame()
            
        # Set timestamp as index if not already
        if not isinstance(df.index, pd.DatetimeIndex):
            df = df.set_index('timestamp')
        
        # Resample to fixed intervals and calculate features
        resampled = df.resample('1S')
        
        # Calculate time-series features
        ts_features = pd.DataFrame()
        
        # Packet count per second
        if 'length' in df.columns:
            ts_features['packet_count'] = resampled['length'].count()
            ts_features['bytes_per_second'] = resampled['length'].sum()
        
        # Protocol distribution over time
        if 'protocol' in df.columns:
            for proto in self.protocol_mapping:
                if proto:  # Skip None
                    ts_features[f'{proto.lower()}_count'] = resampled.apply(
                        lambda x: (x['protocol'] == proto).sum()
                    )
        
        return ts_features
    
    def extract_flow_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract flow-based features (conversations between IPs).
        
        Args:
            df: Preprocessed DataFrame
            
        Returns:
            DataFrame with flow-based features
        """
        if df.empty or 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
            return pd.DataFrame()
            
        # Group by source and destination IP pairs
        flow_groups = df.groupby(['src_ip', 'dst_ip'])
        
        flow_features = []
        
        for (src, dst), group in flow_groups:
            if len(group) < 2:
                continue
                
            flow = {
                'src_ip': src,
                'dst_ip': dst,
                'flow_duration': (group['timestamp'].max() - group['timestamp'].min()).total_seconds(),
                'packet_count': len(group),
                'bytes_total': group['length'].sum(),
                'packets_per_second': len(group) / (group['timestamp'].max() - group['timestamp'].min()).total_seconds() if len(group) > 1 else 0,
            }
            
            # Protocol distribution in flow
            if 'protocol' in group.columns:
                proto_counts = group['protocol'].value_counts(normalize=True)
                for proto in self.protocol_mapping:
                    if proto and proto in proto_counts:
                        flow[f'flow_proto_{proto.lower()}_ratio'] = proto_counts[proto]
            
            flow_features.append(flow)
        
        return pd.DataFrame(flow_features)
    
    def _ip_to_int(self, ip: str) -> int:
        """Convert IP address to integer."""
        try:
            parts = list(map(int, ip.split('.')))
            return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        except (AttributeError, IndexError, ValueError):
            return 0
    
    def _calculate_entropy(self, value_counts: pd.Series) -> float:
        """Calculate entropy of a distribution."""
        probs = value_counts / value_counts.sum()
        return -np.sum(probs * np.log2(probs + 1e-10))  # Add small epsilon to avoid log(0)


def extract_features(df: pd.DataFrame, window_size: int = 10) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Extract all features from packet data.
    
    Args:
        df: Raw packet DataFrame
        window_size: Size of the sliding window for time-based features
        
    Returns:
        Tuple of (basic_features, time_series_features, flow_features)
    """
    engineer = FeatureEngineer(window_size=window_size)
    
    # Preprocess data
    df_processed = engineer.preprocess_data(df)
    
    # Extract different types of features
    basic_features = engineer.extract_basic_features(df_processed)
    time_series_features = engineer.extract_time_series_features(df_processed)
    flow_features = engineer.extract_flow_features(df_processed)
    
    return basic_features, time_series_features, flow_features
