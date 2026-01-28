import os
import sys
import argparse
import logging
import pandas as pd
from datetime import datetime

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import local modules
from core.packet_capture import PacketCapture, capture_live_traffic
from features.feature_engineering import extract_features, FeatureEngineer
from detection.anomaly_detector import AnomalyDetector
from config.config import DATA_PATHS, MODEL_CONFIG, FEATURE_CONFIG, NETWORK_CONFIG

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('smartguard_ai.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SmartGuardAI:
    """
    Main class for the SmartGuard AI Network Threat Detector.
    """
    
    def __init__(self, config=None):
        """
        Initialize SmartGuardAI with configuration.
        
        Args:
            config: Configuration dictionary (optional)
        """
        self.config = {
            'data_paths': DATA_PATHS,
            'model_config': MODEL_CONFIG,
            'feature_config': FEATURE_CONFIG,
            'network_config': NETWORK_CONFIG
        }
        
        if config:
            self.config.update(config)
        
        # Initialize components
        self.packet_capture = None
        self.feature_engineer = FeatureEngineer(
            window_size=self.config['feature_config'].get('window_size', 10)
        )
        self.anomaly_detector = AnomalyDetector(
            model_params=self.config['model_config'].get('isolation_forest', {})
        )
        
        # Create necessary directories
        self._create_directories()
    
    def _create_directories(self):
        """Create necessary directories if they don't exist."""
        for path in self.config['data_paths'].values():
            os.makedirs(path, exist_ok=True)
    
    def capture_traffic(self, interface=None, timeout=None, packet_count=None, save_to_file=True):
        """
        Capture network traffic.
        
        Args:
            interface: Network interface to capture from
            timeout: Time in seconds to capture
            packet_count: Maximum number of packets to capture
            save_to_file: Whether to save captured packets to a file
            
        Returns:
            DataFrame containing captured packets
        """
        # Use config values if parameters are not provided
        interface = interface or self.config['network_config'].get('interface')
        timeout = timeout or self.config['network_config'].get('timeout', 30)
        packet_count = packet_count or self.config['network_config'].get('packet_count', 1000)
        
        logger.info(f"Starting packet capture on interface {interface} for {timeout} seconds...")
        
        try:
            # Create and configure packet capture
            self.packet_capture = PacketCapture(
                interface=interface,
                timeout=timeout,
                packet_count=packet_count
            )
            
            # Start capturing packets
            packets_df = self.packet_capture.start_capture()
            
            # Save to file if requested
            if save_to_file and not packets_df.empty:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = os.path.join(
                    self.config['data_paths']['raw_data'],
                    f'capture_{timestamp}.csv'
                )
                packets_df.to_csv(output_file, index=False)
                logger.info(f"Saved captured packets to {output_file}")
            
            return packets_df
            
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
            raise
    
    def process_packets(self, packets_df=None, input_file=None):
        """
        Process captured packets and extract features.
        
        Args:
            packets_df: DataFrame containing packets (optional)
            input_file: Path to CSV file containing packets (optional)
            
        Returns:
            Tuple of (basic_features, time_series_features, flow_features)
        """
        try:
            # Load data if not provided
            if packets_df is None and input_file:
                logger.info(f"Loading packets from {input_file}")
                packets_df = pd.read_csv(input_file)
            
            if packets_df is None or packets_df.empty:
                raise ValueError("No packet data provided or data is empty")
            
            # Extract features
            logger.info("Extracting features from packets...")
            basic_features, time_series_features, flow_features = extract_features(
                packets_df,
                window_size=self.config['feature_config'].get('window_size', 10)
            )
            
            # Save extracted features
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            if not basic_features.empty:
                basic_file = os.path.join(
                    self.config['data_paths']['processed_data'],
                    f'basic_features_{timestamp}.csv'
                )
                basic_features.to_csv(basic_file, index=False)
                logger.info(f"Saved basic features to {basic_file}")
            
            if not time_series_features.empty:
                ts_file = os.path.join(
                    self.config['data_paths']['processed_data'],
                    f'time_series_features_{timestamp}.csv'
                )
                time_series_features.to_csv(ts_file, index=True)
                logger.info(f"Saved time series features to {ts_file}")
            
            if not flow_features.empty:
                flow_file = os.path.join(
                    self.config['data_paths']['processed_data'],
                    f'flow_features_{timestamp}.csv'
                )
                flow_features.to_csv(flow_file, index=False)
                logger.info(f"Saved flow features to {flow_file}")
            
            return basic_features, time_series_features, flow_features
            
        except Exception as e:
            logger.error(f"Error processing packets: {str(e)}")
            raise
    
    def train_model(self, features_df, labels=None):
        """
        Train the anomaly detection model.
        
        Args:
            features_df: DataFrame containing features for training
            labels: Optional labels for supervised training
            
        Returns:
            Training metrics
        """
        try:
            logger.info("Training anomaly detection model...")
            metrics = self.anomaly_detector.train(features_df)
            logger.info("Model training completed successfully")
            return metrics
            
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            raise
    
    def detect_anomalies(self, features_df, threshold=None):
        """
        Detect anomalies in the provided features.
        
        Args:
            features_df: DataFrame containing features to analyze
            threshold: Decision threshold (optional)
            
        Returns:
            Tuple of (predictions, scores)
        """
        try:
            logger.info("Detecting anomalies...")
            predictions = self.anomaly_detector.predict(features_df)
            scores = self.anomaly_detector.predict_proba(features_df)
            
            # Convert to anomaly (1) / normal (0) format
            anomalies = (predictions == -1).astype(int)
            
            logger.info(f"Detected {anomalies.sum()} anomalies out of {len(anomalies)} samples")
            
            return anomalies, scores
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            raise

def list_interfaces():
    """List all available network interfaces."""
    from core.packet_capture import PacketCapture
    print("\nAvailable network interfaces:")
    print("-" * 40)
    for i, iface in enumerate(PacketCapture.list_interfaces()):
        print(f"{i + 1}. {iface}")
    print("\nTo use an interface, copy its name and use it with the capture command.")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='SmartGuard AI: Network Threat Detector')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List interfaces command
    list_parser = subparsers.add_parser('list-interfaces', help='List available network interfaces')
    
    # Capture command
    capture_parser = subparsers.add_parser('capture', help='Capture network traffic')
    capture_parser.add_argument('-i', '--interface', help='Network interface to capture from')
    capture_parser.add_argument('-t', '--timeout', type=int, help='Capture duration in seconds')
    capture_parser.add_argument('-c', '--count', type=int, help='Maximum number of packets to capture')
    
    # Process command
    process_parser = subparsers.add_parser('process', help='Process captured packets')
    process_parser.add_argument('-i', '--input', required=True, help='Input CSV file containing packets')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train the anomaly detection model')
    train_parser.add_argument('-i', '--input', required=True, help='Input CSV file containing features')
    train_parser.add_argument('-l', '--labels', help='Input CSV file containing labels')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Detect anomalies')
    detect_parser.add_argument('-i', '--input', required=True, help='Input CSV file containing features')
    detect_parser.add_argument('-m', '--model', help='Path to trained model file')
    
    return parser.parse_args()

def main():
    """Main entry point for the SmartGuard AI application."""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Initialize SmartGuardAI
        smartguard = SmartGuardAI()
        
        # Execute the requested command
        if args.command == 'list-interfaces':
            list_interfaces()
            return 0
        elif args.command == 'capture':
            try:
                smartguard = SmartGuardAI()
                packets = smartguard.capture_traffic(
                    interface=args.interface,
                    timeout=args.timeout,
                    packet_count=args.count
                )
                print(f"Captured {len(packets)} packets")
            except Exception as e:
                logger.error(f"Error: {str(e)}", exc_info=True)
                return 1
            
        elif args.command == 'process':
            # Process captured packets
            basic, ts, flow = smartguard.process_packets(input_file=args.input)
            print(f"Extracted {len(basic)} basic features, {len(ts)} time series features, and {len(flow)} flow features")
            
        elif args.command == 'train':
            # Train the model
            features = pd.read_csv(args.input)
            labels = pd.read_csv(args.labels) if args.labels else None
            metrics = smartguard.train_model(features, labels)
            print("Training completed with metrics:", metrics)
            
        elif args.command == 'detect':
            # Detect anomalies
            features = pd.read_csv(args.input)
            anomalies, scores = smartguard.detect_anomalies(features)
            print(f"Detected {anomalies.sum()} anomalies out of {len(anomalies)} samples")
            
        else:
            print("Please specify a valid command. Use --help for usage information.")
            return 1
            
        return 0
        
    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
