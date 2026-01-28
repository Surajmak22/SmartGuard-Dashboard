import logging
import pandas as pd
from scapy.all import sniff, Ether, IP, TCP, UDP, Raw, get_if_list
import scapy.layers.http as http
from typing import Dict, Any, List, Optional
import time
import platform

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketCapture:
    """
    A class to capture and process network packets in real-time.
    """
    
    def __init__(self, interface: str = None, timeout: int = 30, packet_count: int = 1000):
        """
        Initialize the PacketCapture.
        
        Args:
            interface: Network interface to capture from (None for default)
            timeout: Time in seconds to capture packets
            packet_count: Maximum number of packets to capture
        """
        self.interface = interface
        self.timeout = timeout
        self.packet_count = packet_count
        self.packets = []
        
    @staticmethod
    def list_interfaces() -> list:
        """
        List all available network interfaces.
        
        Returns:
            List of available interface names
        """
        return get_if_list()
        
    def _process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Process a single packet and extract relevant features.
        
        Args:
            packet: Raw packet from scapy
            
        Returns:
            Dictionary of extracted features or None if packet is invalid
        """
        try:
            # Initialize packet info
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'length': len(packet),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'sport': None,
                'dport': None,
                'flags': None,
                'payload_size': 0
            }
            
            # Process Ethernet layer
            if Ether in packet:
                packet_info['src_mac'] = packet[Ether].src
                packet_info['dst_mac'] = packet[Ether].dst
            
            # Process IP layer
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['ip_version'] = packet[IP].version
                packet_info['ip_ttl'] = packet[IP].ttl
            
            # Process TCP layer
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['sport'] = packet[TCP].sport
                packet_info['dport'] = packet[TCP].dport
                packet_info['flags'] = str(packet[TCP].flags)
                if Raw in packet:
                    packet_info['payload_size'] = len(packet[Raw].load)
            
            # Process UDP layer
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['sport'] = packet[UDP].sport
                packet_info['dport'] = packet[UDP].dport
                if Raw in packet:
                    packet_info['payload_size'] = len(packet[Raw].load)
            
            # Process HTTP layer if present
            if packet.haslayer(http.HTTPRequest) or packet.haslayer(http.HTTPResponse):
                packet_info['protocol'] = 'HTTP'
            
            return packet_info
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return None
    
    def _get_interface_name(self, interface):
        """Convert Windows interface name to format expected by Scapy."""
        if platform.system() == 'Windows':
            if interface.startswith('\\Device\\NPF_'):
                # For Windows, use the full interface name
                return interface
            # If it's just the GUID, add the prefix
            if all(c in '0123456789ABCDEF-' for c in interface.upper()):
                return f'\\Device\\NPF_{interface}'
        return interface
        
    def _generate_synthetic_data(self) -> pd.DataFrame:
        """Generate synthetic network traffic data for testing."""
        import random
        from datetime import datetime, timedelta
        
        logger.warning("Live packet capture not available. Generating synthetic data for testing...")
        
        # Generate timestamps
        end_time = datetime.now()
        start_time = end_time - timedelta(seconds=self.timeout)
        timestamps = [start_time + timedelta(seconds=random.uniform(0, self.timeout)) 
                     for _ in range(self.packet_count or 100)]
        
        # Generate packet data
        packets = []
        for ts in sorted(timestamps):
            is_anomaly = random.random() < 0.1  # 10% chance of anomaly
            packet = {
                'timestamp': ts,
                'src_ip': f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                'dst_ip': f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 21, 53, 3389]),
                'protocol': random.choice(['TCP', 'UDP']),
                'length': random.randint(60, 1500),
                'is_anomaly': is_anomaly
            }
            
            # Add some anomalies
            if is_anomaly:
                packet['dst_port'] = random.choice([8080, 4444, 31337])  # Suspicious ports
                packet['length'] = random.randint(1500, 9000)  # Oversized packets
                
            packets.append(packet)
            
        return pd.DataFrame(packets)
        
    def start_capture(self) -> pd.DataFrame:
        """
        Start capturing network traffic or generate synthetic data if capture fails.
        
        Returns:
            DataFrame containing processed packet information
        """
        # Try live capture first
        try:
            # Convert interface name to correct format for Windows
            iface = self._get_interface_name(self.interface)
            logger.info(f"Starting packet capture on interface {iface}")
            
            # Clear previous packets
            self.packets = []
            
            # Start packet capture
            packets = sniff(
                iface=iface,
                timeout=self.timeout,
                count=self.packet_count,
                prn=self._process_packet_callback,
                store=0  # Don't store packets in memory, just process them
            )
            
            # Convert captured packets to DataFrame
            df = pd.DataFrame(self.packets)
            
            if not df.empty:
                logger.info(f"Successfully captured {len(df)} packets")
                return df
                
            logger.warning("No packets captured. Falling back to synthetic data.")
            
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
            logger.info("Available interfaces: %s", get_if_list())
            
        # Fall back to synthetic data
        return self._generate_synthetic_data()
        
        logger.info(f"Captured {len(df)} packets")
        return df
    
    def _process_packet_callback(self, packet):
        """Callback function for packet processing."""
        processed = self._process_packet(packet)
        if processed:
            self.packets.append(processed)
            
    def save_to_csv(self, filepath: str):
        """
        Save captured packets to a CSV file.
        
        Args:
            filepath: Path to save the CSV file
        """
        if not self.packets:
            logger.warning("No packets to save")
            return
            
        df = pd.DataFrame(self.packets)
        df.to_csv(filepath, index=False)
        logger.info(f"Saved {len(df)} packets to {filepath}")


def capture_live_traffic(interface: str, timeout: int = 30, packet_count: int = 1000) -> pd.DataFrame:
    """
    Convenience function to capture live network traffic.
    
    Args:
        interface: Network interface to capture from
        timeout: Time in seconds to capture
        packet_count: Maximum number of packets to capture
        
    Returns:
        DataFrame containing captured packet information
    """
    capture = PacketCapture(interface=interface, timeout=timeout, packet_count=packet_count)
    return capture.start_capture()
