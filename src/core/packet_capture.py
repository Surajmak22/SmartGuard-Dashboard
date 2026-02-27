import logging
import pandas as pd
from scapy.all import sniff, Ether, IP, TCP, UDP, Raw, get_if_list
import scapy.layers.http as http
from typing import Dict, Any, List, Optional
import time
import platform
import threading
from collections import deque
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketCapture:
    """
    A class to capture and process network packets in real-time (Background Thread).
    Implements a Singleton pattern to ensure only one sniffer runs effectively.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(PacketCapture, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, interface: str = None):
        """
        Initialize the PacketCapture.
        """
        if self._initialized:
            return
            
        self.interface = interface
        # Thread-safe circular buffer for latest packets
        self.packet_buffer = deque(maxlen=2000) 
        self.is_running = False
        self.capture_thread = None
        self._initialized = True
        
    @staticmethod
    def list_interfaces() -> list:
        """List all available network interfaces."""
        return get_if_list()
        
    def start_background_capture(self):
        """Start the packet capture in a background thread."""
        if self.is_running:
            return
            
        self.is_running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        logger.info("Background packet capture started.")

    def stop_capture(self):
        """Stop the packet capture thread."""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=1.0)
            logger.info("Packet capture stopped.")

    def _capture_loop(self):
        """Internal loop to run scapy sniff continuously."""
        try:
            # Determine interface
            iface = self.interface
            if not iface and platform.system() == 'Windows':
                # On Windows, user might need to specify interface if default fails
                pass

            # Use scapy sniff with 'prn' callback
            while self.is_running:
                try:
                    sniff(
                        iface=iface,
                        prn=self._process_packet_callback,
                        store=0,
                        timeout=1  # Check is_running every second
                    )
                except Exception as e:
                    logger.error(f"Sniff error: {e}")
                    time.sleep(2) # Backoff if sniffing fails (e.g. permission error)
                    
        except Exception as e:
            logger.error(f"Capture loop crashed: {e}")
            self.is_running = False

# Import ML Engine
from src.core.ml_engine import ml_engine

    def _process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Process a single packet and extract features."""
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'length': len(packet),
                'protocol': 'OTHER',
                'src_ip': 'N/A',
                'dst_ip': 'N/A',
                'sport': 0,
                'dport': 0,
                'flags': '',
                'payload_size': 0,
                'is_anomaly': False, 
                'risk_score': 0.0
            }
            
            # IP Layer
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['ip_ttl'] = packet[IP].ttl
            
            # Transport Layer
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['sport'] = packet[TCP].sport
                packet_info['dport'] = packet[TCP].dport
                packet_info['flags'] = str(packet[TCP].flags)
                if Raw in packet: packet_info['payload_size'] = len(packet[Raw].load)
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['sport'] = packet[UDP].sport
                packet_info['dport'] = packet[UDP].dport
                if Raw in packet: packet_info['payload_size'] = len(packet[Raw].load)
            elif packet.haslayer(http.HTTPRequest) or packet.haslayer(http.HTTPResponse):
                packet_info['protocol'] = 'HTTP'
            
            # Real-time ML Prediction
            try:
                risk_score = ml_engine.predict(packet_info)
                packet_info['risk_score'] = risk_score
                packet_info['is_anomaly'] = risk_score > 0.6  # Threshold for alert
            except Exception as ml_err:
                logger.error(f"ML Prediction failed: {ml_err}")
                
            return packet_info
            
        except Exception as e:
            return None
    
    def _process_packet_callback(self, packet):
        """Callback for Scapy."""
        if not self.is_running: return
        data = self._process_packet(packet)
        if data:
            self.packet_buffer.append(data)

    def get_dataframe(self, limit: int = 100) -> pd.DataFrame:
        """Get the latest N packets as a DataFrame."""
        if not self.packet_buffer:
            return pd.DataFrame()
            
        # Convert deque to list for DataFrame creation
        data = list(self.packet_buffer)[-limit:]
        return pd.DataFrame(data)

# Singleton Instance for easy import
# Usage: from src.core.packet_capture import scanner_instance
scanner_instance = PacketCapture()
