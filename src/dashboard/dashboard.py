"""
SmartGuard AI - Real-time Network Threat Detection Dashboard

This module provides an interactive web interface for monitoring network traffic
and detecting potential security threats using machine learning.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np
import os
import time
from pathlib import Path

# Set page config
st.set_page_config(
    page_title="SmartGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main-header {font-size:24px; color: #1f77b4; font-weight: bold;}
    .metric-card {background-color: #f8f9fa; border-radius: 10px; padding: 15px; margin: 10px 0;}
    .anomaly {color: #d62728; font-weight: bold;}
    .normal {color: #2ca02c;}
    </style>
""", unsafe_allow_html=True)

class SmartGuardDashboard:
    def __init__(self):
        self.data_dir = Path(os.path.expanduser("~")).joinpath("SmartGuardAI", "data")
        self.raw_data_dir = self.data_dir / "raw"
        self.processed_data_dir = self.data_dir / "processed"
        self.models_dir = self.data_dir / "models"
        
        # Ensure directories exist
        for d in [self.raw_data_dir, self.processed_data_dir, self.models_dir]:
            d.mkdir(parents=True, exist_ok=True)
    
    def get_latest_capture_file(self):
        """Get the most recent capture file."""
        try:
            capture_files = list(self.raw_data_dir.glob("capture_*.csv"))
            if not capture_files:
                return None
            return max(capture_files, key=os.path.getmtime)
        except Exception as e:
            st.error(f"Error finding capture files: {e}")
            return None
    
    def load_data(self, file_path):
        """Load and preprocess data from a capture file."""
        try:
            df = pd.read_csv(file_path)
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df = df.sort_values('timestamp')
            return df
        except Exception as e:
            st.error(f"Error loading data: {e}")
            return pd.DataFrame()
    
    def generate_synthetic_data(self, rows=1000):
        """Generate synthetic network traffic data for demonstration."""
        np.random.seed(42)
        now = datetime.now()
        timestamps = [now - timedelta(seconds=x) for x in range(rows)][::-1]
        
        data = {
            'timestamp': timestamps,
            'src_ip': [f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" for _ in range(rows)],
            'dst_ip': [f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" for _ in range(rows)],
            'src_port': np.random.randint(1024, 65535, size=rows),
            'dst_port': np.random.choice([80, 443, 22, 53, 3389, 8080, 21], size=rows, p=[0.3, 0.4, 0.05, 0.1, 0.05, 0.05, 0.05]),
            'protocol': np.random.choice(['TCP', 'UDP'], size=rows, p=[0.8, 0.2]),
            'length': np.random.lognormal(6.5, 0.5, size=rows).astype(int),
            'is_anomaly': np.random.choice([0, 1], size=rows, p=[0.9, 0.1])
        }
        
        # Add some patterns to anomalies
        for i in range(rows):
            if data['is_anomaly'][i]:
                if np.random.random() > 0.5:
                    data['dst_port'][i] = np.random.choice([4444, 31337, 2323, 23231])
                    data['length'][i] = np.random.randint(1500, 10000)
                else:
                    data['src_ip'][i] = f"1.2.3.{np.random.randint(1, 255)}"
        
        return pd.DataFrame(data)
    
    def plot_traffic_overview(self, df):
        """Create an overview plot of network traffic."""
        if df.empty:
            return None
            
        # Resample to show traffic over time
        df_resampled = df.set_index('timestamp').resample('1T').size().reset_index(name='count')
        
        fig = px.line(
            df_resampled, 
            x='timestamp', 
            y='count',
            title='Network Traffic Over Time',
            labels={'timestamp': 'Time', 'count': 'Packets per Minute'}
        )
        
        return fig
    
    def plot_protocol_distribution(self, df):
        """Create a pie chart of protocol distribution."""
        if df.empty or 'protocol' not in df.columns:
            return None
            
        protocol_counts = df['protocol'].value_counts().reset_index()
        protocol_counts.columns = ['Protocol', 'Count']
        
        fig = px.pie(
            protocol_counts,
            values='Count',
            names='Protocol',
            title='Protocol Distribution',
            hole=0.3
        )
        
        return fig
    
    def plot_port_activity(self, df, top_n=10):
        """Create a bar chart of top destination ports."""
        if df.empty or 'dst_port' not in df.columns:
            return None
            
        port_counts = df['dst_port'].value_counts().head(top_n).reset_index()
        port_counts.columns = ['Port', 'Count']
        
        fig = px.bar(
            port_counts,
            x='Port',
            y='Count',
            title=f'Top {top_n} Destination Ports',
            text='Count',
            color='Count',
            color_continuous_scale='Viridis'
        )
        
        fig.update_traces(texttemplate='%{text:.2s}', textposition='outside')
        return fig
    
    def plot_anomalies(self, df):
        """Highlight anomalies in the traffic."""
        if df.empty or 'is_anomaly' not in df.columns:
            return None
            
        # Create a scatter plot of packet lengths over time
        df['anomaly'] = df['is_anomaly'].map({0: 'Normal', 1: 'Anomaly'})
        
        fig = px.scatter(
            df,
            x='timestamp',
            y='length',
            color='anomaly',
            color_discrete_map={'Normal': '#1f77b4', 'Anomaly': '#d62728'},
            title='Network Traffic Anomalies',
            labels={'timestamp': 'Time', 'length': 'Packet Length (bytes)', 'anomaly': 'Status'},
            hover_data=['src_ip', 'dst_ip', 'dst_port', 'protocol']
        )
        
        return fig
    
    def run(self):
        """Run the Streamlit dashboard."""
        st.title("🛡️ SmartGuard AI - Network Threat Detection")
        st.markdown("---")
        
        # Sidebar for controls
        st.sidebar.header("Dashboard Controls")
        
        # Data source selection
        data_source = st.sidebar.radio(
            "Data Source",
            ["Live Capture (Simulated)", "Load from File"]
        )
        
        if data_source == "Load from File":
            uploaded_file = st.sidebar.file_uploader("Upload capture file", type=["csv", "pcap"])
            if uploaded_file is not None:
                df = self.load_data(uploaded_file)
            else:
                latest_file = self.get_latest_capture_file()
                if latest_file:
                    st.sidebar.info(f"Using latest capture: {latest_file.name}")
                    df = self.load_data(latest_file)
                else:
                    st.warning("No capture files found. Using synthetic data.")
                    df = self.generate_synthetic_data()
        else:
            # Use synthetic data for demo
            df = self.generate_synthetic_data()
            st.sidebar.info("Using simulated live data")
        
        # Display metrics
        if not df.empty:
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Packets", len(df))
            
            with col2:
                anomalies = df.get('is_anomaly', pd.Series([0])).sum()
                st.metric("Anomalies Detected", f"{anomalies} ({anomalies/len(df)*100:.1f}%)")
            
            with col3:
                if 'protocol' in df.columns:
                    top_proto = df['protocol'].value_counts().index[0]
                    st.metric("Top Protocol", top_proto)
            
            with col4:
                if 'length' in df.columns:
                    avg_len = int(df['length'].mean())
                    st.metric("Avg Packet Size", f"{avg_len:,} bytes")
            
            st.markdown("---")
            
            # Main content area with tabs
            tab1, tab2, tab3 = st.tabs(["Traffic Overview", "Anomaly Analysis", "Raw Data"])
            
            with tab1:
                st.header("Network Traffic Overview")
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    fig = self.plot_traffic_overview(df)
                    if fig:
                        st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    fig = self.plot_protocol_distribution(df)
                    if fig:
                        st.plotly_chart(fig, use_container_width=True)
                
                st.plotly_chart(
                    self.plot_port_activity(df),
                    use_container_width=True
                )
            
            with tab2:
                st.header("Anomaly Detection")
                
                fig = self.plot_anomalies(df)
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
                
                if 'is_anomaly' in df.columns:
                    anomaly_df = df[df['is_anomaly'] == 1].copy()
                    if not anomaly_df.empty:
                        st.subheader("Detected Anomalies")
                        st.dataframe(
                            anomaly_df[['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'length']],
                            height=300,
                            use_container_width=True
                        )
            
            with tab3:
                st.header("Raw Data")
                st.dataframe(df, use_container_width=True)
        
        # Add auto-refresh for live data
        if data_source == "Live Capture (Simulated)":
            time.sleep(5)
            st.rerun()  # Using st.rerun() instead of the deprecated st.experimental_rerun()

if __name__ == "__main__":
    dashboard = SmartGuardDashboard()
    dashboard.run()
