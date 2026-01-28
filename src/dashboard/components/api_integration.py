import streamlit as st
import random
from datetime import datetime, timedelta

def render_api_integration():
    """
    Renders an API integration dashboard for external threat intelligence.
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            🔌 API INTEGRATION DASHBOARD
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">External Threat Intelligence Sources</p>
    </div>
    """, unsafe_allow_html=True)
    
    # API Status Cards
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">VIRUSTOTAL API</div>
            <div class="metric-value" style="color: #00FF88; font-size: 1.5rem;">🟢 ACTIVE</div>
            <div class="metric-subtitle">Simulated Integration</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">HYBRID ANALYSIS</div>
            <div class="metric-value" style="color: #00FF88; font-size: 1.5rem;">🟢 ACTIVE</div>
            <div class="metric-subtitle">Simulated Integration</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">MITRE ATT&CK</div>
            <div class="metric-value" style="color: #00FF88; font-size: 1.5rem;">🟢 ACTIVE</div>
            <div class="metric-subtitle">Simulated Integration</div>
        </div>
        """, unsafe_allow_html=True)
    
    # API Configuration
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <h3 style="color: #00F5FF; font-weight: 800; margin-bottom: 1rem;">
        ⚙️ API CONFIGURATION
    </h3>
    """, unsafe_allow_html=True)
    
    with st.expander("🔑 VirusTotal API Settings", expanded=False):
        vt_api_key = st.text_input("API Key", type="password", placeholder="Enter your VirusTotal API key")
        vt_enabled = st.checkbox("Enable VirusTotal Integration", value=True)
        if st.button("💾 Save VirusTotal Config"):
            st.success("✅ VirusTotal configuration saved!")
    
    with st.expander("🔑 Hybrid Analysis API Settings", expanded=False):
        ha_api_key = st.text_input("API Key", type="password", placeholder="Enter your Hybrid Analysis API key", key="ha_key")
        ha_enabled = st.checkbox("Enable Hybrid Analysis Integration", value=True)
        if st.button("💾 Save Hybrid Analysis Config"):
            st.success("✅ Hybrid Analysis configuration saved!")
    
    # Simulated API Results
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <h3 style="color: #00F5FF; font-weight: 800; margin-bottom: 1rem;">
        📊 RECENT API QUERIES
    </h3>
    """, unsafe_allow_html=True)
    
    # Generate simulated data
    api_queries = [
        {
            "source": "VirusTotal",
            "hash": "a1b2c3d4e5f6...",
            "result": "32/70 detections",
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime("%H:%M:%S"),
            "status": "MALICIOUS"
        },
        {
            "source": "Hybrid Analysis",
            "hash": "f6e5d4c3b2a1...",
            "result": "Threat Score: 85/100",
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime("%H:%M:%S"),
            "status": "SUSPICIOUS"
        },
        {
            "source": "VirusTotal",
            "hash": "9876543210ab...",
            "result": "0/70 detections",
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime("%H:%M:%S"),
            "status": "CLEAN"
        }
    ]
    
    for query in api_queries:
        status_colors = {
            "MALICIOUS": "#FF003C",
            "SUSPICIOUS": "#FFA500",
            "CLEAN": "#00FF88"
        }
        
        color = status_colors.get(query['status'], "#00F5FF")
        
        st.markdown(f"""
        <div style="padding: 1rem; border-left: 4px solid {color}; background: rgba(0, 245, 255, 0.05); margin-bottom: 0.8rem; border-radius: 4px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h4 style="color: #00F5FF; font-weight: 800; margin: 0;">{query['source']}</h4>
                    <p style="color: #FFFFFF; font-weight: 700; margin: 0.3rem 0;">Hash: {query['hash']}</p>
                    <p style="color: #FFFFFF; font-weight: 600; margin: 0.3rem 0; font-size: 0.9rem;">{query['result']}</p>
                </div>
                <div style="text-align: right;">
                    <div style="color: {color}; font-size: 1.2rem; font-weight: 900;">{query['status']}</div>
                    <div style="color: #FFFFFF; font-size: 0.85rem; font-weight: 600;">{query['timestamp']}</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # API Usage Statistics
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <h3 style="color: #00F5FF; font-weight: 800; margin-bottom: 1rem;">
        📈 API USAGE STATISTICS
    </h3>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">TODAY'S QUERIES</div>
            <div class="metric-value" style="color: #00F5FF;">247</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">QUOTA REMAINING</div>
            <div class="metric-value" style="color: #00FF88;">753</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">AVG RESPONSE TIME</div>
            <div class="metric-value" style="color: #00F5FF;">1.2s</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">SUCCESS RATE</div>
            <div class="metric-value" style="color: #00FF88;">98.5%</div>
        </div>
        """, unsafe_allow_html=True)
