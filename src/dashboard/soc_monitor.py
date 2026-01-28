import streamlit as st
import pandas as pd
from src.dashboard.styles.soc_map import create_threat_map

def run():
    # 1. Visual Header
    st.markdown("""
        <div style="text-align: center; margin-bottom: 2rem;">
            <h1 style="background: linear-gradient(to right, #00F5FF, #0072FF); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: 2px; font-weight: 800;">GLOBAL THREAT LANDSCAPE</h1>
            <p style="color: #94A3B8; font-size: 1.1rem;">Real-time visualization of global cyber activity and safety awareness.</p>
        </div>
    """, unsafe_allow_html=True)

    # 2. Key Status Indicators (Simple)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Global Threat Level", "ELEVATED", delta="Active Campaigns Detected", delta_color="inverse")
    with c2:
        st.metric("System Protection", "ACTIVE", "AI Shield Engaged")
    with c3:
        st.metric("Community Status", "SAFE", "No Local Breaches")

    st.markdown("---")

    # 3. Interactive Map (Eye Candy)
    st.markdown("### 🌍 Live Cyber Activity Map")
    st.plotly_chart(create_threat_map(), use_container_width=True)
    
    st.markdown("---")

    # 4. Educational / Awareness Section (Value for Non-Tech Users)
    st.markdown("""
        <div style="margin-bottom: 1rem;">
            <h3 style="color: #FFFFFF;">🧠 Security Wisdom</h3>
            <p style="color: #666;">Daily insights to keep your digital life secure.</p>
        </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
            <div style="background: rgba(0, 245, 255, 0.1); border: 1px solid rgba(0, 245, 255, 0.3); border-radius: 10px; padding: 20px; height: 100%;">
                <h4 style="color: #00F5FF;">💡 Tip of the Day</h4>
                <p style="color: #EEE; font-size: 0.9rem;">
                    <strong>Enable Multi-Factor Authentication (MFA)</strong> on your email and banking accounts. 
                    It stops 99% of automated attacks even if your password is stolen.
                </p>
            </div>
        """, unsafe_allow_html=True)
        
    with col2:
        st.markdown("""
            <div style="background: rgba(255, 0, 60, 0.1); border: 1px solid rgba(255, 0, 60, 0.3); border-radius: 10px; padding: 20px; height: 100%;">
                <h4 style="color: #FF003C;">⚠️ Emerging Threat</h4>
                <p style="color: #EEE; font-size: 0.9rem;">
                    <strong>'Deepfake' Voice Scams</strong> are on the rise. 
                    If a 'relative' calls asking for money urgently, verify their identity with a text or a secret question.
                </p>
            </div>
        """, unsafe_allow_html=True)
        
    with col3:
        st.markdown("""
            <div style="background: rgba(57, 255, 20, 0.1); border: 1px solid rgba(57, 255, 20, 0.3); border-radius: 10px; padding: 20px; height: 100%;">
                <h4 style="color: #39FF14;">✅ Best Practice</h4>
                <p style="color: #EEE; font-size: 0.9rem;">
                    <strong>Use a Password Manager</strong> (like Bitwarden). 
                    It's safer than memorizing passwords because it generates unique 20+ character strings for every site.
                </p>
            </div>
        """, unsafe_allow_html=True)
