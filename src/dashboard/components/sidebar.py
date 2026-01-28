import streamlit as st
import psutil
from src.dashboard.styles.ui_components import glass_card

def render_sidebar():
    """Renders the main sidebar with navigation and system status."""
    
    # 1. Branding Header
    st.sidebar.markdown("""
        <div style="text-align: center; padding: 2rem 0; animation: fadeIn 1.5s ease-in-out;">
            <img src="https://img.icons8.com/isometric/100/shield.png" width="90" style="filter: drop-shadow(0 0 10px #00F5FF);">
            <h2 style="margin-top: 1rem; letter-spacing: 2px; font-weight: 900; background: linear-gradient(90deg, #00F5FF, #0072FF); -webkit-background-clip: text; -webkit-text-fill-color: transparent; text-shadow: 0 0 20px rgba(0, 245, 255, 0.3);">
                SMARTGUARD AI
            </h2>
            <div style="font-size: 0.75rem; color: #CCCCCC; text-transform: uppercase; letter-spacing: 4px; font-weight: 600;">Elite Cyber Defense</div>
        </div>
    """, unsafe_allow_html=True)
    
    st.sidebar.divider()
    
    # 2. Navigation Mode Selection
    st.sidebar.markdown("<h3 style='color: #00F5FF; font-size: 0.9rem; margin-bottom: 0.5rem; text-transform: uppercase;'>Mission Control</h3>", unsafe_allow_html=True)
    
    # Check for admin mode
    # USAGE: http://localhost:8501/?mode=admin
    # query_params = st.query_params
    # admin_mode = query_params.get("mode") == "admin"
    
    # Use session state for persistence if needed, or just URL
    admin_mode = st.query_params.get("mode") == "admin"
    
    modes = [
        "🌍 Global Threat Map", 
        "🦠 Malware Analysis Portal",
        "📚 Documentation & Guides"
    ]
    
    if admin_mode:
        modes.append("🔐 Admin Command Center")
    
    app_mode = st.sidebar.radio(
        "Select Operation Mode",
        modes,
        label_visibility="collapsed"
    )

    st.sidebar.divider()
    
    # 3. (Optional) Credits or Footer
    st.sidebar.markdown("""
        <div style="text-align: center; font-size: 0.7rem; color: #666; margin-top: 50px;">
            SECURE ENVIRONMENT<br>v2.5.0
        </div>
    """, unsafe_allow_html=True)
    
    return app_mode

# render_system_monitor removed as per user request

def render_system_monitor():
    """Renders real-time system resource usage."""
    cpu_percent = psutil.cpu_percent()
    mem_usage = psutil.virtual_memory().percent
    
    # Dynamic Health Color
    cpu_color = "#38BDF8" if cpu_percent < 70 else "#FFA500" if cpu_percent < 90 else "#FF003C"
    mem_color = "#818CF8" if mem_usage < 70 else "#FFA500" if mem_usage < 90 else "#FF003C"

    st.sidebar.markdown(f"""
        <div class="glass-card" style="padding: 1rem; margin-top: 1rem;">
            <div style="font-size: 0.75rem; color: #9CA3AF; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 1px;">System Status</div>
            
            <div style="margin-bottom: 0.8rem;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <span style="font-size: 0.8rem; color: #E0E0E0;">CPU Load</span>
                    <span style="font-size: 0.8rem; color: {cpu_color}; font-weight: bold;">{cpu_percent}%</span>
                </div>
                <div style="width: 100%; height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px;">
                    <div style="width: {cpu_percent}%; height: 100%; background: {cpu_color}; border-radius: 2px; transition: width 0.5s;"></div>
                </div>
            </div>
            
            <div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <span style="font-size: 0.8rem; color: #E0E0E0;">Memory</span>
                    <span style="font-size: 0.8rem; color: {mem_color}; font-weight: bold;">{mem_usage}%</span>
                </div>
                <div style="width: 100%; height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px;">
                    <div style="width: {mem_usage}%; height: 100%; background: {mem_color}; border-radius: 2px; transition: width 0.5s;"></div>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)
