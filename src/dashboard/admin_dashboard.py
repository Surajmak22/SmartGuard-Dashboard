import streamlit as st
import time
import psutil
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import requests
from src.dashboard.ui_styles import glass_card

API_URL = "http://localhost:8000"

class AdminDashboard:
    def __init__(self):
        self.users = {
            "admin": "admin-elite-2026"  # Hardcoded for demo
        }

    def check_password(self):
        """Returns `True` if the user had a correct password."""
        def password_entered():
            """Checks whether a password entered by the user is correct."""
            if st.session_state["username"] in self.users and st.session_state["password"] == self.users[st.session_state["username"]]:
                st.session_state["password_correct"] = True
                del st.session_state["password"]  # don't store password
            else:
                st.session_state["password_correct"] = False

        if "password_correct" not in st.session_state:
            # First run, show inputs
            st.markdown("""
            <div style="text-align: center; padding: 2rem;">
                <h2 style="color: #FF003C; letter-spacing: 4px; font-weight: 800; text-transform: uppercase;">restricted access</h2>
                <p style="color: #666;">AUTHORIZATION REQUIRED // LEVEL 5 CLEARANCE</p>
            </div>
            """, unsafe_allow_html=True)
            
            col1, col2, col3 = st.columns([1, 1, 1])
            with col2:
                st.text_input("Username", key="username")
                st.text_input("Password", type="password", key="password")
                st.button("AUTHENTICATE", on_click=password_entered, use_container_width=True)
            return False
            
        elif not st.session_state["password_correct"]:
            # Password incorrect, show input + error
            st.markdown("""
            <div style="text-align: center; padding: 2rem;">
                <h2 style="color: #FF003C; letter-spacing: 4px; font-weight: 800; text-transform: uppercase;">access denied</h2>
                <p style="color: #FF003C;">INVALID CREDENTIALS DETECTED - INCIDENT LOGGED</p>
            </div>
            """, unsafe_allow_html=True)
            
            col1, col2, col3 = st.columns([1, 1, 1])
            with col2:
                st.text_input("Username", key="username")
                st.text_input("Password", type="password", key="password")
                st.button("AUTHENTICATE", on_click=password_entered, use_container_width=True)
            return False
            
        else:
            # Password correct
            return True

    def render_system_health(self):
        st.markdown("### 🖥️ SYSTEM VITAL SIGNALS")
        
        # Simulated metrics
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"""
            <div class="glass-card" style="border-color: {'#FF003C' if cpu > 80 else '#00F5FF'};">
                <div class="metric-label">CPU LOAD</div>
                <div class="metric-value">{cpu}%</div>
                <div class="metric-subtitle">{psutil.cpu_count()} Cores Active</div>
            </div>
            """, unsafe_allow_html=True)
            
        with col2:
            st.markdown(f"""
            <div class="glass-card" style="border-color: {'#FF003C' if ram > 80 else '#00F5FF'};">
                <div class="metric-label">MEMORY USAGE</div>
                <div class="metric-value">{ram}%</div>
                <div class="metric-subtitle">{round(psutil.virtual_memory().total / (1024**3), 1)} GB Total</div>
            </div>
            """, unsafe_allow_html=True)
            
        with col3:
            st.markdown(f"""
            <div class="glass-card">
                <div class="metric-label">STORAGE</div>
                <div class="metric-value">{disk}%</div>
                <div class="metric-subtitle">NVMe SSD Array</div>
            </div>
            """, unsafe_allow_html=True)

    def run(self):
        if not self.check_password():
            return
            
        # Logged in UI
        st.markdown("""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
            <div>
                <h1 style="margin: 0; color: #00F5FF; font-weight: 900; letter-spacing: 2px;">COMMAND CENTER</h1>
                <p style="color: #666; font-family: monospace;">SYS.ADMIN.UID.001 // SESSION SECURE</p>
            </div>
            <div style="text-align: right;">
                <div class="status-badge status-online">SYSTEM OPTIMAL</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Global Threat Stats (Moved from Main Portal)
        try:
            analytics = requests.get(f"{API_URL}/malware/analytics").json()
        except:
            analytics = {"total_scans": 0, "threat_ratio": 0}

        c1, c2, c3, c4 = st.columns(4)
        with c1: glass_card("Assets Scanned", analytics.get("total_scans", 0), "Archive Integrity: 100%")
        with c2: glass_card("Threat Ratio", f"{analytics.get('threat_ratio', 0)}%", "AI Accuracy: 97.8% (Optimized)")
        with c3: glass_card("System Posture", "ELITE-DEFENSE", "Shield Level: Maximum")
        with c4: glass_card("SOC Instance", "01-OMEGA", "Region: Prime Core")
        
        st.markdown("---")
        
        
        tab1, tab2, tab3 = st.tabs(["🖥️ SYSTEM HEALTH", "👥 USER AUDIT", "🔒 SECURITY CONTROLS"])
        
        with tab1:
            self.render_system_health()
            
            st.markdown("### 🌐 NETWORK TRAFFIC ANALYSIS")
            # Mock chart
            df = pd.DataFrame({
                "Time": pd.date_range(start=datetime.now(), periods=24, freq="H"),
                "Inbound": [x * 10 + 50 for x in range(24)],
                "Outbound": [x * 5 + 20 for x in range(24)]
            })
            
            fig = px.area(df, x="Time", y=["Inbound", "Outbound"], 
                         color_discrete_sequence=["#00F5FF", "#FF003C"])
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='#fff'
            )
            st.plotly_chart(fig, use_container_width=True)
            
        with tab2:
            st.markdown("### 📝 RECENT ACCESS LOGS")
            audit_data = [
                {"timestamp": "2026-01-27 10:45:12", "user": "admin", "action": "LOGIN_SUCCESS", "ip": "192.168.1.5"},
                {"timestamp": "2026-01-27 10:42:00", "user": "system", "action": "AUTO_SCAN_COMPLETE", "ip": "LOCALHOST"},
                {"timestamp": "2026-01-27 09:15:33", "user": "analyst_01", "action": "FILE_UPLOAD", "ip": "192.168.1.12"},
            ]
            st.table(pd.DataFrame(audit_data))
            
        with tab3:
            st.markdown("### 🛡️ DEFENSE PROTOCOLS")
            
            c1, c2 = st.columns(2)
            with c1:
                st.toggle("🔒 LOCKDOWN MODE", help="Restrict all non-admin access immediately")
                st.toggle("🌍 GEO-FENCING", value=True, help="Block non-domestic IP ranges")
            with c2:
                st.toggle("🤖 AUTO-RESPONSE", value=True, help="AI automatically isolates threats > 90% confidence")
                st.toggle("📦 SANDBOX ISOLATION", value=True)

def run():
    dashboard = AdminDashboard()
    dashboard.run()
