import streamlit as st
from datetime import datetime

def render_alert_manager():
    """
    Renders a custom alert rules management interface.
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            🚨 CUSTOM ALERT MANAGER
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Configure Threat Detection Alerts</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize session state for alerts
    if 'alert_rules' not in st.session_state:
        st.session_state['alert_rules'] = [
            {"name": "Critical Threat", "threshold": 90, "enabled": True, "severity": "CRITICAL"},
            {"name": "High Risk Detection", "threshold": 70, "enabled": True, "severity": "HIGH"},
        ]
    
    if 'alert_history' not in st.session_state:
        st.session_state['alert_history'] = []
    
    # Create new alert rule
    with st.expander("➕ CREATE NEW ALERT RULE", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            alert_name = st.text_input("Alert Name", placeholder="e.g., Ransomware Detection")
            risk_threshold = st.number_input("Risk Score Threshold", min_value=0, max_value=100, value=80)
        
        with col2:
            severity = st.selectbox("Severity Level", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            notification_type = st.selectbox("Notification Type", ["Dashboard Only", "Email (Simulated)", "Webhook (Simulated)"])
        
        if st.button("💾 Save Alert Rule", use_container_width=True):
            new_rule = {
                "name": alert_name,
                "threshold": risk_threshold,
                "enabled": True,
                "severity": severity,
                "notification": notification_type,
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            st.session_state['alert_rules'].append(new_rule)
            st.success(f"✅ Alert rule '{alert_name}' created successfully!")
    
    # Display existing rules
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <h3 style="color: #00F5FF; font-weight: 800; margin-bottom: 1rem;">
        📋 ACTIVE ALERT RULES
    </h3>
    """, unsafe_allow_html=True)
    
    if st.session_state['alert_rules']:
        for idx, rule in enumerate(st.session_state['alert_rules']):
            severity_colors = {
                "LOW": "#00FF88",
                "MEDIUM": "#FFA500",
                "HIGH": "#FF6B00",
                "CRITICAL": "#FF003C"
            }
            
            color = severity_colors.get(rule['severity'], "#00F5FF")
            
            col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
            
            with col1:
                st.markdown(f"""
                <div style="padding: 1rem; background: rgba(0, 245, 255, 0.05); border-left: 4px solid {color}; border-radius: 4px;">
                    <h4 style="color: #FFFFFF; font-weight: 800; margin: 0;">{rule['name']}</h4>
                    <p style="color: #FFFFFF; font-weight: 700; margin: 0.5rem 0 0 0; font-size: 0.9rem;">
                        Threshold: {rule['threshold']} | Severity: {rule['severity']}
                    </p>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                status = "🟢 ENABLED" if rule['enabled'] else "🔴 DISABLED"
                st.markdown(f"<p style='color: #FFFFFF; font-weight: 700; padding-top: 1rem;'>{status}</p>", unsafe_allow_html=True)
            
            with col3:
                if st.button(f"{'Disable' if rule['enabled'] else 'Enable'}", key=f"toggle_{idx}"):
                    st.session_state['alert_rules'][idx]['enabled'] = not rule['enabled']
                    st.rerun()
            
            with col4:
                if st.button("🗑️", key=f"delete_{idx}"):
                    st.session_state['alert_rules'].pop(idx)
                    st.rerun()
    else:
        st.info("No alert rules configured. Create your first rule above.")
    
    # Alert history
    st.markdown("<br><br>", unsafe_allow_html=True)
    st.markdown("""
    <h3 style="color: #00F5FF; font-weight: 800; margin-bottom: 1rem;">
        📜 ALERT HISTORY
    </h3>
    """, unsafe_allow_html=True)
    
    if st.session_state['alert_history']:
        for alert in st.session_state['alert_history'][-10:]:  # Show last 10
            st.markdown(f"""
            <div style="padding: 0.8rem; border-left: 4px solid #FF003C; background: rgba(255, 0, 60, 0.1); margin-bottom: 0.5rem; border-radius: 4px;">
                <p style="color: #FFFFFF; font-weight: 700; margin: 0;">
                    <strong style="color: #FF003C;">{alert['rule_name']}</strong> triggered at {alert['timestamp']}
                </p>
                <p style="color: #FFFFFF; font-weight: 600; margin: 0.3rem 0 0 0; font-size: 0.9rem;">
                    File: {alert['filename']} | Risk: {alert['risk_score']}
                </p>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No alerts triggered yet.")
