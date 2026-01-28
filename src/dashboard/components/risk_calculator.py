import streamlit as st
import plotly.graph_objects as go

def render_risk_calculator():
    """
    Renders the interactive Risk Score Calculator.
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            🧮 RISK SCORE CALCULATOR
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Interactive Threat Impact Analysis</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("""
        <div style="padding: 1rem; background: rgba(0, 0, 0, 0.5); border: 1px solid #00F5FF; border-radius: 8px;">
            <h3 style="color: #00F5FF; font-size: 1.2rem; margin-bottom: 1rem;">⚙️ Adjust Risk Factors</h3>
        </div>
        """, unsafe_allow_html=True)
        
        signature_match = st.slider("Signature Match Severity (0-100)", 0, 100, 50)
        heuristic_score = st.slider("Heuristic Anomaly Score (0-100)", 0, 100, 30)
        behavioral_impact = st.slider("Behavioral Impact (0-100)", 0, 100, 20)
        network_activity = st.slider("Suspicious Network Activity (0-100)", 0, 100, 10)
        
        # Simple weighted formula
        total_risk = (
            (signature_match * 0.4) + 
            (heuristic_score * 0.3) + 
            (behavioral_impact * 0.2) + 
            (network_activity * 0.1)
        )
        
    with col2:
        st.markdown("""
        <div style="padding: 1rem; background: rgba(0, 0, 0, 0.5); border: 1px solid #00F5FF; border-radius: 8px; height: 100%;">
            <h3 style="color: #00F5FF; font-size: 1.2rem; margin-bottom: 1rem; text-align: center;">📊 Projected Risk Score</h3>
            <div style="display: flex; justify-content: center; align-items: center; height: 300px;">
        """, unsafe_allow_html=True)
        
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = total_risk,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Combined Risk", 'font': {'color': "white", 'size': 24}},
            gauge = {
                'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
                'bar': {'color': "#00F5FF"},
                'bgcolor': "rgba(0,0,0,0)",
                'borderwidth': 2,
                'bordercolor': "#333",
                'steps': [
                    {'range': [0, 40], 'color': 'rgba(0, 255, 136, 0.3)'},
                    {'range': [40, 70], 'color': 'rgba(255, 165, 0, 0.3)'},
                    {'range': [70, 100], 'color': 'rgba(255, 0, 60, 0.3)'}],
                'threshold': {
                    'line': {'color': "white", 'width': 4},
                    'thickness': 0.75,
                    'value': total_risk}}))
        
        fig.update_layout(paper_bgcolor = "rgba(0,0,0,0)", font = {'color': "white", 'family': "Outfit"})
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("</div></div>", unsafe_allow_html=True)

    # Risk Classification
    risk_level = "LOW"
    risk_color = "#00FF88"
    if total_risk > 70:
        risk_level = "CRITICAL"
        risk_color = "#FF003C"
    elif total_risk > 40:
        risk_level = "MEDIUM"
        risk_color = "#FFA500"

    st.markdown(f"""
    <div style="margin-top: 1rem; padding: 1.5rem; background: rgba(0,0,0,0.6); border: 2px solid {risk_color}; border-radius: 8px; text-align: center;">
        <h2 style="color: {risk_color}; margin: 0; font-weight: 900; letter-spacing: 2px;">{risk_level} RISK DETECTED</h2>
        <p style="color: white; margin-top: 0.5rem;">Based on the provided parameters, this simulation indicates a <strong>{risk_level}</strong> threat level.</p>
    </div>
    """, unsafe_allow_html=True)
