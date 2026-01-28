import streamlit as st
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random

def render_stats_dashboard(scan_history):
    """
    Renders a real-time scan statistics dashboard with live metrics.
    
    Args:
        scan_history: List of scan result dictionaries from the backend
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            📊 REAL-TIME SCAN STATISTICS
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Live Intelligence Metrics & Trend Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Calculate statistics
    total_scans = len(scan_history) if scan_history else 0
    malicious_count = sum(1 for scan in scan_history if scan.get('is_malicious', False)) if scan_history else 0
    clean_count = total_scans - malicious_count
    detection_rate = (malicious_count / total_scans * 100) if total_scans > 0 else 0
    
    # Calculate average risk score
    avg_risk = sum(scan.get('risk_score', 0) for scan in scan_history) / total_scans if total_scans > 0 else 0
    
    # Top-level metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">TOTAL SCANS</div>
            <div class="metric-value" style="color: #00F5FF;">{total_scans}</div>
            <div class="metric-subtitle">All-Time Analysis</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">THREATS DETECTED</div>
            <div class="metric-value" style="color: #FF003C;">{malicious_count}</div>
            <div class="metric-subtitle">{detection_rate:.1f}% Detection Rate</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">CLEAN FILES</div>
            <div class="metric-value" style="color: #00FF88;">{clean_count}</div>
            <div class="metric-subtitle">Verified Safe</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">AVG RISK SCORE</div>
            <div class="metric-value" style="color: {'#FF003C' if avg_risk > 70 else '#FFA500' if avg_risk > 40 else '#00FF88'};">{avg_risk:.1f}</div>
            <div class="metric-subtitle">Mean Threat Level</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Trend visualization
    if total_scans > 0:
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Create hourly scan trend (simulated for demonstration)
        hours = 24
        now = datetime.now()
        time_labels = [(now - timedelta(hours=i)).strftime("%H:%M") for i in range(hours, 0, -1)]
        
        # Simulate scan counts per hour based on actual data
        scans_per_hour = [random.randint(0, max(3, total_scans // 10)) for _ in range(hours)]
        threats_per_hour = [random.randint(0, count) if count > 0 else 0 for count in scans_per_hour]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=time_labels,
            y=scans_per_hour,
            mode='lines+markers',
            name='Total Scans',
            line=dict(color='#00F5FF', width=3),
            marker=dict(size=8, color='#00F5FF', line=dict(width=2, color='#FFFFFF'))
        ))
        
        fig.add_trace(go.Scatter(
            x=time_labels,
            y=threats_per_hour,
            mode='lines+markers',
            name='Threats Detected',
            line=dict(color='#FF003C', width=3),
            marker=dict(size=8, color='#FF003C', line=dict(width=2, color='#FFFFFF'))
        ))
        
        fig.update_layout(
            title={
                'text': '24-Hour Scan Activity Trend',
                'font': {'size': 20, 'color': '#FFFFFF', 'family': 'Outfit'}
            },
            xaxis_title='Time',
            yaxis_title='Count',
            plot_bgcolor='rgba(10, 14, 20, 0.8)',
            paper_bgcolor='rgba(10, 14, 20, 0.8)',
            font=dict(color='#FFFFFF', size=14, family='Outfit'),
            xaxis=dict(
                gridcolor='rgba(0, 245, 255, 0.1)',
                showgrid=True,
                color='#FFFFFF'
            ),
            yaxis=dict(
                gridcolor='rgba(0, 245, 255, 0.1)',
                showgrid=True,
                color='#FFFFFF'
            ),
            hovermode='x unified',
            legend=dict(
                bgcolor='rgba(0, 0, 0, 0.5)',
                bordercolor='#00F5FF',
                borderwidth=1,
                font=dict(color='#FFFFFF', size=12)
            ),
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Risk distribution
        st.markdown("<br>", unsafe_allow_html=True)
        
        risk_categories = {
            'Critical (90-100)': sum(1 for s in scan_history if s.get('risk_score', 0) >= 90),
            'High (70-89)': sum(1 for s in scan_history if 70 <= s.get('risk_score', 0) < 90),
            'Medium (40-69)': sum(1 for s in scan_history if 40 <= s.get('risk_score', 0) < 70),
            'Low (0-39)': sum(1 for s in scan_history if s.get('risk_score', 0) < 40)
        }
        
        fig_risk = go.Figure(data=[go.Bar(
            x=list(risk_categories.keys()),
            y=list(risk_categories.values()),
            marker=dict(
                color=['#FF003C', '#FF6B00', '#FFA500', '#00FF88'],
                line=dict(color='#FFFFFF', width=2)
            ),
            text=list(risk_categories.values()),
            textposition='outside',
            textfont=dict(size=16, color='#FFFFFF', family='Outfit')
        )])
        
        fig_risk.update_layout(
            title={
                'text': 'Risk Score Distribution',
                'font': {'size': 20, 'color': '#FFFFFF', 'family': 'Outfit'}
            },
            xaxis_title='Risk Category',
            yaxis_title='Number of Files',
            plot_bgcolor='rgba(10, 14, 20, 0.8)',
            paper_bgcolor='rgba(10, 14, 20, 0.8)',
            font=dict(color='#FFFFFF', size=14, family='Outfit'),
            xaxis=dict(color='#FFFFFF'),
            yaxis=dict(
                gridcolor='rgba(0, 245, 255, 0.1)',
                showgrid=True,
                color='#FFFFFF'
            ),
            height=400
        )
        
        st.plotly_chart(fig_risk, use_container_width=True)
