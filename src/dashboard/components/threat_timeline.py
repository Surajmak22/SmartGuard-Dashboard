import streamlit as st
import plotly.graph_objects as go
from datetime import datetime, timedelta
import pandas as pd

def render_threat_timeline(scan_history):
    """
    Renders an interactive threat timeline visualization.
    
    Args:
        scan_history: List of scan result dictionaries from the backend
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            ⏱️ THREAT DETECTION TIMELINE
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Chronological Threat Intelligence Visualization</p>
    </div>
    """, unsafe_allow_html=True)
    
    if not scan_history or len(scan_history) == 0:
        st.info("No scan history available. Perform scans to see the timeline.")
        return
    
    # Prepare timeline data
    timeline_data = []
    
    for idx, scan in enumerate(scan_history):
        # Use actual timestamp if available, otherwise simulate
        if 'timestamp' in scan:
            timestamp = datetime.fromisoformat(scan['timestamp'])
        else:
            # Simulate timestamps going back in time
            timestamp = datetime.now() - timedelta(hours=len(scan_history) - idx)
        
        timeline_data.append({
            'timestamp': timestamp,
            'filename': scan.get('filename', f'File_{idx+1}'),
            'risk_score': scan.get('risk_score', 0),
            'is_malicious': scan.get('is_malicious', False),
            'hash': scan.get('sha256', 'N/A')[:16] + '...'
        })
    
    # Sort by timestamp
    timeline_data.sort(key=lambda x: x['timestamp'])
    
    # Create timeline visualization
    fig = go.Figure()
    
    # Separate malicious and clean files
    malicious_data = [d for d in timeline_data if d['is_malicious']]
    clean_data = [d for d in timeline_data if not d['is_malicious']]
    
    # Add malicious files trace
    if malicious_data:
        fig.add_trace(go.Scatter(
            x=[d['timestamp'] for d in malicious_data],
            y=[d['risk_score'] for d in malicious_data],
            mode='markers+lines',
            name='Malicious Files',
            marker=dict(
                size=[max(15, d['risk_score'] / 5) for d in malicious_data],
                color=[d['risk_score'] for d in malicious_data],
                colorscale=[
                    [0, '#FFA500'],
                    [0.5, '#FF6B00'],
                    [1, '#FF003C']
                ],
                showscale=True,
                colorbar=dict(
                    title='Risk Score',
                    titlefont=dict(color='#FFFFFF'),
                    tickfont=dict(color='#FFFFFF'),
                    bgcolor='rgba(0, 0, 0, 0.5)',
                    bordercolor='#00F5FF',
                    borderwidth=1
                ),
                line=dict(width=2, color='#FFFFFF'),
                symbol='diamond'
            ),
            line=dict(color='#FF003C', width=2, dash='dash'),
            text=[f"{d['filename']}<br>Risk: {d['risk_score']}<br>Hash: {d['hash']}" for d in malicious_data],
            hovertemplate='<b>%{text}</b><br>Time: %{x}<extra></extra>'
        ))
    
    # Add clean files trace
    if clean_data:
        fig.add_trace(go.Scatter(
            x=[d['timestamp'] for d in clean_data],
            y=[d['risk_score'] for d in clean_data],
            mode='markers+lines',
            name='Clean Files',
            marker=dict(
                size=12,
                color='#00FF88',
                line=dict(width=2, color='#FFFFFF'),
                symbol='circle'
            ),
            line=dict(color='#00FF88', width=2, dash='dot'),
            text=[f"{d['filename']}<br>Risk: {d['risk_score']}<br>Hash: {d['hash']}" for d in clean_data],
            hovertemplate='<b>%{text}</b><br>Time: %{x}<extra></extra>'
        ))
    
    # Add risk threshold lines
    fig.add_hline(
        y=70, 
        line_dash="dash", 
        line_color="#FF6B00", 
        annotation_text="High Risk Threshold",
        annotation_position="right",
        annotation_font=dict(color='#FF6B00', size=12)
    )
    
    fig.add_hline(
        y=40, 
        line_dash="dash", 
        line_color="#FFA500", 
        annotation_text="Medium Risk Threshold",
        annotation_position="right",
        annotation_font=dict(color='#FFA500', size=12)
    )
    
    # Update layout
    fig.update_layout(
        title={
            'text': 'Threat Detection Timeline - Risk Score Evolution',
            'font': {'size': 20, 'color': '#FFFFFF', 'family': 'Outfit'}
        },
        xaxis_title='Time',
        yaxis_title='Risk Score',
        plot_bgcolor='rgba(10, 14, 20, 0.8)',
        paper_bgcolor='rgba(10, 14, 20, 0.8)',
        font=dict(color='#FFFFFF', size=14, family='Outfit'),
        xaxis=dict(
            gridcolor='rgba(0, 245, 255, 0.1)',
            showgrid=True,
            color='#FFFFFF',
            tickformat='%H:%M\n%d/%m'
        ),
        yaxis=dict(
            gridcolor='rgba(0, 245, 255, 0.1)',
            showgrid=True,
            color='#FFFFFF',
            range=[0, 105]
        ),
        hovermode='closest',
        legend=dict(
            bgcolor='rgba(0, 0, 0, 0.5)',
            bordercolor='#00F5FF',
            borderwidth=1,
            font=dict(color='#FFFFFF', size=12)
        ),
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Timeline statistics
    st.markdown("<br>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">FIRST SCAN</div>
            <div class="metric-value" style="color: #00F5FF; font-size: 1.2rem;">
                {timeline_data[0]['timestamp'].strftime('%d/%m/%Y %H:%M')}
            </div>
            <div class="metric-subtitle">{timeline_data[0]['filename']}</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">LATEST SCAN</div>
            <div class="metric-value" style="color: #00F5FF; font-size: 1.2rem;">
                {timeline_data[-1]['timestamp'].strftime('%d/%m/%Y %H:%M')}
            </div>
            <div class="metric-subtitle">{timeline_data[-1]['filename']}</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        time_span = timeline_data[-1]['timestamp'] - timeline_data[0]['timestamp']
        hours = time_span.total_seconds() / 3600
        st.markdown(f"""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">TIME SPAN</div>
            <div class="metric-value" style="color: #00F5FF; font-size: 1.2rem;">
                {hours:.1f}h
            </div>
            <div class="metric-subtitle">Analysis Period</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Recent threats table
    if malicious_data:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <h3 style="color: #FF003C; font-weight: 800; text-align: center; margin-bottom: 1rem;">
            🚨 RECENT THREAT DETECTIONS
        </h3>
        """, unsafe_allow_html=True)
        
        # Show last 5 malicious files
        recent_threats = malicious_data[-5:]
        
        for threat in reversed(recent_threats):
            st.markdown(f"""
            <div style="padding: 1rem; border-left: 4px solid #FF003C; margin-bottom: 0.8rem; background: rgba(255, 0, 60, 0.1); border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong style="color: #FFFFFF; font-size: 1.1rem;">{threat['filename']}</strong><br>
                        <span style="color: #FFFFFF; font-size: 0.9rem;">🕒 {threat['timestamp'].strftime('%d/%m/%Y %H:%M:%S')}</span>
                    </div>
                    <div style="text-align: right;">
                        <div style="color: #FF003C; font-size: 1.8rem; font-weight: 900;">{threat['risk_score']}</div>
                        <div style="color: #FFFFFF; font-size: 0.8rem; font-weight: 700;">RISK SCORE</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
