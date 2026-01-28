import streamlit as st
import plotly.graph_objects as go
import random

def render_performance_metrics():
    """
    Renders the System Performance Metrics Dashboard.
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            ⚡ PERFORMANCE METRICS
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Engine Health & Resource Utilization</p>
    </div>
    """, unsafe_allow_html=True)

    # Simulated Metrics
    cpu_usage = random.randint(15, 45)
    memory_usage = random.randint(30, 60)
    disk_io = random.randint(5, 20)
    queue_depth = random.randint(0, 5)

    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; border: 1px solid #00F5FF; border-radius: 8px; background: rgba(0,0,0,0.5);">
            <h3 style="color: #00F5FF; margin: 0;">CPU Load</h3>
            <p style="color: white; font-size: 2rem; font-weight: 800; margin: 0;">{cpu_usage}%</p>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; border: 1px solid #00F5FF; border-radius: 8px; background: rgba(0,0,0,0.5);">
            <h3 style="color: #00F5FF; margin: 0;">Memory</h3>
            <p style="color: white; font-size: 2rem; font-weight: 800; margin: 0;">{memory_usage}%</p>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; border: 1px solid #00F5FF; border-radius: 8px; background: rgba(0,0,0,0.5);">
            <h3 style="color: #00F5FF; margin: 0;">Disk I/O</h3>
            <p style="color: white; font-size: 2rem; font-weight: 800; margin: 0;">{disk_io} MB/s</p>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; border: 1px solid #00F5FF; border-radius: 8px; background: rgba(0,0,0,0.5);">
            <h3 style="color: #00F5FF; margin: 0;">Queue</h3>
            <p style="color: white; font-size: 2rem; font-weight: 800; margin: 0;">{queue_depth} Jobs</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Charts
    colA, colB = st.columns(2)
    
    with colA:
        st.markdown("<h4 style='color: white; text-align: center;'>Engine Latency (ms) - Last Hour</h4>", unsafe_allow_html=True)
        # Generate dummy time series data
        x_data = list(range(60))
        y_data = [random.randint(100, 300) for _ in range(60)]
        fig_lat = go.Figure(data=go.Scatter(x=x_data, y=y_data, mode='lines', fill='tozeroy', line_color='#00F5FF'))
        fig_lat.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", 
                              font={'color': "white"}, margin=dict(l=20, r=20, t=20, b=20), height=300)
        st.plotly_chart(fig_lat, use_container_width=True)

    with colB:
        st.markdown("<h4 style='color: white; text-align: center;'>Scan Throughput (Files/min)</h4>", unsafe_allow_html=True)
        y_thru = [random.randint(5, 20) for _ in range(60)]
        fig_thru = go.Figure(data=go.Bar(x=x_data, y=y_thru, marker_color='#00FF88'))
        fig_thru.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", 
                               font={'color': "white"}, margin=dict(l=20, r=20, t=20, b=20), height=300)
        st.plotly_chart(fig_thru, use_container_width=True)
