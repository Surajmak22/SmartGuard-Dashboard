import streamlit as st
import requests
import plotly.graph_objects as go

def render_file_comparator(api_url="http://localhost:8000"):
    """
    Renders a side-by-side file comparison interface.
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            🔄 FILE COMPARISON MODE
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Side-by-Side Threat Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div style="text-align: center; padding: 1rem; background: rgba(0, 245, 255, 0.1); border-radius: 8px; margin-bottom: 1rem;">
            <h3 style="color: #00F5FF; font-weight: 800; margin: 0;">📄 FILE A</h3>
        </div>
        """, unsafe_allow_html=True)
        file_a = st.file_uploader("Upload First File", key="file_a", type=["pdf", "exe", "jpg", "png", "doc", "docx", "mp4", "zip"])
    
    with col2:
        st.markdown("""
        <div style="text-align: center; padding: 1rem; background: rgba(255, 0, 60, 0.1); border-radius: 8px; margin-bottom: 1rem;">
            <h3 style="color: #FF003C; font-weight: 800; margin: 0;">📄 FILE B</h3>
        </div>
        """, unsafe_allow_html=True)
        file_b = st.file_uploader("Upload Second File", key="file_b", type=["pdf", "exe", "jpg", "png", "doc", "docx", "mp4", "zip"])
    
    if file_a and file_b:
        if st.button("🔬 COMPARE FILES", use_container_width=True):
            with st.spinner("Analyzing both files..."):
                try:
                    # Scan both files
                    files_a = {"file": (file_a.name, file_a.getvalue(), file_a.type)}
                    files_b = {"file": (file_b.name, file_b.getvalue(), file_b.type)}
                    
                    response_a = requests.post(f"{api_url}/malware/scan", files=files_a, data={"filename": file_a.name}, timeout=30)
                    response_b = requests.post(f"{api_url}/malware/scan", files=files_b, data={"filename": file_b.name}, timeout=30)
                    
                    if response_a.status_code == 200 and response_b.status_code == 200:
                        result_a = response_a.json()
                        result_b = response_b.json()
                        
                        st.markdown("<br>", unsafe_allow_html=True)
                        
                        # Comparison Summary
                        st.markdown("""
                        <h3 style="color: #00F5FF; font-weight: 800; text-align: center; margin-bottom: 1.5rem;">
                            📊 COMPARISON SUMMARY
                        </h3>
                        """, unsafe_allow_html=True)
                        
                        col1, col2, col3 = st.columns(3)
                        
                        risk_diff = abs(result_a.get('risk_score', 0) - result_b.get('risk_score', 0))
                        
                        with col1:
                            st.markdown(f"""
                            <div class="glass-card" style="text-align: center;">
                                <div class="metric-label">RISK DIFFERENCE</div>
                                <div class="metric-value" style="color: {'#FF003C' if risk_diff > 30 else '#FFA500' if risk_diff > 10 else '#00FF88'};">{risk_diff:.1f}</div>
                                <div class="metric-subtitle">Score Delta</div>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        with col2:
                            similarity = 100 - risk_diff
                            st.markdown(f"""
                            <div class="glass-card" style="text-align: center;">
                                <div class="metric-label">SIMILARITY</div>
                                <div class="metric-value" style="color: #00F5FF;">{similarity:.1f}%</div>
                                <div class="metric-subtitle">Pattern Match</div>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        with col3:
                            both_malicious = result_a.get('is_malicious', False) and result_b.get('is_malicious', False)
                            verdict = "BOTH THREATS" if both_malicious else "DIFFERENT"
                            verdict_color = "#FF003C" if both_malicious else "#00F5FF"
                            st.markdown(f"""
                            <div class="glass-card" style="text-align: center;">
                                <div class="metric-label">VERDICT</div>
                                <div class="metric-value" style="color: {verdict_color}; font-size: 1.3rem;">{verdict}</div>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        # Side-by-side comparison
                        st.markdown("<br>", unsafe_allow_html=True)
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown(f"""
                            <div style="padding: 1.5rem; background: rgba(0, 245, 255, 0.1); border: 2px solid #00F5FF; border-radius: 8px;">
                                <h4 style="color: #00F5FF; font-weight: 800; text-align: center; margin-bottom: 1rem;">FILE A: {file_a.name}</h4>
                                <p style="color: #FFFFFF; font-weight: 700;"><strong style="color: #00F5FF;">Risk Score:</strong> {result_a.get('risk_score', 0)}</p>
                                <p style="color: #FFFFFF; font-weight: 700;"><strong style="color: #00F5FF;">Status:</strong> {'🚨 MALICIOUS' if result_a.get('is_malicious', False) else '✅ CLEAN'}</p>
                                <p style="color: #FFFFFF; font-weight: 700;"><strong style="color: #00F5FF;">SHA256:</strong> {result_a.get('sha256', 'N/A')[:16]}...</p>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            if result_a.get('threats'):
                                st.markdown("**🔍 Threats Detected:**")
                                for threat in result_a['threats'][:5]:
                                    st.markdown(f"- {threat}")
                        
                        with col2:
                            st.markdown(f"""
                            <div style="padding: 1.5rem; background: rgba(255, 0, 60, 0.1); border: 2px solid #FF003C; border-radius: 8px;">
                                <h4 style="color: #FF003C; font-weight: 800; text-align: center; margin-bottom: 1rem;">FILE B: {file_b.name}</h4>
                                <p style="color: #FFFFFF; font-weight: 700;"><strong style="color: #FF003C;">Risk Score:</strong> {result_b.get('risk_score', 0)}</p>
                                <p style="color: #FFFFFF; font-weight: 700;"><strong style="color: #FF003C;">Status:</strong> {'🚨 MALICIOUS' if result_b.get('is_malicious', False) else '✅ CLEAN'}</p>
                                <p style="color: #FFFFFF; font-weight: 700;"><strong style="color: #FF003C;">SHA256:</strong> {result_b.get('sha256', 'N/A')[:16]}...</p>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            if result_b.get('threats'):
                                st.markdown("**🔍 Threats Detected:**")
                                for threat in result_b['threats'][:5]:
                                    st.markdown(f"- {threat}")
                        
                        # Visual comparison chart
                        st.markdown("<br>", unsafe_allow_html=True)
                        st.markdown("""
                        <h3 style="color: #00F5FF; font-weight: 800; text-align: center; margin-bottom: 1rem;">
                            📈 LAYER-BY-LAYER COMPARISON
                        </h3>
                        """, unsafe_allow_html=True)
                        
                        layers_a = result_a.get('layer_results', {})
                        layers_b = result_b.get('layer_results', {})
                        
                        layer_names = list(set(list(layers_a.keys()) + list(layers_b.keys())))
                        
                        fig = go.Figure()
                        
                        fig.add_trace(go.Bar(
                            name=f'File A ({file_a.name})',
                            x=layer_names,
                            y=[layers_a.get(layer, {}).get('score', 0) for layer in layer_names],
                            marker_color='#00F5FF',
                            text=[layers_a.get(layer, {}).get('score', 0) for layer in layer_names],
                            textposition='outside'
                        ))
                        
                        fig.add_trace(go.Bar(
                            name=f'File B ({file_b.name})',
                            x=layer_names,
                            y=[layers_b.get(layer, {}).get('score', 0) for layer in layer_names],
                            marker_color='#FF003C',
                            text=[layers_b.get(layer, {}).get('score', 0) for layer in layer_names],
                            textposition='outside'
                        ))
                        
                        fig.update_layout(
                            barmode='group',
                            plot_bgcolor='rgba(10, 14, 20, 0.8)',
                            paper_bgcolor='rgba(10, 14, 20, 0.8)',
                            font=dict(color='#FFFFFF', size=14, family='Outfit'),
                            xaxis=dict(title='Detection Layer', color='#FFFFFF'),
                            yaxis=dict(title='Risk Score', color='#FFFFFF', gridcolor='rgba(0, 245, 255, 0.1)'),
                            legend=dict(
                                bgcolor='rgba(0, 0, 0, 0.5)',
                                bordercolor='#00F5FF',
                                borderwidth=1,
                                font=dict(color='#FFFFFF')
                            ),
                            height=400
                        )
                        
                        st.plotly_chart(fig, use_container_width=True)
                        
                    else:
                        st.error("Failed to scan one or both files. Please try again.")
                        
                except Exception as e:
                    st.error(f"Comparison failed: {str(e)}")
