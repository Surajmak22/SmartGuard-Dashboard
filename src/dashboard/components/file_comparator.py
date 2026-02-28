import streamlit as st
import requests
import plotly.graph_objects as go

def render_file_comparator(api_url="http://localhost:80", user_id=None):
    """
    Renders a side-by-side file comparison interface with Pattern Highlighting (#17).
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            🔄 ELITE COMPARISON ENGINE
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Structural & Neural Contrast Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div style="text-align: center; padding: 1rem; background: rgba(0, 245, 255, 0.1); border-radius: 8px; margin-bottom: 1rem;">
            <h3 style="color: #00F5FF; font-weight: 800; margin: 0;">📄 SPECIMEN A</h3>
        </div>
        """, unsafe_allow_html=True)
        file_a = st.file_uploader("Upload First File", key="file_a", type=["pdf", "exe", "jpg", "png", "doc", "docx", "mp4", "zip"])
    
    with col2:
        st.markdown("""
        <div style="text-align: center; padding: 1rem; background: rgba(255, 0, 60, 0.1); border-radius: 8px; margin-bottom: 1rem;">
            <h3 style="color: #FF003C; font-weight: 800; margin: 0;">📄 SPECIMEN B</h3>
        </div>
        """, unsafe_allow_html=True)
        file_b = st.file_uploader("Upload Second File", key="file_b", type=["pdf", "exe", "jpg", "png", "doc", "docx", "mp4", "zip"])
    
    if file_a and file_b:
        if st.button("🔬 EXECUTE NEURAL COMPARISON", use_container_width=True):
            with st.spinner("Analyzing neural structures..."):
                try:
                    # Scan both files with session isolation
                    data_a = {"filename": file_a.name, "x_user_id": user_id}
                    data_b = {"filename": file_b.name, "x_user_id": user_id}
                    
                    files_a = {"file": (file_a.name, file_a.getvalue(), file_a.type)}
                    files_b = {"file": (file_b.name, file_b.getvalue(), file_b.type)}
                    
                    response_a = requests.post(f"{api_url}/malware/scan", files=files_a, data=data_a, timeout=30)
                    response_b = requests.post(f"{api_url}/malware/scan", files=files_b, data=data_b, timeout=30)
                    
                    if response_a.status_code == 200 and response_b.status_code == 200:
                        result_a = response_a.json()
                        result_b = response_b.json()
                        
                        # --- Elite Feature #17: Threat Indicator Highlighting ---
                        st.markdown("<br>", unsafe_allow_html=True)
                        st.markdown("""
                        <h3 style="color: #00F5FF; font-weight: 800; text-align: center; margin-bottom: 1.5rem;">
                            🔎 PATTERN CONTRAST HIGHLIGHTING
                        </h3>
                        """, unsafe_allow_html=True)

                        threats_a = set(result_a.get('all_threats', []))
                        threats_b = set(result_b.get('all_threats', []))
                        
                        unique_a = threats_a - threats_b
                        unique_b = threats_b - threats_a
                        common = threats_a & threats_b

                        c1, c2 = st.columns(2)
                        with c1:
                            if unique_a:
                                st.markdown(f"**⚡ Unique to {file_a.name}:**")
                                for t in unique_a: st.error(f"⚠️ {t}")
                        with c2:
                            if unique_b:
                                st.markdown(f"**⚡ Unique to {file_b.name}:**")
                                for t in unique_b: st.error(f"⚠️ {t}")

                        if common:
                            st.info(f"**🤝 Shared Malicious Patterns:** {', '.join(list(common)[:3])}...")

                        # Comparison Summary
                        col1, col2, col3 = st.columns(3)
                        
                        risk_a = result_a.get('risk_score', 0)
                        risk_b = result_b.get('risk_score', 0)
                        risk_diff = abs(risk_a - risk_b)
                        
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
                                <div class="metric-label">NEURAL SIMILARITY</div>
                                <div class="metric-value" style="color: #00F5FF;">{similarity:.1f}%</div>
                                <div class="metric-subtitle">Structure Overlay</div>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        with col3:
                            both_malicious = result_a.get('is_malicious', False) and result_b.get('is_malicious', False)
                            verdict = "HIGH CONGRUENCE" if both_malicious and similarity > 80 else "DISTINCT SAMPLES"
                            verdict_color = "#FF003C" if both_malicious else "#00F5FF"
                            st.markdown(f"""
                            <div class="glass-card" style="text-align: center;">
                                <div class="metric-label">VERDICT</div>
                                <div class="metric-value" style="color: {verdict_color}; font-size: 1.1rem;">{verdict}</div>
                            </div>
                            """, unsafe_allow_html=True)

                        # Side-by-side details
                        st.markdown("<br>", unsafe_allow_html=True)
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            status_a = "🚨 MALICIOUS" if result_a.get('is_malicious', False) else "✅ CLEAN"
                            st.markdown(f"""
                            <div style="padding: 1.5rem; background: rgba(0, 245, 255, 0.05); border: 2px solid #00F5FF; border-radius: 8px;">
                                <h4 style="color: #00F5FF; font-weight: 800; text-align: center; margin-bottom: 1rem;">{file_a.name}</h4>
                                <p style="color: #FFFFFF; font-weight: 700;"><strong style="color: #00F5FF;">Risk:</strong> {risk_a}</p>
                                <p style="color: #FFFFFF; font-weight: 700;"><strong style="color: #00F5FF;">Status:</strong> {status_a}</p>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        with col2:
                            status_b = "🚨 MALICIOUS" if result_b.get('is_malicious', False) else "✅ CLEAN"
                            st.markdown(f"""
                            <div style="padding: 1.5rem; background: rgba(255, 0, 60, 0.05); border: 2px solid #FF003C; border-radius: 8px;">
                                <h4 style="color: #FF003C; font-weight: 800; text-align: center; margin-bottom: 1rem;">{file_b.name}</h4>
                                <p style="color: #FFFFFF; font-weight: 700;"><strong style="color: #FF003C;">Risk:</strong> {risk_b}</p>
                                <p style="color: #FFFFFF; font-weight: 700;"><strong style="color: #FF003C;">Status:</strong> {status_b}</p>
                            </div>
                            """, unsafe_allow_html=True)

                    else:
                        st.error("Engine Timeout or Offline. Please try again.")
                        
                except Exception as e:
                    st.error(f"Neural Scan failed: {str(e)}")
