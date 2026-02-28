import streamlit as st
import requests
import pandas as pd

def render_threat_hunter(api_url="http://localhost:80", user_id=None):
    """
    Renders an advanced threat hunting interface for searching historical scans.
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            🎯 THREAT HUNTER
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Advanced IOC Search & Pattern Matching</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Search options
    search_type = st.selectbox(
        "🔍 Search Type",
        ["SHA256 Hash", "Filename Pattern", "Risk Score Range", "Threat Keyword"]
    )
    
    search_query = ""
    min_risk = 0
    max_risk = 100
    
    if search_type == "SHA256 Hash":
        search_query = st.text_input("Enter SHA256 Hash (full or partial)", placeholder="e.g., a1b2c3d4...")
    elif search_type == "Filename Pattern":
        search_query = st.text_input("Enter Filename Pattern", placeholder="e.g., *.exe, malware*, etc.")
    elif search_type == "Risk Score Range":
        col1, col2 = st.columns(2)
        with col1:
            min_risk = st.number_input("Minimum Risk Score", min_value=0, max_value=100, value=70)
        with col2:
            max_risk = st.number_input("Maximum Risk Score", min_value=0, max_value=100, value=100)
    elif search_type == "Threat Keyword":
        search_query = st.text_input("Enter Threat Keyword", placeholder="e.g., trojan, ransomware, etc.")
    
        try:
            response = requests.get(f"{api_url}/malware/history", params={"x_user_id": user_id})
            
            if response.status_code == 200:
                history = response.json()
                
                if not history:
                    st.info("No scan history available. Perform scans to build the threat database.")
                    return
                
                # Filter based on search type
                results = []
                
                if search_type == "SHA256 Hash":
                    results = [h for h in history if search_query.lower() in h.get('sha256', '').lower()]
                
                elif search_type == "Filename Pattern":
                    import fnmatch
                    results = [h for h in history if fnmatch.fnmatch(h.get('filename', '').lower(), search_query.lower())]
                
                elif search_type == "Risk Score Range":
                    results = [h for h in history if min_risk <= h.get('risk_score', 0) <= max_risk]
                
                elif search_type == "Threat Keyword":
                    results = [
                        h for h in history 
                        if any(search_query.lower() in str(threat).lower() for threat in h.get('threats', []))
                    ]
                
                # Display results
                st.markdown("<br>", unsafe_allow_html=True)
                
                if results:
                    st.markdown(f"""
                    <div style="text-align: center; padding: 1rem; background: rgba(0, 255, 136, 0.1); border: 1px solid #00FF88; border-radius: 8px; margin-bottom: 2rem;">
                        <h3 style="color: #00FF88; font-weight: 800; margin: 0;">✅ FOUND {len(results)} MATCHING THREATS</h3>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Summary metrics
                    malicious_count = sum(1 for r in results if r.get('is_malicious', False))
                    avg_risk = sum(r.get('risk_score', 0) for r in results) / len(results)
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.markdown(f"""
                        <div class="glass-card" style="text-align: center;">
                            <div class="metric-label">TOTAL MATCHES</div>
                            <div class="metric-value" style="color: #00F5FF;">{len(results)}</div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col2:
                        st.markdown(f"""
                        <div class="glass-card" style="text-align: center;">
                            <div class="metric-label">MALICIOUS</div>
                            <div class="metric-value" style="color: #FF003C;">{malicious_count}</div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col3:
                        st.markdown(f"""
                        <div class="glass-card" style="text-align: center;">
                            <div class="metric-label">AVG RISK</div>
                            <div class="metric-value" style="color: {'#FF003C' if avg_risk > 70 else '#FFA500' if avg_risk > 40 else '#00FF88'};">{avg_risk:.1f}</div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # Detailed results
                    st.markdown("<br>", unsafe_allow_html=True)
                    st.markdown("""
                    <h3 style="color: #00F5FF; font-weight: 800; margin-bottom: 1rem;">
                        📋 DETAILED RESULTS
                    </h3>
                    """, unsafe_allow_html=True)
                    
                    for idx, result in enumerate(results, 1):
                        is_malicious = result.get('is_malicious', False)
                        risk_score = result.get('risk_score', 0)
                        border_color = '#FF003C' if is_malicious else '#00FF88'
                        status_icon = '🚨' if is_malicious else '✅'
                        
                        with st.expander(f"{status_icon} {idx}. {result.get('filename', 'Unknown')} - Risk: {risk_score}", expanded=False):
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown(f"""
                                <div style="color: #FFFFFF; font-weight: 700;">
                                    <p><strong style="color: #00F5FF;">SHA256:</strong> {result.get('sha256', 'N/A')[:32]}...</p>
                                    <p><strong style="color: #00F5FF;">Risk Score:</strong> {risk_score}</p>
                                    <p><strong style="color: #00F5FF;">Status:</strong> {'MALICIOUS' if is_malicious else 'CLEAN'}</p>
                                </div>
                                """, unsafe_allow_html=True)
                            
                            with col2:
                                st.markdown(f"""
                                <div style="color: #FFFFFF; font-weight: 700;">
                                    <p><strong style="color: #00F5FF;">Timestamp:</strong> {result.get('timestamp', 'N/A')}</p>
                                    <p><strong style="color: #00F5FF;">File Size:</strong> {result.get('metadata', {}).get('size', 'N/A')} bytes</p>
                                    <p><strong style="color: #00F5FF;">Type:</strong> {result.get('metadata', {}).get('type', 'Unknown')}</p>
                                </div>
                                """, unsafe_allow_html=True)
                            
                            if result.get('threats'):
                                st.markdown("**🔍 Threat Indicators:**")
                                for threat in result['threats'][:10]:
                                    st.markdown(f"- {threat}")
                    
                    # Export results
                    st.markdown("<br>", unsafe_allow_html=True)
                    df = pd.DataFrame(results)
                    csv = df.to_csv(index=False)
                    st.download_button(
                        label="📥 Export Results as CSV",
                        data=csv,
                        file_name=f"threat_hunt_{search_type.lower().replace(' ', '_')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                    
                else:
                    st.markdown(f"""
                    <div style="text-align: center; padding: 2rem; background: rgba(255, 165, 0, 0.1); border: 1px solid #FFA500; border-radius: 8px;">
                        <h3 style="color: #FFA500; font-weight: 800; margin: 0;">⚠️ NO MATCHES FOUND</h3>
                        <p style="color: #FFFFFF; font-weight: 700; margin-top: 1rem;">Try adjusting your search criteria</p>
                    </div>
                    """, unsafe_allow_html=True)
            
            else:
                st.error("Failed to retrieve scan history.")
                
        except Exception as e:
            st.error(f"Threat hunt failed: {str(e)}")
