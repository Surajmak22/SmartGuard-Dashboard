import streamlit as st
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def scan_file_batch(file, api_url):
    """Helper function to scan a single file."""
    try:
        files = {"file": (file.name, file.getvalue(), file.type)}
        response = requests.post(f"{api_url}/malware/scan", files=files, data={"filename": file.name}, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            result['filename'] = file.name
            result['status'] = 'success'
            return result
        else:
            return {
                'filename': file.name,
                'status': 'error',
                'error': f"HTTP {response.status_code}"
            }
    except Exception as e:
        return {
            'filename': file.name,
            'status': 'error',
            'error': str(e)
        }

def render_batch_scanner(api_url="http://localhost:8000"):
    """
    Renders a batch file scanning interface with progress tracking.
    
    Args:
        api_url: Backend API endpoint
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            🚀 BATCH FILE SCANNER
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Multi-File Parallel Analysis Engine</p>
    </div>
    """, unsafe_allow_html=True)
    
    # File uploader for multiple files
    uploaded_files = st.file_uploader(
        "Upload Multiple Files for Batch Analysis",
        accept_multiple_files=True,
        help="Select multiple files to scan simultaneously"
    )
    
    if uploaded_files:
        st.markdown(f"""
        <div class="glass-card" style="text-align: center;">
            <div class="metric-label">FILES QUEUED</div>
            <div class="metric-value" style="color: #00F5FF;">{len(uploaded_files)}</div>
            <div class="metric-subtitle">Ready for Parallel Scanning</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Display file list
        with st.expander("📋 View Queued Files", expanded=False):
            for idx, file in enumerate(uploaded_files, 1):
                file_size_kb = len(file.getvalue()) / 1024
                st.markdown(f"""
                <div style="padding: 0.5rem; border-left: 3px solid #00F5FF; margin-bottom: 0.5rem; background: rgba(0, 245, 255, 0.05);">
                    <strong style="color: #00F5FF;">{idx}.</strong> 
                    <strong style="color: #FFFFFF;">{file.name}</strong> 
                    <span style="color: #FFFFFF;">({file_size_kb:.2f} KB)</span>
                </div>
                """, unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Scan button
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🔥 START BATCH SCAN", use_container_width=True):
                st.session_state['batch_scanning'] = True
        
        # Execute batch scan
        if st.session_state.get('batch_scanning', False):
            st.markdown("""
            <div style="text-align: center; padding: 1rem; background: rgba(0, 245, 255, 0.1); border: 1px solid #00F5FF; border-radius: 8px; margin-bottom: 1rem;">
                <h3 style="color: #00F5FF; font-weight: 800; margin: 0;">⚡ PARALLEL SCAN IN PROGRESS</h3>
            </div>
            """, unsafe_allow_html=True)
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            results = []
            total_files = len(uploaded_files)
            completed = 0
            
            # Parallel scanning with ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_file = {
                    executor.submit(scan_file_batch, file, api_url): file 
                    for file in uploaded_files
                }
                
                for future in as_completed(future_to_file):
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    # Update progress
                    progress = completed / total_files
                    progress_bar.progress(progress)
                    status_text.markdown(f"""
                    <p style="text-align: center; color: #FFFFFF; font-weight: 700; font-size: 1.1rem;">
                        Scanning: {completed}/{total_files} files completed
                    </p>
                    """, unsafe_allow_html=True)
            
            # Clear progress indicators
            progress_bar.empty()
            status_text.empty()
            
            # Display results summary
            st.markdown("""
            <div style="text-align: center; padding: 1rem; background: rgba(0, 255, 136, 0.1); border: 1px solid #00FF88; border-radius: 8px; margin-bottom: 2rem;">
                <h3 style="color: #00FF88; font-weight: 800; margin: 0;">✅ BATCH SCAN COMPLETE</h3>
            </div>
            """, unsafe_allow_html=True)
            
            # Summary metrics
            successful_scans = sum(1 for r in results if r.get('status') == 'success')
            failed_scans = total_files - successful_scans
            malicious_files = sum(1 for r in results if r.get('status') == 'success' and r.get('is_malicious', False))
            clean_files = successful_scans - malicious_files
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.markdown(f"""
                <div class="glass-card" style="text-align: center;">
                    <div class="metric-label">TOTAL SCANNED</div>
                    <div class="metric-value" style="color: #00F5FF;">{successful_scans}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown(f"""
                <div class="glass-card" style="text-align: center;">
                    <div class="metric-label">THREATS</div>
                    <div class="metric-value" style="color: #FF003C;">{malicious_files}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col3:
                st.markdown(f"""
                <div class="glass-card" style="text-align: center;">
                    <div class="metric-label">CLEAN</div>
                    <div class="metric-value" style="color: #00FF88;">{clean_files}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col4:
                st.markdown(f"""
                <div class="glass-card" style="text-align: center;">
                    <div class="metric-label">FAILED</div>
                    <div class="metric-value" style="color: #FFA500;">{failed_scans}</div>
                </div>
                """, unsafe_allow_html=True)
            
            # Detailed results table
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("""
            <h3 style="color: #00F5FF; font-weight: 800; text-align: center; margin-bottom: 1rem;">
                📊 DETAILED SCAN RESULTS
            </h3>
            """, unsafe_allow_html=True)
            
            for idx, result in enumerate(results, 1):
                if result.get('status') == 'success':
                    is_malicious = result.get('is_malicious', False)
                    risk_score = result.get('risk_score', 0)
                    
                    border_color = '#FF003C' if is_malicious else '#00FF88'
                    status_text = '🚨 MALICIOUS' if is_malicious else '✅ CLEAN'
                    status_color = '#FF003C' if is_malicious else '#00FF88'
                    
                    with st.expander(f"{idx}. {result['filename']} - {status_text}", expanded=False):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown(f"""
                            <div class="glass-card">
                                <div class="metric-label">RISK SCORE</div>
                                <div class="metric-value" style="color: {status_color};">{risk_score}</div>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        with col2:
                            st.markdown(f"""
                            <div class="glass-card">
                                <div class="metric-label">STATUS</div>
                                <div class="metric-value" style="color: {status_color}; font-size: 1.5rem;">{status_text}</div>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        # Show threats if malicious
                        if is_malicious and result.get('threats'):
                            st.markdown("**🔍 Detected Threats:**", unsafe_allow_html=True)
                            for threat in result['threats'][:5]:  # Show top 5 threats
                                st.markdown(f"- {threat}", unsafe_allow_html=True)
                else:
                    # Error case
                    with st.expander(f"{idx}. {result['filename']} - ❌ ERROR", expanded=False):
                        st.error(f"Scan failed: {result.get('error', 'Unknown error')}")
            
            # Reset button
            st.markdown("<br>", unsafe_allow_html=True)
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                if st.button("🔄 SCAN NEW BATCH", use_container_width=True):
                    st.session_state['batch_scanning'] = False
                    st.rerun()
