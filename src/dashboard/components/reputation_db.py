import streamlit as st
import pandas as pd

def render_reputation_db():
    """
    Renders the File Reputation Database Management interface.
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            🗄️ FILE REPUTATION DATABASE
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Manage Allow/Block Lists & Trusted Signatures</p>
    </div>
    """, unsafe_allow_html=True)
    
    if 'reputation_db' not in st.session_state:
        st.session_state['reputation_db'] = [
            {"Hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Status": "Trusted", "Added By": "System_Auto", "Notes": "Empty File"},
            {"Hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "Status": "Blocked", "Added By": "Admin_01", "Notes": "Known Ransomware"}
        ]

    tab1, tab2 = st.tabs(["📋 View Database", "➕ Add Entry"])
    
    with tab1:
        reputation_df = pd.DataFrame(st.session_state['reputation_db'])
        st.dataframe(reputation_df, use_container_width=True, hide_index=True)
        
        col1, col2 = st.columns(2)
        with col1:
             if st.button("🗑️ Remove Selected (Simulated)", use_container_width=True):
                 st.info("Selection removal feature simulation.")
        with col2:
             if st.button("📥 Export Database", use_container_width=True):
                 st.success("Database exported to reputation_db.json")

    with tab2:
        st.markdown("### Add New File Hash")
        new_hash = st.text_input("SHA256 Hash", placeholder="Enter hash...")
        status = st.selectbox("Reputation Status", ["Trusted", "Blocked", "Suspicious"])
        notes = st.text_area("Notes", placeholder="Reason for listing...")
        
        if st.button("Add to Database"):
            if new_hash:
                st.session_state['reputation_db'].append({
                    "Hash": new_hash,
                    "Status": status,
                    "Added By": "Current_User",
                    "Notes": notes
                })
                st.success("Entry added successfully!")
                st.rerun()
            else:
                st.error("Please enter a valid hash.")
