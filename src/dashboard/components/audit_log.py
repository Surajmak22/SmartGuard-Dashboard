import streamlit as st
import pandas as pd
from datetime import datetime
import random

def render_audit_log(user_id=None):
    """
    Renders the User Activity Audit Log.
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            📝 USER ACTIVITY AUDIT LOG
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Compliance & Action Tracking</p>
    </div>
    """, unsafe_allow_html=True)

    # Generate dummy data for audit log
    actions = ["Login", "Scan Initiated", "File Upload", "Report Download", "Alert Configured", "Logout", "Settings Changed"]
    users = ["Admin_01", "Analyst_Dave", "SecOps_Lead", "System_Auto"]
    statuses = ["Success", "Success", "Success", "Failed", "Success"]
    
    data = []
    for i in range(20):
        data.append({
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "User": random.choice(users),
            "Action": random.choice(actions),
            "IP Address": f"192.168.1.{random.randint(10, 99)}",
            "Status": random.choice(statuses),
            "Details": f"Operation ID: {random.randint(1000, 9999)}"
        })
    
    df = pd.DataFrame(data)

    # Filters
    col1, col2 = st.columns(2)
    with col1:
        user_filter = st.multiselect("Filter by User", options=users, default=[])
    with col2:
        action_filter = st.multiselect("Filter by Action", options=actions, default=[])

    if user_filter:
        df = df[df["User"].isin(user_filter)]
    if action_filter:
        df = df[df["Action"].isin(action_filter)]

    # Style the dataframe
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Status": st.column_config.TextColumn(
                "Status",
                help="Outcome of the action",
                validate="^(Success|Failed)$"
            )
        }
    )

    if st.button("📥 Export Audit Log (CSV)"):
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name='audit_log.csv',
            mime='text/csv',
        )
