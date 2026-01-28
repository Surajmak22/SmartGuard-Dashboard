import streamlit as st
import time
from datetime import datetime, timedelta

def render_scan_scheduler():
    """
    Renders the simulated Scan Scheduler interface.
    """
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2 style="color: #00F5FF; font-weight: 900; font-size: 2rem; text-shadow: 0 0 15px rgba(0, 245, 255, 0.5);">
            ⏰ AUTOMATED SCAN SCHEDULER
        </h2>
        <p style="color: #FFFFFF; font-weight: 700; font-size: 1rem;">Configure Recurring Security Tasks</p>
    </div>
    """, unsafe_allow_html=True)
    
    if 'scheduled_tasks' not in st.session_state:
        st.session_state['scheduled_tasks'] = [
            {"id": 1, "name": "Daily Full System Scan", "frequency": "Daily", "time": "02:00", "status": "Active", "last_run": "Yesterday, 02:00"},
            {"id": 2, "name": "Weekly Report Generation", "frequency": "Weekly", "time": "Sunday, 23:00", "status": "Active", "last_run": "Sunday, 23:00"}
        ]

    with st.expander("➕ SCHEDULE NEW TASK", expanded=False):
        col1, col2 = st.columns(2)
        with col1:
            task_name = st.text_input("Task Name", placeholder="e.g. Critical Directory Watch")
            frequency = st.selectbox("Frequency", ["Hourly", "Daily", "Weekly", "Monthly"])
        with col2:
            time_val = st.time_input("Execution Time", value=datetime.now().time())
            target = st.text_input("Target Directory/Path", placeholder="C:/Critical/Data")
            
        if st.button("💾 Schedule Task", use_container_width=True):
            new_task = {
                "id": len(st.session_state['scheduled_tasks']) + 1,
                "name": task_name if task_name else "Untitled Task",
                "frequency": frequency,
                "time": time_val.strftime("%H:%M"),
                "status": "Active",
                "last_run": "Never"
            }
            st.session_state['scheduled_tasks'].append(new_task)
            st.success(f"✅ Task '{new_task['name']}' scheduled successfully!")
            time.sleep(1)
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <h3 style="color: #00F5FF; font-weight: 800; margin-bottom: 1rem;">
        📅 ACTIVE SCHEDULES
    </h3>
    """, unsafe_allow_html=True)

    for idx, task in enumerate(st.session_state['scheduled_tasks']):
        col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
        
        with col1:
            st.markdown(f"""
            <div style="padding: 1rem; background: rgba(0, 245, 255, 0.05); border-left: 4px solid #00F5FF; border-radius: 4px;">
                <h4 style="color: #FFFFFF; font-weight: 800; margin: 0;">{task['name']}</h4>
                <p style="color: #00F5FF; font-weight: 600; margin: 0.2rem 0 0 0; font-size: 0.9rem;">
                   {task['frequency']} at {task['time']}
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
             st.markdown(f"""
            <div style="padding-top: 1rem; color: #FFFFFF; font-weight: 600;">
                Last Run: <span style="color: #BBBBBB;">{task['last_run']}</span>
            </div>
            """, unsafe_allow_html=True)

        with col3:
            status_color = "#00FF88" if task['status'] == "Active" else "#FF003C"
            st.markdown(f"""
            <div style="padding-top: 1rem; color: {status_color}; font-weight: 800;">
                {task['status'].upper()}
            </div>
            """, unsafe_allow_html=True)
            
        with col4:
            if st.button("🗑️", key=f"del_task_{idx}"):
                st.session_state['scheduled_tasks'].pop(idx)
                st.rerun()
