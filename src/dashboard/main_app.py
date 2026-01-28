from __future__ import annotations

import streamlit as st
import src.dashboard.malware_portal as malware_dashboard
import src.dashboard.soc_monitor as soc_monitor
from src.dashboard.styles.ui_components import inject_premium_styles
from src.dashboard.components.sidebar import render_sidebar

import src.dashboard.admin_dashboard as admin_dashboard
import src.dashboard.documentation as doc_page

def main():
    # Inject Obsidian Glass theme
    inject_premium_styles()
    
    st.set_page_config(
        page_title="SmartGuard AI | Elite Security Intelligence",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Render Sidebar & Get Mode
    app_mode = render_sidebar()


    if app_mode == "🌍 Global Threat Map":
        soc_monitor.run()
    elif app_mode == "🦠 Malware Analysis Portal":
        malware_dashboard.run()
    elif app_mode == "🔐 Admin Command Center":
        admin_dashboard.run()
    elif app_mode == "📚 Documentation & Guides":
        doc_page.run()


if __name__ == "__main__":
    main()
