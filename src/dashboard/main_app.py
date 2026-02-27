from __future__ import annotations
import streamlit as st
import sys
import os

# Ensure the root project directory is in the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

def main():
    # Set page config FIRST (Streamlit requirement)
    st.set_page_config(
        page_title="SmartGuard AI | Threat Detection",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed"
    )

    # ---- Inject Global CSS ----
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

        /* ---------- GLOBAL RESET ---------- */
        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif !important;
            background-color: #0D1117 !important;
            color: #E6EDF3 !important;
        }

        /* ---------- HIDE STREAMLIT CHROME ---------- */
        [data-testid="stSidebar"]     { display: none !important; }
        [data-testid="stHeader"]      { display: none !important; }
        [data-testid="stToolbar"]     { display: none !important; }
        footer                        { visibility: hidden !important; }
        #MainMenu                     { visibility: hidden !important; }

        /* ---------- APP BACKGROUND ---------- */
        .stApp {
            background-color: #0D1117;
        }

        /* ---------- TOP NAVBAR STRIP ---------- */
        .navbar-strip {
            position: fixed;
            top: 0; left: 0; right: 0;
            height: 56px;
            background: rgba(13, 17, 23, 0.92);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid rgba(255,255,255,0.08);
            display: flex;
            align-items: center;
            padding: 0 2rem;
            z-index: 999;
            gap: 2rem;
        }
        .navbar-brand {
            font-size: 1.1rem;
            font-weight: 700;
            color: #58A6FF;
            letter-spacing: -0.02em;
            display: flex;
            align-items: center;
            gap: 8px;
            white-space: nowrap;
        }

        /* ---------- BODY OFFSET FOR FIXED NAV ---------- */
        .block-container {
            padding-top: 4.5rem !important;
            padding-bottom: 2rem !important;
            max-width: 1200px;
        }

        /* ---------- TAB BAR ---------- */
        [data-testid="stTabs"] [role="tablist"] {
            background: rgba(22, 27, 34, 0.95);
            border-bottom: 1px solid rgba(255,255,255,0.08);
            padding: 0 1rem;
            gap: 0;
            position: sticky;
            top: 56px;
            z-index: 100;
        }
        [data-testid="stTabs"] button[role="tab"] {
            font-family: 'Inter', sans-serif !important;
            font-size: 0.875rem !important;
            font-weight: 500 !important;
            color: #8B949E !important;
            padding: 0.75rem 1.25rem !important;
            border: none !important;
            background: transparent !important;
            border-bottom: 2px solid transparent !important;
            border-radius: 0 !important;
            transition: all 0.2s ease;
        }
        [data-testid="stTabs"] button[role="tab"]:hover {
            color: #E6EDF3 !important;
            background: rgba(255,255,255,0.03) !important;
        }
        [data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
            color: #58A6FF !important;
            border-bottom: 2px solid #58A6FF !important;
            background: transparent !important;
        }

        /* ---------- HERO SECTION ---------- */
        .hero-section {
            padding: 4rem 0 3rem;
            text-align: center;
        }
        .hero-title {
            font-size: clamp(2rem, 5vw, 3.25rem);
            font-weight: 800;
            color: #E6EDF3;
            letter-spacing: -0.04em;
            line-height: 1.15;
            margin-bottom: 1rem;
        }
        .hero-accent {
            background: linear-gradient(135deg, #58A6FF 0%, #79C0FF 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .hero-sub {
            font-size: 1.05rem;
            color: #8B949E;
            max-width: 560px;
            margin: 0 auto 2rem;
            line-height: 1.65;
        }

        /* ---------- FEATURE CARDS ---------- */
        .feature-card {
            background: #161B22;
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            transition: border-color 0.2s ease;
        }
        .feature-card:hover {
            border-color: rgba(88, 166, 255, 0.3);
        }
        .feature-icon { font-size: 1.75rem; margin-bottom: 0.75rem; }
        .feature-title {
            font-size: 1rem;
            font-weight: 600;
            color: #E6EDF3;
            margin-bottom: 0.4rem;
        }
        .feature-desc {
            font-size: 0.875rem;
            color: #8B949E;
            line-height: 1.6;
        }

        /* ---------- STAT BADGE ---------- */
        .stat-badge {
            background: #161B22;
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 8px;
            padding: 1.25rem 1rem;
            text-align: center;
        }
        .stat-num {
            font-size: 1.75rem;
            font-weight: 700;
            color: #58A6FF;
        }
        .stat-label {
            font-size: 0.78rem;
            color: #8B949E;
            margin-top: 0.25rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* ---------- CTA BUTTON ---------- */
        .stButton > button {
            background: #238636 !important;
            color: #ffffff !important;
            border: 1px solid rgba(240, 246, 252, 0.1) !important;
            border-radius: 6px !important;
            font-weight: 600 !important;
            font-size: 0.9rem !important;
            padding: 0.5rem 1.5rem !important;
            transition: background 0.2s ease !important;
        }
        .stButton > button:hover {
            background: #2EA043 !important;
        }

        /* ---------- SECTION HEADING ---------- */
        .section-heading {
            font-size: 1.35rem;
            font-weight: 700;
            color: #E6EDF3;
            margin-bottom: 0.5rem;
        }
        .section-sub {
            font-size: 0.9rem;
            color: #8B949E;
            margin-bottom: 1.5rem;
        }

        /* ---------- GENERAL TEXT FIX ---------- */
        p, span, label, div {
            color: #C9D1D9;
        }
        h1, h2, h3 { color: #E6EDF3 !important; }
        .stMarkdown p { color: #C9D1D9; font-size: 0.95rem; }
    </style>

    <!-- Top Navbar Brand -->
    <div class="navbar-strip">
        <div class="navbar-brand">🛡️ SmartGuard AI</div>
    </div>
    """, unsafe_allow_html=True)

    # ---- Navigation via st.tabs (REAL tabs, NO radio circles) ----
    tab_home, tab_scan, tab_map, tab_docs = st.tabs([
        "🏠 Home",
        "🔬 Neural Analysis",
        "🗺 Threat Map",
        "📖 Documentation"
    ])

    # ============================
    # TAB 1: HOME
    # ============================
    with tab_home:
        st.markdown("""
        <div class="hero-section">
            <h1 class="hero-title">
                AI-Powered<br><span class="hero-accent">Threat Detection</span>
            </h1>
            <p class="hero-sub">
                Upload files and let our multi-layer detection engine —  
                signature matching, neural networks, and heuristic analysis — 
                identify threats in real time.
            </p>
        </div>
        """, unsafe_allow_html=True)

        # Stats row
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown('<div class="stat-badge"><div class="stat-num">3</div><div class="stat-label">Detection Layers</div></div>', unsafe_allow_html=True)
        with c2:
            st.markdown('<div class="stat-badge"><div class="stat-num">10M+</div><div class="stat-label">Known Signatures</div></div>', unsafe_allow_html=True)
        with c3:
            st.markdown('<div class="stat-badge"><div class="stat-num">Real-Time</div><div class="stat-label">Analysis Speed</div></div>', unsafe_allow_html=True)
        with c4:
            st.markdown('<div class="stat-badge"><div class="stat-num">Free</div><div class="stat-label">Open Access</div></div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Feature cards
        st.markdown('<div class="section-heading">How It Works</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-sub">Three detection layers work together to identify threats.</div>', unsafe_allow_html=True)

        f1, f2, f3 = st.columns(3)
        with f1:
            st.markdown("""
            <div class="feature-card">
                <div class="feature-icon">🔑</div>
                <div class="feature-title">Signature Matching</div>
                <div class="feature-desc">Compares file hashes and byte patterns against a database of known malware signatures and EICAR test patterns.</div>
            </div>""", unsafe_allow_html=True)
        with f2:
            st.markdown("""
            <div class="feature-card">
                <div class="feature-icon">🧠</div>
                <div class="feature-title">Neural Network</div>
                <div class="feature-desc">A trained CNN and random forest model analyses byte-level entropy and structural features to detect novel threats.</div>
            </div>""", unsafe_allow_html=True)
        with f3:
            st.markdown("""
            <div class="feature-card">
                <div class="feature-icon">🔬</div>
                <div class="feature-title">Heuristic Analysis</div>
                <div class="feature-desc">Detects suspicious API call patterns, obfuscated code, and abnormal file structures common in stealth malware.</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.info("💡 **Getting Started:** Click the **Neural Analysis** tab above to scan a file.")

    # ============================
    # TAB 2: NEURAL ANALYSIS  
    # ============================
    with tab_scan:
        try:
            import src.dashboard.malware_portal as malware_dashboard
            malware_dashboard.run()
        except Exception as e:
            st.error(f"Error loading Neural Analysis: {e}")

    # ============================
    # TAB 3: THREAT MAP
    # ============================
    with tab_map:
        try:
            import src.dashboard.soc_monitor as soc_monitor
            soc_monitor.run()
        except Exception as e:
            st.error(f"Error loading Threat Map: {e}")

    # ============================
    # TAB 4: DOCUMENTATION
    # ============================
    with tab_docs:
        try:
            import src.dashboard.documentation as doc_page
            doc_page.run()
        except Exception as e:
            st.error(f"Error loading Documentation: {e}")


if __name__ == "__main__":
    main()
