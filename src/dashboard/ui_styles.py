# -*- coding: utf-8 -*-
import streamlit as st
import functools

# Global Premium Typography and Styling
@st.cache_data
def get_premium_css():
    """Returns the CSS for the premium 'Ancrid-style' design system."""
    return """
    <style>
        /* Global Reset & Premium Typography */
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;700&display=swap');

        html, body, [class*="css"] {
            font-family: 'Outfit', sans-serif;
            color: #F8FAFC;
            background-color: #030712;
            scroll-behavior: smooth;
        }
        
        /* Modern Enterprise Background */
        .stApp {
            background-color: #030712;
            background-image: 
                radial-gradient(circle at 50% -20%, rgba(20, 184, 166, 0.1) 0%, transparent 60%),
                radial-gradient(circle at 0% 100%, rgba(99, 102, 241, 0.05) 0%, transparent 40%);
            background-attachment: fixed;
        }

        /* Hide Streamlit Native UI for 'Pure Website' feel */
        [data-testid="stSidebar"] { display: none !important; }
        [data-testid="stHeader"] { display: none !important; }
        footer { visibility: hidden !important; }
        #MainMenu { visibility: hidden !important; }
        
        /* Premium Floating Navbar (ancrid-inspired) */
        .navbar {
            position: fixed;
            top: 2rem;
            left: 50%;
            transform: translateX(-50%);
            width: 85%;
            max-width: 1000px;
            background: rgba(15, 23, 42, 0.7);
            backdrop-filter: blur(12px) saturate(180%);
            -webkit-backdrop-filter: blur(12px) saturate(180%);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 999px;
            padding: 0.75rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            z-index: 1000;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        }

        .nav-logo {
            font-weight: 800;
            font-size: 1.25rem;
            color: #14B8A6; /* Teal */
            letter-spacing: -0.02em;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .nav-links {
            display: flex;
            gap: 2rem;
        }

        .nav-link {
            color: #94A3B8;
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
            transition: color 0.2s ease;
            cursor: pointer;
        }

        .nav-link:hover {
            color: #F8FAFC;
        }

        .nav-link.active {
            color: #14B8A6;
        }

        .nav-cta {
            background: #14B8A6;
            color: #030712;
            padding: 0.5rem 1.25rem;
            border-radius: 999px;
            font-size: 0.85rem;
            font-weight: 700;
            text-decoration: none;
            transition: all 0.2s ease;
        }

        .nav-cta:hover {
            background: #0D9488;
            transform: scale(1.02);
        }

        /* Hero Text & Layout */
        .hero-container {
            padding-top: 10rem;
            text-align: center;
            max-width: 800px;
            margin: 0 auto;
        }

        .badge-trust {
            display: inline-flex;
            align-items: center;
            gap: 12px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 6px 16px;
            border-radius: 999px;
            margin-bottom: 2rem;
        }

        .hero-title {
            font-size: 4rem !important;
            font-weight: 800 !important;
            line-height: 1.1 !important;
            letter-spacing: -0.04em !important;
            background: linear-gradient(180deg, #FFFFFF 0%, #94A3B8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 1.5rem !important;
        }

        .hero-subtitle {
            font-size: 1.15rem;
            color: #94A3B8;
            line-height: 1.6;
            margin-bottom: 3rem;
        }

        /* Generic Layout Adjustments */
        .main-content {
            padding-top: 12rem;
            padding-bottom: 5rem;
        }

        /* Buttons Fix */
        .stButton button {
            background: #14B8A6 !important;
            color: #030712 !important;
            border-radius: 999px !important;
            font-weight: 700 !important;
            padding: 0.5rem 2rem !important;
            border: none !important;
        }
    </style>
    """

def inject_premium_styles():
    """Injects global 'Modern Enterprise' design system."""
    st.markdown(get_premium_css(), unsafe_allow_html=True)

def floating_navbar(active_page="Home"):
    """Render a premium floating navigation bar."""
    pages = ["Home", "Neural Analysis", "Threat Map", "Documentation"]
    links_html = ""
    for page in pages:
        active_class = "active" if page == active_page else ""
        links_html += f'<div class="nav-link {active_class}">{page}</div>'
    
    st.markdown(f"""
    <div class="navbar">
        <div class="nav-logo">🛡️ SMARTGUARD <span style="color: #94A3B8; font-weight: 400;">AI</span></div>
        <div class="nav-links">
            {links_html}
        </div>
        <a href="#" class="nav-cta">Deploy Engine</a>
    </div>
    """, unsafe_allow_html=True)

def render_hero(title, subtitle):
    """Render a centered hero section with professional typography."""
    st.markdown(f"""
    <div class="hero-container">
        <div class="badge-trust">
            <div style="display: flex;">
                <img src="https://ui-avatars.com/api/?name=S&background=14B8A6&color=fff" style="width: 24px; height: 24px; border-radius: 50%; border: 2px solid #030712;">
                <img src="https://ui-avatars.com/api/?name=A&background=6366F1&color=fff" style="width: 24px; height: 24px; border-radius: 50%; border: 2px solid #030712; margin-left: -8px;">
            </div>
            <span style="color: #94A3B8; font-size: 0.8rem; font-weight: 500;">Trusted by 500+ Security Experts</span>
        </div>
        <h1 class="hero-title">{title}</h1>
        <p class="hero-subtitle">{subtitle}</p>
    </div>
    """, unsafe_allow_html=True)

def glass_card(title, value, subtitle=None):
    """Render a premium glassmorphic metric card with modern typography."""
    st.markdown(f"""
    <div class="glass-card" style="background: rgba(30, 41, 59, 0.4); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 24px; margin-bottom: 16px; backdrop-filter: blur(8px);">
        <div style="font-size: 0.75rem; font-weight: 600; color: #94A3B8; text-transform: uppercase;">{title}</div>
        <div style="font-size: 2.25rem; font-weight: 700; color: #F8FAFC;">{value}</div>
        {f'<div style="font-size: 0.875rem; color: #64748B;">{subtitle}</div>' if subtitle else ''}
    </div>
    """, unsafe_allow_html=True)
