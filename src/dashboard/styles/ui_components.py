import streamlit as st

def inject_premium_styles():
    """
    Injects global 'Obsidian Enterprise' design system into the Streamlit dashboard.
    """
    st.markdown("""
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <style>
        /* Global Reset & Typography */
        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
            color: #E0E0E0;
            background-color: #0A0A0A; /* Deep Matte Black */
        }
        
        /* Modern Enterprise Background */
        .stApp {
            background-color: #0A0A0A;
            background-image: 
                radial-gradient(circle at 50% 0%, rgba(56, 189, 248, 0.03) 0%, transparent 50%),
                radial-gradient(circle at 0% 100%, rgba(99, 102, 241, 0.02) 0%, transparent 40%);
            background-attachment: fixed;
        }

        /* Sidebar - Clean & Minimal */
        [data-testid="stSidebar"] {
            background-color: #050505;
            border-right: 1px solid rgba(255, 255, 255, 0.05);
            box-shadow: none;
        }

        /* Modern Glass Cards - Vercel Style */
        .glass-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 16px;
            transition: all 0.2s ease-in-out;
            backdrop-filter: blur(10px);
        }
        
        .glass-card:hover {
            border-color: rgba(56, 189, 248, 0.3); /* Subtle Blue Glow */
            background: rgba(255, 255, 255, 0.03);
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        }

        /* Metrics - Clean Typography */
        .metric-label {
            font-size: 0.85rem;
            font-weight: 500;
            color: #9CA3AF; /* Muted Grey */
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: 600;
            color: #FFFFFF;
            letter-spacing: -1px;
        }
        
        .metric-subtitle {
            font-size: 0.9rem;
            color: #6B7280;
            margin-top: 4px;
        }

        /* Status Badges - Pill Shape */
        .status-badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 9999px; /* Full Pill */
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }
        .status-online { 
            background: rgba(16, 185, 129, 0.1); 
            color: #34D399; 
            border: 1px solid rgba(16, 185, 129, 0.2);
        }
        .status-alert { 
            background: rgba(239, 68, 68, 0.1); 
            color: #F87171; 
            border: 1px solid rgba(239, 68, 68, 0.2);
        }
        
        /* Form Elements - Minimalist */
        .stButton button {
            background: linear-gradient(180deg, #1F2937 0%, #111827 100%);
            color: #E5E7EB;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            padding: 0.5rem 1rem;
            font-weight: 500;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            transition: all 0.2s;
        }
        .stButton button:hover {
            border-color: #38BDF8;
            color: #FFFFFF;
            transform: translateY(-1px);
        }
        
        /* Markdown & Text - High Readability */
        .stMarkdown, p, div, span, label {
            color: #E0E0E0 !important;
            line-height: 1.6;
        }
        
        /* Code Blocks */
        code, pre {
            background-color: #111827 !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
            border-radius: 6px;
            color: #38BDF8 !important; /* Sky Blue */
        }
        
        /* Aggressive Dropdown Fix - Force Dark Theme */
        div[data-baseweb="select"] > div, 
        div[data-baseweb="base-input"], 
        .stSelectbox div[data-baseweb="select"] > div {
            background-color: #0A0A0A !important;
            color: #FFFFFF !important;
            border: 1px solid rgba(255,255,255,0.15) !important;
        }

        /* The Dropdown Menu / Popover */
        div[data-baseweb="popover"], 
        div[data-baseweb="menu"],
        div[data-baseweb="menu"] > div {
            background-color: #0A0A0A !important;
            border: 1px solid rgba(56, 189, 248, 0.3) !important;
        }

        /* Option Items */
        li[role="option"] {
            background-color: #0A0A0A !important;
            color: #E0E0E0 !important;
        }
        
        /* Force text color inside options */
        li[role="option"] div, 
        li[role="option"] span {
            color: #E0E0E0 !important;
        }

        /* Hover / Selected State */
        li[role="option"]:hover, 
        li[role="option"][aria-selected="true"] {
            background-color: rgba(56, 189, 248, 0.2) !important;
            color: #38BDF8 !important;
        }
        
        li[role="option"]:hover span, 
        li[role="option"]:hover div {
            color: #38BDF8 !important;
        }
        
        /* Icons in dropdown */
        .stSelectbox svg {
            fill: #FFFFFF !important;
        }
        
        /* Icons in dropdown */
        .stSelectbox svg {
            fill: #FFFFFF !important;
        }
        
        /* NUCLEAR FILE UPLOADER FIX */
        [data-testid='stFileUploader'] {
            width: 100%;
        }
        
        /* Target the dropzone rect */
        [data-testid='stFileUploader'] section {
            background-color: #0F172A !important;
            border: 2px dashed #00F5FF !important;
        }
        
        /* Target the internal div that actually holds the white background in many themes */
        section[data-testid="stFileUploader"] > div {
             background-color: #0F172A !important;
             color: white !important;
        }
        
        section[data-testid="stFileUploader"] > div > div {
             background-color: #0F172A !important;
        }
        
        /* Force ALL text white */
        [data-testid='stFileUploader'] * {
            color: #FFFFFF !important;
        }
        
        /* Styles for the Browse Button */
        [data-testid='stFileUploader'] button {
            background-color: rgba(56, 189, 248, 0.15) !important;
            color: #38BDF8 !important;
            border: 1px solid #38BDF8 !important;
            font-weight: bold !important;
        }
        
        [data-testid='stFileUploader'] button:hover {
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.6) !important;
            background-color: #38BDF8 !important;
            color: #000000 !important;
        }
        
        /* Icon color */
        [data-testid='stFileUploader'] svg {
            fill: #38BDF8 !important;
        }
        
        /* Input Fields - Clean Dark */
        .stTextInput>div>div>input {
            background-color: #0F1115;
            color: #FFFFFF;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 6px;
        }
        .stTextInput>div>div>input:focus {
            border-color: #38BDF8;
            box-shadow: 0 0 0 1px #38BDF8;
        }

        /* NUCLEAR FIX FOR EXPANDER HEADERS */
        .streamlit-expanderHeader, 
        div[data-testid="stExpander"] details > summary {
            background-color: #0F172A !important;
            color: #FFFFFF !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
            border-radius: 8px !important;
        }

        .streamlit-expanderHeader:hover, 
        div[data-testid="stExpander"] details > summary:hover {
            background-color: #1E293B !important;
            color: #38BDF8 !important;
            border-color: #38BDF8 !important;
        }

        /* Fix SVG Arrows */
        .streamlit-expanderHeader svg, 
        div[data-testid="stExpander"] details > summary svg {
            fill: #FFFFFF !important;
        }
        
        .streamlit-expanderHeader:hover svg,
        div[data-testid="stExpander"] details > summary:hover svg {
            fill: #38BDF8 !important;
        }

        /* ANIMATIONS */
        @keyframes fadeIn {
            0% { opacity: 0; }
            100% { opacity: 1; }
        }
        
        @keyframes slideUp {
            0% { opacity: 0; transform: translateY(20px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes pulse-glow {
            0% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.4); }
            70% { box-shadow: 0 0 0 10px rgba(56, 189, 248, 0); }
            100% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0); }
        }
        
        /* GLOBAL PAGE TRANSITION */
        .main .block-container {
            animation: fadeIn 0.5s ease-out;
        }

        /* HERO TEXT FIX */
        .hero-title {
            font-size: 3.5rem !important;
            font-weight: 900 !important;
            color: #FFFFFF !important;
            text-shadow: 0 0 30px rgba(56, 189, 248, 0.6) !important;
            margin-bottom: 1rem !important;
            letter-spacing: -2px !important;
        }

        .animate-fade-in { animation: fadeIn 0.5s ease-out forwards; }
        .animate-slide-up { animation: slideUp 0.6s ease-out forwards; }
        
        header, footer, [data-testid="stHeader"] { display: none !important; }
    </style>
    """, unsafe_allow_html=True)

def glass_card(title, value, subtitle=None):
    """Render a premium glassmorphic metric card with modern typography."""
    st.markdown(f"""
    <div class="glass-card">
        <div class="metric-label">{title}</div>
        <div class="metric-value">{value}</div>
        {f'<div class="metric-subtitle">{subtitle}</div>' if subtitle else ''}
    </div>
    """, unsafe_allow_html=True)
