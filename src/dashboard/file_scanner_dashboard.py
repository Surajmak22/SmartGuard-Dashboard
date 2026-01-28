from __future__ import annotations

import time
import streamlit as st
from src.utils.file_scanner import FileScanner
from src.phase1.reporting import IncidentReportGenerator


def run() -> None:
    st.subheader("📁 Simplified File Security Scanner")
    st.markdown("""
    <p style='color: #666;'>
    Upload any multimedia file (Image, MP3, Video) to check for hidden threats using heuristic and entropy analysis.
    </p>
    """, unsafe_allow_html=True)

    # Designer Styling
    st.markdown("""
    <style>
    .stUploadedFile {
        border: 2px dashed #4A90E2;
        border-radius: 10px;
        padding: 20px;
    }
    .result-card {
        padding: 2.5rem;
        border-radius: 1.5rem;
        margin: 2rem 0;
        text-align: center;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.1);
    }
    .status-safe { color: #00C851; font-size: 2.5rem; font-weight: bold; }
    .status-threat { color: #ff4444; font-size: 2.5rem; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

    uploaded_file = st.file_uploader("Drop your file here", type=["jpg", "jpeg", "png", "mp3", "mp4", "wav", "flac"])

    if uploaded_file is not None:
        c1, c2 = st.columns([1, 1])
        with c1:
            st.info(f"**Filename:** {uploaded_file.name}")
            st.info(f"**Size:** {len(uploaded_file.getvalue()) / 1024:.2f} KB")
        
        if st.button("🚀 Start Security Scan", use_container_width=True):
            with st.spinner("Analyzing file structure and entropy..."):
                time.sleep(1.5)  # Visual feedback
                
                scanner = FileScanner()
                result = scanner.analyze_file(uploaded_file.name, uploaded_file.getvalue())
                
                # Visual Result Card
                st.markdown("<div class='result-card'>", unsafe_allow_html=True)
                if result.is_safe:
                    st.markdown("<div class='status-safe'>✅ FILE IS SAFE</div>", unsafe_allow_html=True)
                    st.success("No malicious patterns or obfuscation detected. This file is safe to use.")
                else:
                    st.markdown("<div class='status-threat'>❌ THREAT DETECTED</div>", unsafe_allow_html=True)
                    st.error("This file shows suspicious characteristics and may contain hidden payloads.")
                st.markdown("</div>", unsafe_allow_html=True)

                # Detailed Findings
                with st.expander("🔍 View Technical Details"):
                    st.write(f"**Entropy:** `{result.entropy}` (Higher usually means compressed/encrypted)")
                    st.write(f"**Detected Body Type:** `{result.file_type}`")
                    st.write(f"**SHA-256 Hash:** `{result.file_hash}`")
                    if result.threats:
                        st.warning("⚠️ **Heuristic Warnings:**")
                        for t in result.threats:
                            st.write(f"- {t}")

                # PDF Report
                st.divider()
                gen = IncidentReportGenerator()
                pdf_bytes = gen.generate_file_report(
                    filename=result.filename,
                    detected_type=result.file_type,
                    is_safe=result.is_safe,
                    risk_score=result.risk_score,
                    threats=result.threats,
                    file_hash=result.file_hash
                )
                
                st.download_button(
                    label="📄 Download Official Security Report (PDF)",
                    data=pdf_bytes,
                    file_name=f"security_report_{int(time.time())}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )


if __name__ == "__main__":
    # If run standalone for testing
    st.set_page_config(page_title="File Scanner", layout="centered")
    run()
