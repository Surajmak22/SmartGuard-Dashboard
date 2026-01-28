import streamlit as st

def run():
    # Documentation Sub-Navigation
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📘 Knowledge Base")
    doc_mode = st.sidebar.radio(
        "Select Section",
        [
            "📖 Introduction & Overview",
            "🧠 The Hybrid AI Engine",
            "🛠️ User Guide: Reports",
            "⚖️ Legal & Privacy (Official)",
            "❓ F.A.Q."
        ],
        label_visibility="collapsed"
    )

    # Styling
    st.markdown("""
        <style>
        .doc-title { font-size: 2/5rem; font-weight: 800; color: #00F5FF; margin-bottom: 0.5rem; }
        .doc-section { font-size: 1.5rem; font-weight: 600; color: #E0E0E0; margin-top: 2rem; margin-bottom: 1rem; border-bottom: 1px solid #333; }
        .doc-p { color: #CCCCCC; line-height: 1.8; font-size: 1rem; margin-bottom: 1rem; }
        .warning-box { background: rgba(255, 0, 60, 0.1); border-left: 4px solid #FF003C; padding: 1.5rem; margin: 1.5rem 0; }
        .tech-box { background: rgba(0, 245, 255, 0.05); border: 1px solid #00F5FF; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }
        </style>
    """, unsafe_allow_html=True)

    if doc_mode == "📖 Introduction & Overview":
        st.markdown('<div class="doc-title">Project Overview: SmartGuard AI</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="doc-p">
        <strong>SmartGuard AI</strong> is an advanced, experimental Threat Detection System designed to bridge the gap between traditional signature-based antivirus solutions and modern Deep Learning heuristics. 
        Unlike commercial antiviruses that rely on a database of known "bad files" (signatures), SmartGuard AI attempts to "understand" the intent of a file by analyzing its structure, code patterns, and entropy.
        <br><br>
        This platform serves as a <strong>Proof of Concept (PoC)</strong> for the future of decentralized, AI-driven cybersecurity. It is open to the public for educational and research purposes, allowing users to verify files against our trained neural models.
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<div class="doc-section">Mission Statement</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="doc-p">
        1. <strong>Democratize Security:</strong> Provide enterprise-grade AI analysis tools to the general public for free.<br>
        2. <strong>Advance Research:</strong> test the efficacy of Convolutional Neural Networks (CNNs) in detecting obfuscated malware.<br>
        3. <strong>Education:</strong> Help users understand <em>why</em> a file is flagged, not just <em>that</em> it is flagged.
        </div>
        """, unsafe_allow_html=True)

    elif doc_mode == "🧠 The Hybrid AI Engine":
        st.markdown('<div class="doc-title">Technical Deep Dive: The Neural Core</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="doc-p">
        SmartGuard AI does not rely on a single algorithm. Instead, it employs a "Voting Ensemble" of three distinct architectures. This approach mimics a biological immune system, where different cells attack pathogens in different ways.
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<div class="doc-section">1. Convolutional Neural Network (CNN)</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="tech-box">
            <strong>The Concept:</strong> Just as CNNs can recognize a cat in a photo, they can recognize malware in a binary file.
            <br><br>
            <strong>The Process:</strong>
            <ul>
                <li>The raw bytes of a file (0s and 1s) are converted into a grayscale image.</li>
                <li>Code sections become visual textures. Encrypted data looks like static noise.</li>
                <li>The CNN scans this "image" for visual patterns common in malware families (e.g., the specific visual signature of a "WannaCry" unpacker).</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<div class="doc-section">2. Random Forest Classifier (RF)</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="doc-p">
        The "Logical Brain" of the system. It analyzes metadata rather than raw code. It asks questions like:
        <ul>
            <li>"Does this 2KB file claim to be a 4GB installer?"</li>
            <li>"Does this calculator app invoke the Windows Kernel API 500 times per second?"</li>
        </ul>
        If the metadata is suspicious, the RF flags it, even if the code looks clean.
        </div>
        """, unsafe_allow_html=True)

    elif doc_mode == "🛠️ User Guide: Reports":
        st.markdown('<div class="doc-title">Understanding Your Scan Report</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="doc-p">
        When you upload a file, the system generates a detailed Risk Assessment. Here is how to interpret the fields.
        </div>
        """, unsafe_allow_html=True)
        
        st.info("Risk Score Range: 0 (Safe) to 100 (Critical)")
        
        col1, col2 = st.columns(2)
        with col1:
             st.markdown("#### ✅ Safe (0-20)")
             st.caption("The file exhibits standard behaviors. Likely benign.")
        with col2:
             st.markdown("#### ⚠️ Suspicious (21-69)")
             st.caption("Unusual headers or packed sections detected. Proceed with caution.")
             
        st.markdown("#### 🚨 Malicious (70-100)")
        st.caption("Strong indicators of malware (Ransomware, Trojan, Spyware). DO NOT RUN THIS FILE.")

    elif doc_mode == "⚖️ Legal & Privacy (Official)":
        st.markdown('<div class="doc-title">Privacy Policy & Terms of Service</div>', unsafe_allow_html=True)
        st.caption("Last Updated: January 2026")
        
        st.markdown("""
        <div class="warning-box">
            <strong>ACADEMIC PROJECT DISCLAIMER & LIMITATIONS</strong><br>
            Smart Guard AI is an educational project developed for academic research purposes. It is not a commercial service.
            <br><br>
            <strong>WE EXPLICITLY DO NOT CLAIM:</strong>
            <ul style="margin-bottom: 0;">
                <li>"100% Protection" or "Zero-False-Positive" accuracy.</li>
                <li>"Military-grade security" (This is a marketing term, not a technical standard).</li>
                <li>Formal Regulatory Compliance (e.g., "Full GDPR Compliant", "ISO 27001", "HIPAA").</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="doc-p">
        This Privacy Policy describes how Smart Guard AI ("we", "us", or "our") collects, uses, and discloses information when you use our virus scanning and threat intelligence platform (the "Service"). By accessing or using the Service, you agree to the collection and use of information in accordance with this policy.
        </div>
        """, unsafe_allow_html=True)

        with st.expander("1. Information We Collect", expanded=True):
            st.markdown("""
            We collect the following types of information:
            *   **File Uploads:** When you upload a file for scanning, we collect the file content, its metadata (e.g., file name, size, type), and cryptographic hashes (MD5, SHA-1, SHA-256).
            *   **URL Submissions:** When you submit a URL, we collect the URL string and any metadata associated with the target page.
            *   **Log Data:** Our servers automatically log information such as your IP address, browser type, operating system, the referring web page, pages visited, location, your mobile carrier, device information (including device and application IDs), search terms, and cookie information.
            """)

        with st.expander("2. File Upload and Scanning Data Handling"):
            st.markdown("""
            *   **Analysis:** Uploaded files are temporarily stored in a secure sandbox environment for static and dynamic analysis.
            *   **Sharing:** We may share file hashes and metadata with the broader cybersecurity community and research partners. **Do not upload files containing personal data (PII) or confidential information.**
            *   **Deletion:** While we strive to process files ephemerally, cryptographic hashes of uploaded files may be retained indefinitely in our threat database.
            """)

        with st.expander("3. URL Submission Data"):
            st.markdown("""
            URLs submitted for analysis are treated as non-confidential threat intelligence. We may scan the submitted URL and follow redirects to analyze the final destination content. This data contributes to our global threat reputation engine.
            """)

        with st.expander("4. Use of Third-Party Security Services"):
            st.markdown("""
            We may utilize third-party APIs (e.g., virus scanning engines, reputation services) to provide comprehensive analysis. 
            *   **Data Transfer:** File hashes or URL strings may be sent to these third-party providers.
            *   **Independence:** We do not control these third parties' tracking technologies or how they may be used.
            """)

        with st.expander("5. Data Retention Policy (Technical)"):
            st.markdown("""
            We adhere to a strict data lifecycle policy to minimize privacy risks:
            *   **Volatile Analysis (RAM):** Whenever possible, uploaded files are processed in volatile memory (RAM) and are not written to persistent disk storage.
            *   **Ephemeral Storage (Sandbox):** If disk storage is required for dynamic analysis, files are stored in an isolated, encrypted partition (AES-256) and are automatically purged via secure deletion (shredding) processes within 24 hours of report generation.
            *   **Metadata Retention:** While file content is purged, non-identifiable metadata (File Hash, File Size, Magic Headers, Entropy Scores) is retained indefinitely in our **Threat Intelligence Database** for longitudinal research.
            *   **Log Rotation:** System access logs are rotated every 30 days and archived in cold storage for 6 months before permanent deletion, unless required for ongoing security investigations.
            """)

        with st.expander("6. Data Security Measures & Architecture"):
            st.markdown("""
            We employ defense-in-depth security architecture to protect the integrity and confidentiality of your data:
            
            **A. Encryption Standards**
            *   **Data in Transit:** All traffic between your client and our servers is encrypted using **TLS 1.2 or TLS 1.3** with strong cipher suites (Forward Secrecy enabled).
            *   **Data at Rest:** All databases and file stores are encrypted using **AES-256-GCM** standards. Keys are managed via a dedicated Key Management Service (KMS).

            **B. Access Control**
            *   **Role-Based Access Control (RBAC):** Access to analytical data is strictly limited to authorized personnel based on the Principle of Least Privilege.
            *   **MFA enforcement:** Administrative access requires Multi-Factor Authentication.

            **C. Network & Application Security**
            *   **Isolation:** Malware analysis interacts with a mocked internet environment to prevent actual malware propagation.
            *   **WAF:** A verified Web Application Firewall filters malicious traffic (SQLi, XSS) before it reaches our analysis core.
            
            **D. Security Monitoring**
            *   **SIEM Logging:** All API access attempts are logged to an immutable audit trail to detect anomaly patterns.
            """)
        
        with st.expander("7. Limitation of Liability"):
            st.markdown("""
            **TO THE MAXIMUM EXTENT PERMITTED BY LAW:**
            *   THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE".
            *   SUPER GUARD AI DISCLAIMS ALL LIABILITY FOR ANY DAMAGES (DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL) ARISING FROM YOUR USE OF THE SERVICE.
            *   WE ARE NOT RESPONSIBLE FOR ANY DECISIONS MADE BASED ON OUR THREAT ANALYSIS (E.G., DELETING A FILE MARKED AS UNSAFE).
            *   YOU ASSUME FULL RESPONSIBILITY FOR THE FILES YOU UPLOAD.
            """)

        with st.expander("8. Legal Compliance"):
            st.markdown("""
            We reserve the right to disclose your information that we believe, in good faith, is appropriate or necessary to:
            *   Take precautions against liability.
            *   Protect ourselves or others from fraudulent, abusive, or unlawful uses or activity.
            *   Investigate and defend ourselves against any third-party claims or allegations.
            *   Protect the security or integrity of the Service.
            """)

        with st.expander("9. Cookies and Tracking Technologies"):
            st.markdown("""
            We use "cookies" and similar tracking technologies to track the activity on our Service and hold certain information.
            *   **Session Cookies:** We use Session Cookies to operate our Service.
            *   **Preference Cookies:** We use Preference Cookies to remember your preferences and various settings.
            *   **Security Cookies:** We use Security Cookies for security purposes.
            You can instruct your browser to refuse all cookies or to indicate when a cookie is being sent. However, if you do not accept cookies, you may not be able to use some portions of our Service.
            """)

        with st.expander("10. Children's Privacy"):
            st.markdown("""
            Our Service does not address anyone under the age of 18 ("Children"). We do not knowingly collect personally identifiable information from anyone under the age of 18. If you are a parent or guardian and you are aware that your Children has provided us with Personal Data, please contact us. If we become aware that we have collected Personal Data from children without verification of parental consent, we take steps to remove that information from our servers.
            """)

        with st.expander("11. International Data Transfers"):
            st.markdown("""
            Your information, including Personal Data, may be transferred to — and maintained on — computers located outside of your state, province, country or other governmental jurisdiction where the data protection laws may differ than those from your jurisdiction.
            If you are located outside India/USA and choose to provide information to us, please note that we transfer the data, including Personal Data, to our servers and process it there.
            """)

        with st.expander("12. Changes to This Privacy Policy"):
            st.markdown("""
            We may update our Privacy Policy from time to time. We will notify you of any changes by posting the new Privacy Policy on this page.
            We will let you know via email and/or a prominent notice on our Service, prior to the change becoming effective and update the "effective date" at the top of this Privacy Policy.
            You are advised to review this Privacy Policy periodically for any changes. Changes to this Privacy Policy are effective when they are posted on this page.
            """)
        
        st.markdown("""
        <div class="doc-p" style="margin-top: 2rem;">
        <strong>Contact Information</strong><br>
        For questions about this Privacy Policy or the Service, please contact the project administration team.<br>
        <em>Smart Guard AI Education Team</em>
        </div>
        """, unsafe_allow_html=True)

    elif doc_mode == "❓ F.A.Q.":
        st.markdown('<div class="doc-title">Frequently Asked Questions</div>', unsafe_allow_html=True)
        
        with st.expander("Is SmartGuard AI really free?"):
            st.write("Yes. This is a non-commercial educational project.")
            
        with st.expander("Why did it flag my game mod as a virus?"):
            st.write("Game hacks/mods often use 'Code Injection' techniques identical to Trojans. This is likely a False Positive due to behavior, but proceed with risk.")
            
        with st.expander("Can I integrate this into my company's SOC?"):
            st.write("Yes, but please review the 'Limitations of Liability' section. We offer no SLA (Service Level Agreement).")

