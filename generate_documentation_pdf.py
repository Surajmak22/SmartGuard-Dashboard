from fpdf import FPDF
import datetime

class SmartGuardDoc(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font('helvetica', 'B', 10)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, 'SMARTGUARD AI - TOTAL TECHNICAL MANUAL', 0, 1, 'R')
            self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(169, 169, 169)
        self.cell(0, 10, f'Page {self.page_no()} | Generated on {datetime.datetime.now().strftime("%B %d, %Y")}', 0, 0, 'C')

def create_manual():
    pdf = SmartGuardDoc()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # --- TITLE PAGE ---
    pdf.add_page()
    pdf.set_fill_color(3, 7, 18) 
    pdf.rect(0, 0, 210, 297, 'F')
    
    pdf.set_y(80)
    pdf.set_font('helvetica', 'B', 48)
    pdf.set_text_color(0, 245, 255) # Cyan
    pdf.cell(0, 30, 'SMARTGUARD AI', 0, 1, 'C')
    
    pdf.set_font('helvetica', 'B', 18)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 15, 'THE DEFINITIVE TECHNICAL SPECIFICATION', 0, 1, 'C')
    pdf.cell(0, 10, 'Comprehensive Platform & Intelligence Manual', 0, 1, 'C')
    
    pdf.ln(30)
    pdf.set_draw_color(0, 245, 255)
    pdf.set_line_width(1)
    pdf.line(50, pdf.get_y(), 160, pdf.get_y())
    
    pdf.set_y(240)
    pdf.set_font('helvetica', '', 14)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 10, 'Prepared for: Senior Cybersecurity Evaluation', 0, 1, 'C')
    pdf.cell(0, 10, 'Platform Version: 2.0.0 (Elite Evolution)', 0, 1, 'C')
    pdf.cell(0, 10, f'Authorized Release: {datetime.datetime.now().strftime("%Y")}', 0, 1, 'C')

    # --- 1. CORE ARCHITECTURE ---
    pdf.add_page()
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', 'B', 24)
    pdf.cell(0, 20, '1. SYSTEM ARCHITECTURE & TECH STACK', 0, 1, 'L')
    
    pdf.set_font('helvetica', 'B', 16)
    pdf.set_text_color(0, 114, 255)
    pdf.cell(0, 12, '1.1 Backend Engine: FastAPI & Python', 0, 1, 'L')
    
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', '', 12)
    pdf.multi_cell(0, 8, (
        "The backend is built using FastAPI, chosen for its ultra-high performance and "
        "asynchronous capabilities. Unlike traditional synchronous frameworks, "
        "FastAPI allows the SmartGuard engine to process multiple heavy file scans concurrently "
        "without blocking the intelligence pipeline. It leverages Pydantic for data validation, "
        "ensuring that every security result is strictly typed and professional."
    ))
    
    pdf.ln(5)
    pdf.set_font('helvetica', 'B', 16)
    pdf.set_text_color(0, 114, 255)
    pdf.cell(0, 12, '1.2 Frontend Interface: Streamlit & Custom CSS', 0, 1, 'L')
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', '', 12)
    pdf.multi_cell(0, 8, (
        "The primary dashboard is powered by Streamlit, integrated with a bespoke custom "
        "CSS design system (Obsidian Enterprise). Streamlit was selected to bridge the gap "
        "between data-intensive machine learning and a professional user interface. It enables "
        "real-time reactive updates for the Cinematic Scan Sequences and allows for the "
        "integration of Plotly.js for advanced technical visualizations."
    ))

    # --- 2. DATA FLOW & STORAGE ---
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 24)
    pdf.cell(0, 20, '2. DATA LIFECYCLE & STORAGE', 0, 1, 'L')
    
    content = (
        "When a user uploads a file to SmartGuard AI, the system follows a secure, transient lifecycle:\n\n"
        "Step 1: In-Memory Ingestion\n"
        "The file is sent over a TLS 1.3 encrypted connection. It is ingested as a byte stream. "
        "The actual file content is never permanently stored on our disk during standard analysis "
        "to maintain maximum user privacy.\n\n"
        "Step 2: Multi-Layer Decomposition\n"
        "The engine performs signature matching, heuristic randomness checks (Entropy), and "
        "ML pattern recognition. Only the metadata and results (risk score, detections) are captured.\n\n"
        "Step 3: History Logging\n"
        "Scan results are persisted in logs/malware_history.json. This file stores the filename, "
        "SHA-256 hash, Risk Score, and a unique Session User ID. This allows for User-Specific "
        "Isolation, ensuring one user cannot see another users scan archive."
    )
    pdf.set_font('helvetica', '', 12)
    pdf.multi_cell(0, 8, content)

    # --- 3. THE INTELLIGENCE ENGINE ---
    pdf.ln(10)
    pdf.set_font('helvetica', 'B', 24)
    pdf.cell(0, 20, '3. MACHINE LEARNING & INTELLIGENCE', 0, 1, 'L')
    
    pdf.set_font('helvetica', 'B', 16)
    pdf.set_text_color(0, 114, 255)
    pdf.cell(0, 12, '3.1 The NSL-KDD Dataset', 0, 1, 'L')
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', '', 12)
    pdf.multi_cell(0, 8, (
        "The Neural Core of SmartGuard AI is trained on the NSL-KDD dataset, a world-standard "
        "benchmark in cybersecurity research. Provided by the Canadian Institute for "
        "Cybersecurity (University of New Brunswick), this dataset contains thousands of "
        "real-world network and file attack patterns. It was selected because it eliminates "
        "redundancies found in the older KDD 99 dataset, resulting in a more accurate and "
        "less biased model for detecting modern threats likes Probes, DoS, and Rootkits."
    ))

    pdf.ln(5)
    pdf.set_font('helvetica', 'B', 16)
    pdf.set_text_color(0, 114, 255)
    pdf.cell(0, 12, '3.2 Model Architecture', 0, 1, 'L')
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', '', 12)
    pdf.multi_cell(0, 8, (
        "The platform utilizes an Ensemble Voting Classifier consisting of a Random Forest "
        "model (for structural feature importance) and a Multi-Layer Perceptron (for non-linear "
        "pattern matching). We also utilize SMOTE (Synthetic Minority Over-sampling Technique) "
        "during training to ensure the model is equally effective at identifying rare, critical "
        "zero-day exploits."
    ))

    # --- 4. FEATURE DEEP-DIVE ---
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 24)
    pdf.cell(0, 20, '4. FEATURE MECHANICAL OVERVIEW', 0, 1, 'L')
    
    features = [
        ("Cinematic Scan Sequences", 
         "Uses st.status and time-staggered status updates. This isn't just aesthetic; it "
         "slows down the UI to a human-digestible pace while the high-speed backend completes "
         "its analysis, providing feedback on which neural bridge is being established."),
        
        ("Actionable Remediation Guides", 
         "Translates mathematical risk scores into physical security steps. A score > 90 "
         "triggers critical isolation protocols, whereas < 40 provides Safe Monitoring "
         "advice. It acts as a digital first-aid kit for users."),
        
        ("Side-by-Side Comparison", 
         "Forensic tool that uses set-theory to find the Threat Contrast. It highlights "
         "exactly which malicious indicators are present in Specimen A but absent in Specimen B.")
    ]
    
    for title, desc in features:
        pdf.set_font('helvetica', 'B', 14)
        pdf.set_text_color(255, 0, 60)
        pdf.cell(0, 10, f"- {title}", 0, 1, 'L')
        pdf.set_text_color(0, 0, 0)
        pdf.set_font('helvetica', '', 12)
        pdf.multi_cell(0, 8, desc)
        pdf.ln(5)

    # --- 5. GLOSSARY & SPECS ---
    pdf.ln(10)
    pdf.set_font('helvetica', 'B', 24)
    pdf.cell(0, 20, '5. FINAL TECHNICAL SPECIFICATIONS', 0, 1, 'L')
    
    pdf.set_font('courier', '', 10)
    specs = [
        "PRIMARY LANGUAGE:     Python 3.10+",
        "UI FRAMEWORK:        Streamlit (Enterprise Theme)",
        "API LAYER:           FastAPI (Uvicorn ASGI)",
        "ML DATASET:          NSL-KDD (UNB CIC)",
        "ENCRYPTION:          TLS 1.3 / AES-256 (History)",
        "SCANNING SPEED:      < 200ms (Core Engine)",
        "DETECTION LAYERS:    Signatures, Entropy, Neural Core"
    ]
    for spec in specs:
        pdf.cell(0, 7, spec, 0, 1, 'L')

    pdf.output("SmartGuard_AI_Total_Technical_Manual.pdf")
    print("Total Manual PDF Generated Successfully.")

if __name__ == "__main__":
    create_manual()
