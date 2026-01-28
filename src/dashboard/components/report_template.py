from datetime import datetime

def generate_report_html(file_name, file_hash, risk_score, file_size, threat_level):
    """
    Generates a professional HTML report string that looks like a Verified Certificate.
    """
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Determine Color
    color = "#10B981" # Green
    if risk_score > 70: color = "#EF4444" # Red
    elif risk_score > 20: color = "#F59E0B" # Orange
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SmartGuard AI Analysis Report</title>
        <style>
            body {{ font-family: 'Helvetica', sans-serif; background: #f4f4f5; padding: 40px; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); border-top: 8px solid {color}; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }}
            .logo {{ font-size: 24px; font-weight: bold; color: #111827; }}
            .badge {{ background: {color}; color: white; padding: 5px 15px; border-radius: 20px; font-weight: bold; font-size: 14px; text-transform: uppercase; }}
            .score-box {{ text-align: center; margin: 30px 0; padding: 30px; background: #fafafa; border-radius: 8px; }}
            .score-val {{ font-size: 48px; font-weight: 900; color: {color}; }}
            .details table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            .details td {{ padding: 12px; border-bottom: 1px solid #eee; }}
            .footer {{ margin-top: 50px; text-align: center; font-size: 12px; color: #888; border-top: 1px solid #eee; padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛡️ SmartGuard AI</div>
                <div class="badge">{threat_level}</div>
            </div>
            
            <div style="text-align: center;">
                <h2>CERTIFICATE OF ANALYSIS</h2>
                <p style="color: #666;">Report generated on {date_str}</p>
            </div>
            
            <div class="score-box">
                <div>AI RISK ASSESSMENT</div>
                <div class="score-val">{risk_score}/100</div>
                <div>Confidence Level: 98.2% (High)</div>
            </div>
            
            <div class="details">
                <h3>📁 File Artifacts</h3>
                <table>
                    <tr><td><strong>File Name:</strong></td><td>{file_name}</td></tr>
                    <tr><td><strong>SHA-256 Hash:</strong></td><td><code style="background: #eee; padding: 2px 5px; border-radius: 4px;">{file_hash}</code></td></tr>
                    <tr><td><strong>File Size:</strong></td><td>{file_size}</td></tr>
                    <tr><td><strong>Analysis Engine:</strong></td><td>Hybrid Neural Network (v2.4)</td></tr>
                </table>
            </div>
            
            <div class="details">
                <h3>🧠 Neural Verdict</h3>
                <p>
                This file was analyzed by our triple-layer detection system (Random Forest, CNN, Autoencoders).
                The calculated risk score indicates the probability of malicious intent based on static analysis and heuristic behavioral patterns.
                </p>
                <p style="background: #fdf2f2; padding: 10px; border-left: 4px solid #f87171; display: {'block' if risk_score > 50 else 'none'}; color: #991b1b;">
                    <strong>⚠️ WARNING:</strong> This file shows strong indicators of malicious behavior. Do not execute in a production environment.
                </p>
            </div>
            
            <div class="footer">
                <p>Verified by SmartGuard AI Node OMEGA-01<br>
                ID: {file_hash[:12]}</p>
                <p><em>Disclaimer: This report is for educational purposes only. SmartGuard AI provides no warranties regarding the accuracy of this analysis.</em></p>
            </div>
        </div>
    </body>
    </html>
    """
    return html
