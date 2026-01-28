# 🛡️ SmartGuard AI: Advanced Network Threat Detection System

SmartGuard AI is a comprehensive network security solution that leverages machine learning and rule-based techniques to identify and mitigate potential security threats in real-time. The system features an interactive dashboard for monitoring network traffic, detecting anomalies, and visualizing potential security incidents.

## 🚀 Key Features

- **Interactive Web Dashboard** - Beautiful, real-time visualization of network traffic and threats
- **Advanced Anomaly Detection** - Multiple ML models including Isolation Forest and Random Forest
- **Real-time Network Analysis** - Live packet capture and analysis
- **Comprehensive Visualization** - Interactive charts and graphs for traffic patterns
- **Threat Intelligence** - Rule-based detection of known attack patterns
- **Modular Architecture** - Easy to extend with new detection algorithms
- **Automated Reporting** - Generate detailed security reports
- **Cross-platform** - Works on Windows, Linux, and macOS

## 🏗️ Project Structure

```
AI-Driven-Threat-Detection-System/
├── data/                   # Data storage
│   ├── raw/               # Raw captured packets
│   └── processed/         # Processed features and datasets
├── docs/                  # Documentation
├── src/                   # Source code
│   ├── config/            # Configuration files
│   ├── core/              # Core functionality
│   ├── dashboard/         # Web dashboard components
│   ├── detection/         # Anomaly detection algorithms
│   ├── features/          # Feature engineering
│   ├── models/            # Model definitions and training
│   ├── utils/             # Utility functions
│   └── main.py            # Main application entry point
├── tests/                 # Unit and integration tests
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## 🛠️ Prerequisites

- Python 3.10+ (recommended: Python 3.11)
- Git
- Required Python packages (see `requirements.txt`)
- Network interface with packet capture permissions (only for live capture)

## 🚀 Quick Start

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Surajmak22/AI-Driven-Threat-Detection-System.git
   cd AI-Driven-Threat-Detection-System
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # On Windows (PowerShell may block this; see Troubleshooting below)
   source venv/bin/activate  # On Linux/Mac
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Phase IV (Production): Enterprise SOC Portal

Phase IV introduces the FastAPI production backend and the unified SOC Monitor dashboard.

### Start the Production System (Windows)

To start both the API and the Dashboard simultaneously, run:

```bat
run_production.bat
```

The script will:
- Launch the **FastAPI Backend** (port 8000)
- Initialize the **Hybrid Ensemble Models** (RF + MLP + Anomaly)
- Open the **SmartGuard AI Portal** (port 8501)

### Manual Launch (CLI)

If you prefer to run services separately:

1. **Start Backend**:
   ```bash
   uvicorn src.api.main:app --host 0.0.0.0 --port 8000
   ```
2. **Start Dashboard**:
   ```bash
   streamlit run src/dashboard/main_app.py
   ```

### Use the Dashboard with CIC-IDS2017

- Upload a CIC-IDS2017 flow CSV (example: `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`)
- Ensure the label column is set to `Label`
- Use the `Max rows to use for training` slider for speed

After training, the Evaluation tab shows:
- metrics (Accuracy/Precision/Recall/F1)
- a confusion matrix (TN/FP/FN/TP)
- quick filters (Actual Attack / Predicted Attack / FP / FN / Low-confidence)

### Dataset placement (recommended)

Datasets are not committed to GitHub.

On each PC, keep datasets in a consistent folder, for example:

```
datasets/
  cicids2017/
    *.csv
```

You can then upload any of those CSV files from the dashboard file picker.

## Cross-dataset / Train-Test Script

The Phase-1 evaluation script is located here:

```bash
python scripts/cross_dataset_evaluation.py --help
```

Use it to run train/test evaluation from CSV files and generate metrics output (for example into `results/`).

## 🖥️ Dashboard Usage

### Starting the Dashboard

```bash
# Install dependencies
pip install -r requirements.txt

# Run the dashboard
python run_dashboard.py
```

Note: `run_dashboard.py` is a legacy launcher for an older dashboard entrypoint. For the Phase-1 demo dashboard, use `start_dashboard.bat`.

Then open your web browser to [http://localhost:8501](http://localhost:8501)

### Dashboard Features

- **Real-time Monitoring**: View live network traffic statistics
- **Anomaly Detection**: Visualize detected anomalies in network traffic
- **Traffic Analysis**: Explore protocol distributions and traffic patterns
- **Threat Intelligence**: View detected threats and their details
- **Export Data**: Save analysis results for further investigation

## ⚙️ Command Line Interface

```bash
# Start capturing network traffic
python src/main.py capture -i <interface> -t <timeout>

# Process captured packets
python src/main.py process -i <input_file> -o <output_file>

# Train the detection model
python src/main.py train -d <dataset> -m <model_output>

# Detect anomalies in network traffic
python src/main.py detect -i <input_file> -m <model_file>

# List available network interfaces
python src/main.py list-interfaces
```

## 🏃 Usage

### 1. Capture Network Traffic

Capture live network traffic from a specific interface:

```bash
python src/main.py capture -i <interface> -t <timeout> -c <packet_count>
```

Example:
```bash
python src/main.py capture -i Ethernet -t 60 -c 1000
```

### 2. Process Captured Packets

Process captured packets and extract features:

```bash
python src/main.py process -i data/raw/capture_20230808_123456.csv
```

### 3. Train the Model

Train the anomaly detection model:

```bash
python src/main.py train -i data/processed/features.csv
```

### 4. Detect Anomalies

Detect anomalies in network traffic:

```bash
python src/main.py detect -i data/processed/live_features.csv
```

## 📊 Features

### Core Components

- **Packet Capture**: Real-time network traffic capture and analysis
- **Feature Engineering**: Advanced feature extraction from network packets
- **Anomaly Detection**: Multiple detection algorithms with configurable thresholds
- **Visualization**: Interactive dashboards for monitoring and analysis

### Advanced Functionality

- Multiple detection algorithms (Isolation Forest, One-Class SVM, etc.)
- Real-time monitoring and alerting
- Historical data analysis
- Custom rule-based detection

## 📚 Documentation

For detailed documentation, please see the [docs](docs/) directory.

## 🤝 Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👩‍💻 Author

Melisa Sever

## 📝 Citation

If you use this project in your research, please cite it as:

```
@misc{smartguardai2023,
  author = {Sever, Melisa},
  title = {SmartGuard AI: Network Threat Detection System},
  year = {2023},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://github.com/Surajmak22/AI-Driven-Threat-Detection-System}}
}
```

## Troubleshooting (Windows)

### PowerShell blocks `Activate.ps1`

If you see:

`running scripts is disabled on this system`

You can avoid activation and just run:

```bat
start_dashboard.bat
```

Or (optional) allow activation for your user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### scikit-learn import blocked (DLL / Application Control)

If `import sklearn` fails with Windows policy blocking `.pyd` files, the quickest fix is to unblock and recreate the venv:

```powershell
Get-ChildItem -Recurse .\venv | Unblock-File
Remove-Item -Recurse -Force .\venv
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```
