# AegisGuardAI

![Python](https://img.shields.io/badge/python-3.8+-blue) ![Version](https://img.shields.io/badge/version-1.0.0-brightgreen) ![License](https://img.shields.io/badge/license-MIT-green)

A professional, modular, and efficient **AI-Powered Cybersecurity Analysis Platform** built using Python and Streamlit. AegisGuardAI supports multi-page analysis, dark/light themes, and comprehensive threat intelligence powered by VirusTotal.

---

## 📁 Project Structure

```
AegisGuardAI/
├── assets/                      # Project assets like CSS and icons
├── data/                        # Data files, including trained models
│   └── models/
│       └── malware_features.pkl
├── modules/                     # Modular backend files (in `utils` directory)
├── pages/                       # Streamlit pages for different features
│   ├── 1_File_Analysis.py
│   ├── 2_Network_Analysis.py
│   ├── 3_Threat_Intelligence.py
│   └── 4_Security_Reports.py
├── utils/                       # Utility and analyzer modules
│   ├── file_analyzer.py
│   ├── ip_analyzer.py
│   ├── ml_detector.py
│   ├── network_analyzer.py
│   ├── report_generator.py
│   ├── threat_intelligence.py
│   ├── train_model.py
│   └── ui_helpers.py
├── app.py                       # Main dashboard application
├── main.py                      # Application entry point (`run.py`)
├── README.md                    # This file
├── LICENSE                      # MIT License
└── requirements.txt             # Python dependencies
```

---

## ⚡ Features

*   **Streamlit-Powered UI**: A clean, modern, and responsive user interface.
*   **Multi-Page Dashboard**: Separate pages for different analysis tasks.
*   **File Analysis**: Upload and analyze files for potential threats.
*   **Network Analysis**: Analyze network logs and identify suspicious activity.
*   **Threat Intelligence**: Look up IPs, domains, and file hashes against VirusTotal.
*   **AI/ML Malware Detection**: Use a trained model to predict if a file is malicious.
*   **Comprehensive Reporting**: Generate and view detailed security reports.
*   **Dark/Light Theme**: A stylish, custom-themed interface.
*   **Modular Python Design**: Clean structure for maintainability and open contribution.


## 🧠 Technical Overview

*   **Framework**: Streamlit
*   **Threat Intelligence**: VirusTotal API
*   **Additional Libraries**: pandas, numpy, plotly, scikit-learn, yara-python
*   **Supported Platforms**: Windows, Linux, macOS
*   **License**: MIT
*   **Current Version**: 1.0.0


## 🚀 Ideal For

*   Cybersecurity students and enthusiasts
*   Developers learning to build security tools with Python and Streamlit
*   Anyone who wants a **powerful, user-friendly security analysis tool** with a professional UI

## 💻 Tagline

"Analyze. Detect. Defend. — AegisGuardAI, your personal AI-powered security dashboard."
---

## 🚀 Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/j3fcruz/AegisGuardAI.git
    cd AegisGuardAI
    ```

2.  Create a virtual environment (recommended):

    ```bash
    python -m venv .venv
    source .venv/bin/activate  # Linux/Mac
    .venv\Scripts\activate     # Windows
    ```

3.  Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4.  Configure your VirusTotal API Key:
    Create a file named `.env` in the project root and add your API key:
    ```
    VT_API_KEY="your_virustotal_api_key_here"
    ```

5.  Run the application:

    ```bash
    python run.py
    ```

> **Note:** A VirusTotal API key is required for the Threat Intelligence feature to work with live data.

---

## 📝 Usage

1.  **Dashboard**: The main page provides a high-level overview of security metrics.
2.  **File Analysis**: Navigate to the "File Analysis" page from the sidebar to upload and scan files.
3.  **Network Analysis**: Go to the "Network Analysis" page to analyze network log files.
4.  **Threat Intelligence**: Use the "Threat Intelligence" page to look up IPs, domains, and file hashes.
5.  **Security Reports**: Visit the "Security Reports" page to generate and view comprehensive reports.

---

## ⚙ Dependencies

```text
streamlit>=1.12.0
pandas>=1.3.3
numpy>=1.21.2
plotly>=5.3.1
requests>=2.26.0
scikit-learn>=1.0.1
yara-python>=4.2.0
python-magic-win64>=0.4.24; sys_platform == 'win32'
python-magic>=0.4.24; sys_platform != 'win32'
pefile>=2021.9.3
streamlit-autorefresh>=0.0.1
streamlit-aggrid>=0.3.3
python-dotenv>=0.19.2
```

Install via pip:

```bash
pip install -r requirements.txt
```

---

## 🧠 Modules Overview

| Module                  | Description                                                    |
| ----------------------- | -------------------------------------------------------------- |
| **file_analyzer.py**    | Handles file analysis, including PE inspection and YARA scanning. |
| **ip_analyzer.py**      | Provides utilities for analyzing IP addresses.                 |
| **ml_detector.py**      | Uses a trained model to predict if a file is malicious.        |
| **network_analyzer.py** | Analyzes network logs for anomalies and suspicious patterns.   |
| **report_generator.py** | Generates comprehensive security reports.                      |
| **threat_intelligence.py**| Looks up IOCs against the VirusTotal database.               |
| **train_model.py**      | A script to train the malware detection model.                 |
| **ui_helpers.py**       | Contains shared UI components and helper functions.            |
| **app.py**              | The main dashboard page.                                       |
| **run.py**              | The entry point to run the Streamlit application.              |

---

## 🛠 Contributing

1.  Fork the repository.
2.  Create a new branch: `git checkout -b feature/YourFeature`.
3.  Make your changes.
4.  Commit: `git commit -m 'Add YourFeature'`.
5.  Push: `git push origin feature/YourFeature`.
6.  Submit a Pull Request.

> Follow PEP8 style and modular conventions.

---

## 📜 License

This project is licensed under the **MIT License**. See the `LICENSE` file for more information.

---

## 👤 Author & Contributors

**PatronHub Development Team**
GitHub: [@j3fcruz](https://github.com/j3fcruz) 
Ko-fi: [@marcopolo55681](https://ko-fi.com/marcopolo55681)

💰 PayPal: [@jecfcruz](https://paypal.me/jofreydelacruz13)  

🪙 Crypto: BTC 1BcWJT8gBdZSPwS8UY39X9u4Afu1nZSzqk,ETH xcd5eef32ff4854e4cefa13cb308b727433505bf4

---

## 🙏 Acknowledgments & Credits

This project stands on the shoulders of amazing open-source projects:

-   **[Streamlit](https://streamlit.io/)** - The fastest way to build and share data apps.
-   **[VirusTotal](https://www.virustotal.com/)** - The threat intelligence service that powers our lookups.
-   **[YARA](https://virustotal.github.io/yara/)** - The pattern matching swiss knife for malware researchers.

We're grateful for these contributions to the open-source community!

---
