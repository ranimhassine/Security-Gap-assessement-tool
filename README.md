# Security Gap Assessment Tool 🛡️

An advanced cybersecurity assessment platform built with Streamlit that helps organizations identify and analyze security gaps across multiple security pillars.

## 🌟 Features

- **Interactive Web Interface**: Built with Streamlit for a smooth user experience
- **Multi-pillar Security Assessment**: Covers five critical security domains:
  - Network Security
  - Endpoint Security
  - Identity & Access Management
  - Logging & Monitoring
  - Cloud Security

- **Comprehensive Analysis**:
  - Real-time gap analysis
  - Automated PDF report generation
  - Visual security posture dashboard
  - Detailed recommendations

## 📋 Prerequisites

```bash
python >= 3.7
streamlit
pandas
matplotlib
fpdf
```

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/security-gap-assessment.git
cd security-gap-assessment
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## 💻 Usage

1. Start the application:
```bash
streamlit run security_assessment.py
```

2. Navigate through the assessment:
   - Log in to the system
   - Fill in company information
   - Complete the security measures assessment
   - Add network device information
   - Generate and download the assessment report

## 🏗️ Structure

The tool follows a structured assessment process:

1. **Company Information**
   - Company details
   - Team size
   - Security infrastructure

2. **Security Measures**
   - Configuration status
   - Implementation details
   - Compliance checks

3. **Network Devices**
   - Device inventory
   - Configuration status

4. **Results & Report**
   - Gap analysis
   - Visual representations
   - Downloadable PDF report

## 📊 Report Generation

The tool generates comprehensive PDF reports including:
- Company profile
- Security posture analysis
- Identified gaps
- Visual representations
- Recommendations

## 🔒 Security Note

This tool is designed for security assessments. Consider implementing:
- Proper authentication mechanisms
- Data encryption
- Access controls
- Regular updates

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ✨ Customization

You can customize the security pillars by modifying the `SECURITY_PILLARS` dictionary in the code:

```python
SECURITY_PILLARS = {
    "Network Security": ["firewall_enabled", "intrusion_detection", "vpn_usage"],
    # Add or modify pillars and controls as needed
}
```

## 🐛 Troubleshooting

Common issues and solutions:

1. **Session Management**
   - Clear browser cache if experiencing session issues
   - Ensure proper logout between sessions

2. **PDF Generation**
   - Verify write permissions in the application directory
   - Check FPDF installation

3. **Visualization**
   - Ensure matplotlib is properly installed
   - Check for proper data formatting


## 🔄 Future Updates

Planned features:
- Custom security control definitions
- Risk scoring system
- API integration capabilities
- Multi-language support
- Advanced reporting options
