import json
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from fpdf import FPDF
from datetime import datetime

# Predefined security pillars
SECURITY_PILLARS = {
    "Network Security": ["firewall_enabled", "intrusion_detection", "vpn_usage"],
    "Endpoint Security": ["endpoint_protection", "patching_up_to_date", "device_encryption"],
    "Identity & Access Management": ["multi_factor_auth", "privileged_access", "password_policy"],
    "Logging & Monitoring": ["logging_enabled", "siem_implementation", "incident_response"],
    "Cloud Security": ["cloud_security_configured", "data_encryption", "cloud_compliance"]
}

def authenticate(username, password):
    """Always return True for any username and password combination."""
    return True

def analyze_security_gaps(client_data):
    """Compare client security posture with security pillars and identify gaps."""
    gaps = {}
    for pillar, controls in SECURITY_PILLARS.items():
        for control in controls:
            actual_value = client_data.get(control, None)
            if actual_value is None:
                gaps[control] = "Not Implemented"
            elif not actual_value:
                gaps[control] = "Non-Compliant"
    return gaps

def generate_pdf_report(client_data, gaps):
    """Generate a PDF report with security posture details and gaps."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Security Gap Assessment Report", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    
    pdf.cell(200, 10, "Security Posture Details:", ln=True)
    for key, value in client_data.items():
        pdf.cell(200, 10, f"{key.replace('_', ' ').title()}: {value}", ln=True)
    pdf.ln(10)
    
    pdf.cell(200, 10, "Identified Security Gaps:", ln=True)
    for control, description in gaps.items():
        pdf.cell(200, 10, f"- {control.replace('_', ' ').title()}: {description}", ln=True)
    pdf.ln(10)
    
    report_filename = "security_gap_report.pdf"
    pdf.output(report_filename)
    return report_filename

def visualize_security_posture(client_data):
    """Generate a bar chart to visualize security posture."""
    df = pd.DataFrame(client_data.items(), columns=["Security Control", "Status"])
    df["Status"] = df["Status"].apply(lambda x: "Compliant" if x else "Non-Compliant")
    fig, ax = plt.subplots()
    df["Status"].value_counts().plot(kind="bar", ax=ax, color=["green", "red"])
    plt.title("Security Posture Overview")
    plt.xlabel("Compliance Status")
    plt.ylabel("Count")
    st.pyplot(fig)

def main():
    """Streamlit UI for advanced security gap assessment tool with login system and sidebar navigation."""
    st.set_page_config(page_title="Security Gap Assessment", layout="wide")
    
    # Initialize session state for login
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    
    # Login page
    if not st.session_state.logged_in:
        st.title("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if authenticate(username, password):
                st.session_state.logged_in = True
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid username or password")
        return
    
    # Initialize client data in session state if not exists
    if "client_data" not in st.session_state:
        st.session_state.client_data = {}
    
    # Main navigation after login
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Company Information", "Security Measures", "Network Devices", "Results & Report"])
    
    # Logout button in sidebar
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.client_data = {}
        st.rerun()
    
    if page == "Company Information":
        st.title("Company Information")
        st.session_state.client_data["company_name"] = st.text_input(
            "Company Name",
            value=st.session_state.client_data.get("company_name", "")
        )
        st.session_state.client_data["company_size"] = st.selectbox(
            "Company Size",
            ["Small", "Medium", "Large"],
            index=["Small", "Medium", "Large"].index(st.session_state.client_data.get("company_size", "Small"))
        )
        st.session_state.client_data["security_team_size"] = st.number_input(
            "Number of Security Team Members",
            min_value=0,
            step=1,
            value=st.session_state.client_data.get("security_team_size", 0)
        )
    
    elif page == "Security Measures":
        st.title("Security Measures")
        for pillar, controls in SECURITY_PILLARS.items():
            st.subheader(pillar)
            for control in controls:
                st.session_state.client_data[control] = st.radio(
                    f"Is {control.replace('_', ' ')} enabled?",
                    [True, False],
                    index=0 if st.session_state.client_data.get(control, False) else 1
                )
    
    elif page == "Network Devices":
        st.title("Network Devices")
        devices = st.text_area(
            "List the network devices in use (comma-separated)",
            value=",".join(st.session_state.client_data.get("network_devices", []))
        )
        st.session_state.client_data["network_devices"] = devices.split(",") if devices else []
        
    elif page == "Results & Report":
        st.title("Security Gap Assessment Results")
        gaps = analyze_security_gaps(st.session_state.client_data)
        
        if gaps:
            st.subheader("Identified Security Gaps:")
            for control, description in gaps.items():
                st.write(f"- **{control.replace('_', ' ')}**: {description}")
            
            report_file = generate_pdf_report(st.session_state.client_data, gaps)
            with open(report_file, "rb") as file:
                st.download_button(
                    label="Download PDF Report",
                    data=file,
                    file_name=report_file,
                    mime="application/pdf"
                )
        else:
            st.success("No security gaps identified. The client's security posture is strong.")
        
        st.subheader("Security Posture Visualization")
        visualize_security_posture(st.session_state.client_data)

if __name__ == "__main__":
    main()
