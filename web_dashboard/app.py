import streamlit as st
import json

st.title("PentestAutomator Dashboard")

with open("reports/results.json", "r") as f:
    data = json.load(f)

st.subheader("Target: " + data["target"])
st.write("### Subdomains Found")
st.write(data["subdomains"])
st.write("### Open Ports")
st.write(data["open_ports"])
st.write("### OWASP ZAP Vulnerabilities")
st.write(data["vulnerabilities"])

