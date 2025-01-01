from fpdf import FPDF

def generate_report(scan_results, filename="report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Penetration Testing Report", ln=True, align='C')
    pdf.ln(10)
    
    for line in scan_results:
        pdf.multi_cell(0, 10, txt=line)
    
    pdf.output(filename)
    return f"[INFO] Report saved as {filename}"
