from recon.subdomain_enum import run_subdomain_enum
from recon.port_scan import run_port_scan
from zap_scanner.zap_scan import zap_scan
from reporting.generate_report import generate_report
from reporting.notifications import send_slack_notification, send_email_notification

def main():
    print("🔹 PentestAutomator - CLI")
    print("1️⃣ Subdomain Enumeration")
    print("2️⃣ Port Scanning")
    print("3️⃣ Run OWASP ZAP Scan")
    print("4️⃣ Generate Report")
    print("5️⃣ Send Notification")
    print("6️⃣ Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        target = input("Enter target domain: ")
        results = run_subdomain_enum([target])
        print(results)

    elif choice == "2":
        target = input("Enter target domain: ")
        results = run_port_scan([target])
        print(results)

    elif choice == "3":
        target = input("Enter target URL: ")
        results = zap_scan(target)
        print(results)

    elif choice == "4":
        target = input("Enter target domain: ")
        generate_report(target)
        print("✅ Report Generated.")

    elif choice == "5":
        msg = input("Enter notification message: ")
        send_slack_notification(msg)
        send_email_notification("security@example.com", msg)
        print("✅ Notification Sent.")

    elif choice == "6":
        exit()

if __name__ == "__main__":
    main()
