"""
=============================================================================
Dataset Generator: Safe Synthetic Phishing & Legitimate Email Dataset
=============================================================================
Generates 500+ realistic, safe, synthetic emails for defensive cybersecurity
research, training, and awareness education.

IMPORTANT SAFETY & ETHICAL NOTICE:
- All domains used are RFC 2606 / RFC 6761 reserved domains (e.g. example.com,
  example.org, example.net, invalid.test).
- All IP addresses belong to RFC 5737 TEST-NET documentation blocks
  (e.g., 198.51.100.0/24, 203.0.113.0/24).
- NO real credentials, malicious code, or real live targets are utilized.
=============================================================================
"""

import os
import random
import csv
from typing import List, Dict

# Set random seed for reproducibility
random.seed(42)

# ---------------------------------------------------------------------------
# Legitimate Component Pools
# ---------------------------------------------------------------------------
LEGIT_SENDERS = [
    ("Alice Chen (HR Department)", "hr-notifications@example.org"),
    ("Dr. Robert Davis (University Registrar)", "registrar@university.example.edu"),
    ("IT Service Desk", "support@internal-it.example.com"),
    ("Campus Events Coordinator", "events@student-life.example.edu"),
    ("Project Management Office", "pmo-alerts@corp.example.net"),
    ("Payroll & Benefits Team", "benefits@workforce.example.org"),
    ("Library Circulation Desk", "circulation@library.example.edu"),
    ("DevOps Engineering Team", "builds@devops.example.net"),
    ("Online Store Customer Care", "orders@retail.example.com"),
    ("Security Awareness Office", "infosec-training@security.example.org"),
    ("Facilities Management", "facilities@operations.example.net"),
    ("Health & Wellness Center", "wellness@health.example.org"),
    ("Financial Services Portal", "notifications@fictional-bank.example.com"),
    ("Travel & Expense Operations", "expenses@finance.example.org"),
    ("Tech Newsletter Weekly", "newsletter@techdigest.example.net"),
]

LEGIT_TEMPLATES = [
    {
        "category": "university_notice",
        "subjects": [
            "Spring Semester Course Registration Schedule Announced",
            "Campus Library Extended Hours During Final Exam Period",
            "Annual Student Research Symposium Call for Abstracts",
            "Campus Shuttle Schedule Updates for Upcoming Holiday",
            "Academic Calendar and Holiday Closure Notice",
        ],
        "bodies": [
            "Dear Student,\n\nPlease review the updated academic calendar for the upcoming semester. Registration appointment windows have been posted to your student self-service portal at https://portal.university.example.edu/records. If you have any advising holds, please contact your faculty advisor before the deadline.\n\nBest regards,\nOffice of the Registrar",
            "Hello Campus Community,\n\nIn preparation for final examinations, the main library will remain open 24 hours daily starting next Monday. Study rooms can be reserved online through the campus library portal at https://library.example.edu/rooms. Quiet study rules will be enforced throughout the second and third floors.\n\nThank you,\nLibrary Services",
            "Dear Faculty and Students,\n\nSubmissions are now open for the 14th Annual Research Symposium. Undergraduates and graduate researchers are encouraged to submit project abstracts by the end of next month. Review guidelines and presentation templates on our website at https://symposium.example.edu.\n\nWarm regards,\nResearch Committee",
        ],
        "urls": [
            "https://portal.university.example.edu/records",
            "https://library.example.edu/rooms",
            "https://symposium.example.edu/guidelines",
            "",
        ],
        "attachments": ["course_schedule.pdf", "library_hours.pdf", "symposium_guidelines.pdf", ""]
    },
    {
        "category": "hr_update",
        "subjects": [
            "Open Enrollment Period: Health and Wellness Benefits 2026",
            "Reminder: Quarterly Performance Feedback Cycle Begins",
            "Company Holiday Schedule and Office Operations Summary",
            "Upcoming Professional Development Workshops",
            "New Employee Assistance Program (EAP) Resources Available",
        ],
        "bodies": [
            "Dear Team Members,\n\nOur annual benefits open enrollment is now active and will remain open through the 15th of next month. You can review available plan options, compare coverage, and update dependents by visiting our intranet portal at https://workforce.example.org/benefits. If no changes are needed, your current selections will automatically roll over.\n\nSincerely,\nHuman Resources Benefits Team",
            "Hi Everyone,\n\nThis is a friendly reminder that the mid-year feedback cycle starts this week. Please schedule a 30-minute sync with your manager to discuss accomplishments and future development goals. Resources and reflection prompts are available on our knowledge base at https://intranet.example.org/hr/reviews.\n\nBest regards,\nPeople Operations",
            "Dear Colleagues,\n\nPlease note that our offices will be closed next Friday in observance of the statutory holiday. For support staff required to provide coverage, please coordinate schedules with your respective leads. Have a restful weekend!\n\nWarmly,\nOperations & HR",
        ],
        "urls": [
            "https://workforce.example.org/benefits",
            "https://intranet.example.org/hr/reviews",
            "https://wellness.example.org/resources",
            "",
        ],
        "attachments": ["benefits_summary_2026.pdf", "performance_rubric.pdf", "holiday_calendar.xlsx", ""]
    },
    {
        "category": "project_update",
        "subjects": [
            "Sprint Retrospective and Planning Agenda for Tuesday",
            "Release Notes: Version 3.4 Deployment Successful",
            "Design Review Feedback for Mobile Navigation Overhaul",
            "Infrastructure Maintenance Completed Ahead of Schedule",
            "Quarterly Roadmap Alignment Session Summary",
        ],
        "bodies": [
            "Hi Team,\n\nThe sprint retrospective is scheduled for tomorrow at 10:00 AM in Conference Room B and via video link. Please take a moment to add your comments to the retro board at https://jira.internal-it.example.com/sprint-44. Let's celebrate our delivery milestones!\n\nThanks,\nProject Management Office",
            "Hello Engineering,\n\nWe successfully deployed Version 3.4 to production last night. Database migrations completed with zero downtime. You can inspect the detailed change log and monitoring metrics at https://devops.example.net/deployments/v3.4. Great work everyone on this release.\n\nRegards,\nDevOps Team",
            "Dear Stakeholders,\n\nAttached is the slide deck summarizing our key deliverables for Q1 alongside our target roadmap for Q2. Please reply with any feedback before our stakeholder alignment call on Thursday.\n\nBest,\nProduct Management",
        ],
        "urls": [
            "https://jira.internal-it.example.com/sprint-44",
            "https://devops.example.net/deployments/v3.4",
            "https://confluence.corp.example.net/wiki/roadmap",
            "",
        ],
        "attachments": ["sprint_summary.pdf", "release_notes_v3.4.pdf", "roadmap_q2.pptx", ""]
    },
    {
        "category": "shopping_and_finance",
        "subjects": [
            "Your Order #49821 has Shipped - Tracking Details Enclosed",
            "Monthly Account Statement Available for Download",
            "Order Confirmation: Thank You for Your Purchase",
            "Scheduled Service Appointment Confirmation",
            "Your Monthly Utility Statement is Ready to View",
        ],
        "bodies": [
            "Hello Customer,\n\nGood news! Your order #49821 has shipped via standard parcel delivery. You can check the estimated delivery date and transit milestones using our tracking link: https://retail.example.com/orders/49821. If you have questions regarding your package, please visit our customer help portal.\n\nThank you for shopping with us,\nCustomer Experience Team",
            "Dear Valued Client,\n\nYour monthly account statement for the period ending yesterday is now ready to view securely. To review your transaction summary, please log into your account through our official banking application or website at https://fictional-bank.example.com. We will never ask you for your PIN or password via email.\n\nFictional Financial Services",
            "Hello,\n\nThank you for your recent order. We are preparing your items for dispatch. A copy of your itemized receipt has been attached for your records. Feel free to contact our support department if you need any adjustments.\n\nBest,\nRetail Support",
        ],
        "urls": [
            "https://retail.example.com/orders/49821",
            "https://fictional-bank.example.com/statements",
            "https://store.example.com/help",
            "",
        ],
        "attachments": ["order_receipt_49821.pdf", "statement_september.pdf", "invoice_march.pdf", ""]
    },
    {
        "category": "newsletter_and_events",
        "subjects": [
            "Cybersecurity Tech Digest: Top Industry Trends This Week",
            "Invitation: Annual Cybersecurity Awareness Webinar",
            "Campus Wellness Newsletter: Ergonomics in the Workplace",
            "Alumni Network Monthly Spotlight & Career Fair",
            "Library Book Club: Selected Reading for Next Month",
        ],
        "bodies": [
            "Greetings Readers,\n\nWelcome to this week's edition of the Tech Digest! Today we explore zero-trust architecture, defensible network perimeters, and common social engineering techniques. Read the full commentary on our blog at https://techdigest.example.net/issue-89. You can adjust your email delivery preferences at any time.\n\nHappy Reading,\nThe Editorial Staff",
            "Dear Campus Community,\n\nJoin our Information Security team next Wednesday for an interactive seminar on recognizing phishing tactics and safeguarding digital identities. Register at https://security.example.org/webinar-register to receive the meeting invite.\n\nBest,\nInformation Security Office",
        ],
        "urls": [
            "https://techdigest.example.net/issue-89",
            "https://security.example.org/webinar-register",
            "",
        ],
        "attachments": ["infosec_handbook.pdf", "event_flyer.pdf", ""]
    }
]

# ---------------------------------------------------------------------------
# Phishing Component Pools (Fictional, Safe Synthetic Indicators)
# ---------------------------------------------------------------------------
PHISH_SENDERS = [
    ("Account Security Notification", "alert-security@account-check.invalid.test"),
    ("IT Support Verification Desk", "helpdesk-admin@it-portal-verification.invalid.test"),
    ("Executive Payroll Notice", "cfo-office@urgent-exec-wire.invalid.test"),
    ("Banking Security Team", "support@fictional-bank-auth.invalid.test"),
    ("Global Parcel Delivery Dispatch", "tracking-service@express-courier.invalid.test"),
    ("Human Resources Bonus Dept", "payroll-reward@employee-portal-review.invalid.test"),
    ("Cloud Storage Administrator", "quota-warning@cloud-storage-renew.invalid.test"),
    ("Identity Verification Service", "verify@identity-safety-center.invalid.test"),
    ("Tax Refund Authority", "refunds@tax-compliance-review.invalid.test"),
    ("CEO Office / Urgent Request", "executive-task@fast-wire-dispatch.invalid.test"),
    ("System Administrator", "postmaster@mail-server-security.invalid.test"),
    ("Cryptocurrency Giveaway Dept", "rewards@instant-crypto-airdrop.invalid.test"),
]

PHISH_TEMPLATES = [
    {
        "category": "account_verification",
        "subjects": [
            "URGENT: Your Account Has Been Suspended Due to Suspicious Activity",
            "Immediate Action Required: Confirm Your Identity Within 24 Hours",
            "Critical Security Alert: Unauthorized Login Detected on Your Portal",
            "Account Deactivation Notice: Action Required Immediately",
            "FINAL NOTICE: Account Verification Pending Immediate Suspension",
        ],
        "bodies": [
            "Dear Valued Customer,\n\nWe detected unauthorized login attempts to your online account from an unrecognized IP address. To prevent permanent suspension, you must verify your identity immediately. Failure to verify within 24 hours will result in permanent account termination.\n\nClick the link below to verify your password and identity now:\n{URL}\n\nDo not ignore this message. Your security is at risk.\n\nCustomer Support Team",
            "URGENT NOTICE:\n\nYour account credentials have expired. You will lose access to all corporate emails, cloud storage, and payroll portals within 12 hours unless you confirm your password and personal information.\n\nVerify immediately here: {URL}\n\nSystem Administration",
            "Dear user,\n\nOur system detected multiple failed login attempts on your account. To secure your profile, please confirm your current credentials and security questions at our verification portal: {URL}.\n\nIf you do not complete this verification immediately, your account will be locked indefinitely.",
        ],
        "urls": [
            "http://198.51.100.10/verify-account",
            "http://203.0.113.45/login-checkpoint",
            "http://account-verification.invalid.test/auth?token=93821",
            "http://secure-update-credentials.invalid.test/password-reset",
            "http://bit.ly.shortlink.invalid.test/urgent-confirm",
            "http://198.51.100.25/signin/confirm.html",
        ],
        "attachments": ["Security_Verification_Guide.pdf.exe", "Account_Update_Form.scr", "invoice_check.bat", ""]
    },
    {
        "category": "fake_invoice_financial",
        "subjects": [
            "OVERDUE INVOICE #89421: Immediate Payment Required to Avoid Legal Action",
            "Billing Dispute Notification: Outstanding Balance Due Immediately",
            "Wire Transfer Confirmation Needed: Pending Transaction #7721",
            "URGENT: Payment Processing Failed - Account Frozen",
            "Action Required: Unpaid Business Invoice Attached",
        ],
        "bodies": [
            "Attention Accounts Payable,\n\nAttached is the overdue invoice #89421 totaling $4,850.00. Payment is 45 days past due. If funds are not received within 24 hours, this case will be transferred to our legal collections agency with penalty fees applied.\n\nDownload the payment statement here: {URL}\nAlternatively, inspect the attached transaction file immediately.\n\nAccounting Department",
            "Dear Customer,\n\nWe were unable to process your scheduled billing payment. Your services will be terminated by midnight unless you update your credit card and banking details immediately.\n\nUpdate your billing profile at: {URL}\n\nBilling Support",
            "Please find attached the updated corporate invoice for the current billing cycle. Please review the breakdown and submit wire confirmation immediately to avoid disruption.\n\nAccess the portal: {URL}",
        ],
        "urls": [
            "http://198.51.100.88/invoice-download?id=89421",
            "http://financial-records.invalid.test/billing-update",
            "http://203.0.113.12/pay-now/process.php",
            "http://urgent-invoice-portal.invalid.test/settle",
        ],
        "attachments": ["Invoice_89421.pdf.exe", "Overdue_Statement.js", "Payment_Receipt.vbs", "invoice_march.zip"]
    },
    {
        "category": "fake_hr_payroll",
        "subjects": [
            "MANDATORY: HR Policy Update and Annual Bonus Direct Deposit Form",
            "Urgent: Action Required on Your Payroll Benefits Account",
            "All Staff: Immediate Review of Revised Employee Handbook",
            "HR Department: Confirm Your Bank Account Information for Tax Refund",
            "Confidential Employee Bonus Notification - Open Immediately",
        ],
        "bodies": [
            "Dear Employee,\n\nOur human resources department is transitioning to a new payroll disbursement platform. All staff members must log in and confirm their banking details, social security number, and direct deposit routing information before the end of the day to ensure payroll is processed on time.\n\nAccess the employee self-service portal: {URL}\n\nHuman Resources Division",
            "Attention Staff,\n\nPlease review the attached mandatory update regarding health coverage and bonus allocations. To claim your quarterly bonus disbursement, you must complete the authorization form at: {URL}.\n\nHR People Team",
        ],
        "urls": [
            "http://198.51.100.99/hr-portal/login.html",
            "http://employee-benefits-review.invalid.test/update",
            "http://payroll-verification-portal.invalid.test/auth",
            "http://203.0.113.77/hr/direct-deposit.php",
        ],
        "attachments": ["Bonus_Enrollment_Form.docm", "Employee_Handbook_2026.pdf.exe", "HR_Payroll_Form.scr", ""]
    },
    {
        "category": "fake_delivery_package",
        "subjects": [
            "Courier Service: Delivery Attempt Failed - Action Required",
            "Package #US-98214 Pending Dispatch - Customs Clearance Fee Due",
            "Urgent Delivery Notification: Confirm Your Mailing Address",
            "Delivery Rescheduling Notice: Immediate Confirmation Requested",
        ],
        "bodies": [
            "Dear Customer,\n\nOur courier was unable to deliver your package #US-98214 today because the delivery address provided was incomplete. A redelivery fee of $2.50 must be paid immediately to release the parcel from our regional warehouse.\n\nConfirm your delivery address and pay clearance fee: {URL}\nIf unclaimed within 48 hours, package will be returned to sender.\n\nGlobal Express Dispatch",
            "Notice: Your parcel is currently held at our sorting facility. Please verify your identity and confirm your shipping details at {URL} to schedule redelivery.",
        ],
        "urls": [
            "http://198.51.100.33/package-tracking/confirm",
            "http://express-courier-portal.invalid.test/tracking?pkg=98214",
            "http://203.0.113.91/delivery-fee/verify",
        ],
        "attachments": ["Delivery_Receipt_US98214.pdf.exe", "Tracking_Label.cmd", "Shipping_Manifest.js", ""]
    },
    {
        "category": "executive_wire_fraud",
        "subjects": [
            "URGENT & CONFIDENTIAL: Wire Transfer Request from CEO",
            "Quick Task - Are You at Your Desk Right Now?",
            "Immediate Assistance Required - Highly Confidential Project",
            "Request for Urgent Wire Transfer - Vendor Settlement",
        ],
        "bodies": [
            "Hello,\n\nI am currently in an urgent offsite executive board meeting with limited phone access. We have an acquisition milestone that requires an urgent wire transfer to be dispatched before the market closes today.\n\nPlease reply immediately or click the secure executive authorization link to review the vendor disbursement details: {URL}\n\nTreat this with the highest confidentiality. Do not mention this to other team members yet.\n\nChief Executive Officer",
            "Hi,\n\nAre you available to process an urgent wire today? I need you to confirm supplier bank details right away. Check the details on the vendor portal: {URL}.\n\nThanks,\nCEO Office",
        ],
        "urls": [
            "http://198.51.100.150/executive-auth/transfer",
            "http://board-director-tasks.invalid.test/wire-portal",
            "http://203.0.113.111/ceo-disbursement",
        ],
        "attachments": ["Wire_Instructions_Confidential.pdf.exe", "Vendor_Contract.bat", ""]
    }
]

def generate_synthetic_dataset(target_count: int = 550, output_path: str = "data/phishing_email_dataset.csv") -> List[Dict]:
    """
    Generates a balanced dataset of synthetic legitimate and phishing emails.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    emails = []
    
    half_count = target_count // 2
    
    # 1. Generate Legitimate Emails
    for i in range(half_count):
        tmpl = random.choice(LEGIT_TEMPLATES)
        sender_name, sender_email = random.choice(LEGIT_SENDERS)
        domain = sender_email.split("@")[1]
        subject = random.choice(tmpl["subjects"])
        body = random.choice(tmpl["bodies"])
        url = random.choice(tmpl["urls"])
        attachment = random.choice(tmpl["attachments"])
        
        # Occasional variation
        if random.random() < 0.2:
            body += f"\n\nRef ID: LGT-{random.randint(10000, 99999)}"
            
        emails.append({
            "email_id": f"EML-LGT-{i+1:04d}",
            "sender": f"{sender_name} <{sender_email}>",
            "sender_domain": domain,
            "subject": subject,
            "body": body,
            "urls": url,
            "attachment_name": attachment,
            "label": "LEGITIMATE"
        })
        
    # 2. Generate Phishing Emails
    for i in range(target_count - half_count):
        tmpl = random.choice(PHISH_TEMPLATES)
        sender_name, sender_email = random.choice(PHISH_SENDERS)
        domain = sender_email.split("@")[1]
        subject = random.choice(tmpl["subjects"])
        raw_body = random.choice(tmpl["bodies"])
        url = random.choice(tmpl["urls"])
        attachment = random.choice(tmpl["attachments"])
        
        body = raw_body.replace("{URL}", url)
        
        # Occasional extra manipulation keywords or caps
        if random.random() < 0.3:
            body += f"\n\nWARNING: Failure to respond will result in immediate legal penalties and permanent suspension. Ref #{random.randint(100000, 999999)}."
            
        emails.append({
            "email_id": f"EML-PHS-{i+1:04d}",
            "sender": f"{sender_name} <{sender_email}>",
            "sender_domain": domain,
            "subject": subject,
            "body": body,
            "urls": url,
            "attachment_name": attachment,
            "label": "PHISHING"
        })
        
    # Shuffle for realistic distribution
    random.shuffle(emails)
    
    # Write to CSV
    fieldnames = [
        "email_id", "sender", "sender_domain", "subject",
        "body", "urls", "attachment_name", "label"
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(emails)
        
    print(f"[+] Successfully generated {len(emails)} synthetic email records.")
    print(f"[+] Legitimate records: {half_count}, Phishing records: {target_count - half_count}")
    print(f"[+] Dataset saved to: {output_path}")
    return emails

if __name__ == "__main__":
    generate_synthetic_dataset(target_count=600, output_path="data/phishing_email_dataset.csv")
