from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import desc

logger = logging.getLogger("cyberassetiq.training")

# ---------------------------------------------------------------------------
# Seed data — 5 real cybersecurity training modules
# ---------------------------------------------------------------------------

SEED_MODULES: list[dict] = [
    {
        "title": "Phishing & Social Engineering",
        "category": "Threat Awareness",
        "difficulty": "Beginner",
        "estimated_minutes": 15,
        "pass_mark": 80,
        "description": "Learn to recognise phishing emails, spear-phishing, and social engineering tactics used to compromise UK SMEs.",
        "content_html": """
<h3>What is Phishing?</h3>
<p>Phishing is a cyberattack where criminals impersonate a trusted organisation — a bank, HMRC, Microsoft, or a supplier — to trick you into revealing credentials, clicking malicious links, or transferring money.</p>
<p>In 2023, 84% of UK organisations reported experiencing a phishing attempt (DCMS Cyber Security Breaches Survey). For SMEs, a single successful phishing attack costs an average of £65,000.</p>

<h3>Types of Phishing</h3>
<ul>
<li><strong>Mass phishing</strong> — generic emails sent to millions of addresses. Easy to spot if you know what to look for.</li>
<li><strong>Spear phishing</strong> — targeted attack using your name, job title, or company details. Much more convincing.</li>
<li><strong>Whaling</strong> — spear phishing aimed specifically at senior executives or finance staff.</li>
<li><strong>Smishing</strong> — phishing via SMS. Fake parcel delivery notifications are the most common.</li>
<li><strong>Vishing</strong> — phishing via phone call. Attackers impersonate banks or HMRC.</li>
</ul>

<h3>Red Flags to Spot</h3>
<ul>
<li><strong>Urgency</strong> — "Your account will be suspended in 24 hours." Legitimate organisations do not rush you.</li>
<li><strong>Sender mismatch</strong> — the display name says "HMRC" but the email address is hmrc-refund@gmail.com.</li>
<li><strong>Hover before you click</strong> — hover over any link to see the real URL. If it doesn't match the claimed sender, do not click.</li>
<li><strong>Unexpected attachments</strong> — never open .exe, .zip, or Office files with macros from unexpected senders.</li>
<li><strong>Requests for credentials</strong> — no legitimate service will ask for your password via email.</li>
</ul>

<h3>What to Do If You Suspect Phishing</h3>
<ul>
<li>Do NOT click any links or open any attachments.</li>
<li>Report the email to your IT team or manager immediately.</li>
<li>If you clicked a link or entered credentials, assume you are compromised — change passwords and notify IT immediately.</li>
<li>Forward suspicious emails to report@phishing.gov.uk (NCSC service).</li>
</ul>

<h3>Social Engineering</h3>
<p>Social engineering is the broader art of manipulating people into taking actions that benefit the attacker. Common tactics include:</p>
<ul>
<li><strong>Pretexting</strong> — creating a false scenario ("I'm from IT support and need your password to fix an issue").</li>
<li><strong>Baiting</strong> — leaving a USB drive in a car park labelled "Payroll Q4" hoping someone plugs it in.</li>
<li><strong>Tailgating</strong> — following an authorised person through a secure door.</li>
</ul>
<p><strong>Remember:</strong> No legitimate IT team, bank, or government body will ever ask for your password — by phone, email, or in person.</p>
""",
        "questions_json": [
            {
                "question": "An email from 'HMRC Refunds <hmrc-refund2024@gmail.com>' asks you to click a link to claim a tax refund. What should you do?",
                "options": [
                    "Click the link — it sounds like a legitimate HMRC communication",
                    "Do not click; the sender domain is gmail.com not hmrc.gov.uk — report it as phishing",
                    "Forward it to your colleagues to see if they received it too",
                    "Reply asking HMRC to confirm it is genuine"
                ],
                "correct_index": 1,
                "explanation": "The sender domain is gmail.com, not hmrc.gov.uk. HMRC only communicates from gov.uk domains. This is a classic phishing attempt — report it to report@phishing.gov.uk."
            },
            {
                "question": "What is 'spear phishing'?",
                "options": [
                    "A generic phishing email sent to millions of recipients",
                    "Phishing conducted via SMS text message",
                    "A targeted phishing attack using personal details about the victim",
                    "Phishing aimed at stealing credit card numbers"
                ],
                "correct_index": 2,
                "explanation": "Spear phishing uses personal details — your name, job title, company, or recent activities — to craft a convincing targeted attack. It is far more dangerous than generic mass phishing."
            },
            {
                "question": "You receive an unexpected call from someone claiming to be from your bank's fraud team. They say your account is compromised and ask you to confirm your online banking password to verify your identity. What do you do?",
                "options": [
                    "Provide the password — protecting your account is urgent",
                    "Refuse to give the password; hang up and call the bank back on the number on their official website",
                    "Give the first two characters of the password as a security check",
                    "Ask them to send an email instead"
                ],
                "correct_index": 1,
                "explanation": "Banks never ask for full passwords over the phone. Hang up and call back on the official number from the bank's website — not a number the caller gives you."
            },
            {
                "question": "A colleague finds a USB drive labelled 'Q4 Salaries' in the office car park. What is the correct action?",
                "options": [
                    "Plug it into their computer to find out whose it is",
                    "Hand it to the IT team without plugging it in — it may be a baiting attack",
                    "Plug it into a personal laptop to check it safely",
                    "Leave it where it was found"
                ],
                "correct_index": 1,
                "explanation": "Dropping labelled USB drives in car parks is a known social engineering technique called baiting. Never plug in an unknown USB device. Hand it to IT for safe inspection."
            },
            {
                "question": "Which of the following is the strongest indicator that an email is a phishing attempt?",
                "options": [
                    "The email contains your first name",
                    "The email asks you to take action urgently and the link URL does not match the claimed sender's domain",
                    "The email has a company logo",
                    "The email arrives outside business hours"
                ],
                "correct_index": 1,
                "explanation": "Urgency combined with a mismatched link URL is the strongest phishing indicator. Logos are trivial to copy. Arriving outside hours or containing your name alone are not reliable indicators."
            }
        ]
    },
    {
        "title": "Password Security & Multi-Factor Authentication",
        "category": "Access Control",
        "difficulty": "Beginner",
        "estimated_minutes": 10,
        "pass_mark": 80,
        "description": "Understand what makes a password strong, why MFA is essential, and how to use a password manager.",
        "content_html": """
<h3>Why Passwords Matter</h3>
<p>Weak or reused passwords are the leading cause of account compromise. In 2023, credential stuffing attacks — where stolen passwords from one breach are tried against other services — affected millions of UK accounts.</p>
<p>The most common passwords in UK breaches are still: <em>123456, password, qwerty, liverpool, letmein</em>. If yours is on this list, change it immediately.</p>

<h3>What Makes a Strong Password?</h3>
<ul>
<li><strong>Length over complexity</strong> — a 16-character passphrase is stronger than an 8-character mix of symbols. Three random words (e.g. <em>correct-horse-battery</em>) are excellent.</li>
<li><strong>Uniqueness</strong> — every account must have a different password. Reusing passwords means one breach compromises everything.</li>
<li><strong>No personal information</strong> — avoid names, birthdays, pet names, or football teams. Attackers use this information.</li>
</ul>

<h3>Password Managers</h3>
<p>A password manager generates and stores unique, strong passwords for every account. You only need to remember one master password.</p>
<p>Recommended options (all have free tiers): <strong>Bitwarden</strong> (open source), <strong>1Password</strong>, <strong>KeePassXC</strong> (offline). The NCSC endorses password managers for both personal and business use.</p>

<h3>Multi-Factor Authentication (MFA)</h3>
<p>MFA adds a second verification step after your password. Even if your password is stolen, the attacker cannot access your account without the second factor.</p>
<ul>
<li><strong>Authenticator apps</strong> (most secure) — Microsoft Authenticator, Google Authenticator, Authy generate a time-based code.</li>
<li><strong>SMS codes</strong> — better than nothing, but vulnerable to SIM-swap attacks. Avoid for critical accounts.</li>
<li><strong>Hardware keys</strong> (most secure for high-risk accounts) — YubiKey physically proves your presence.</li>
</ul>
<p><strong>Enable MFA on every account that supports it</strong>, especially: email, banking, Microsoft 365, cloud services, and any system containing customer data.</p>

<h3>Cyber Essentials Requirement</h3>
<p>Cyber Essentials v3.2 requires that all user accounts use strong passwords and that MFA is enabled for all remote access and cloud services. Failure to meet this control will result in audit failure.</p>
""",
        "questions_json": [
            {
                "question": "Which of the following is the strongest password?",
                "options": [
                    "P@ssw0rd1!",
                    "liverpool1892",
                    "correct-horse-battery-staple",
                    "Tr0ub4dor&3"
                ],
                "correct_index": 2,
                "explanation": "A long passphrase (correct-horse-battery-staple, 28 characters) is stronger than shorter complex passwords. Length is the primary driver of password strength."
            },
            {
                "question": "You use the same password for your work email and your online banking. Why is this a serious risk?",
                "options": [
                    "It is not a risk — using the same password makes it easier to remember",
                    "If either service is breached, attackers can use the stolen password to access the other account",
                    "It is only a risk if the password contains personal information",
                    "It is a risk only if you share the password with colleagues"
                ],
                "correct_index": 1,
                "explanation": "Password reuse enables credential stuffing attacks. When one service is breached, attackers automatically try the stolen credentials against thousands of other sites."
            },
            {
                "question": "What is the safest form of Multi-Factor Authentication for a business cloud account?",
                "options": [
                    "SMS text message code",
                    "Security question (e.g. mother's maiden name)",
                    "Authenticator app generating a time-based code",
                    "Email verification code"
                ],
                "correct_index": 2,
                "explanation": "Authenticator apps are more secure than SMS (which is vulnerable to SIM-swap) or email (which may itself be compromised). Hardware keys are even stronger but authenticator apps are the practical standard."
            },
            {
                "question": "The NCSC recommends which approach to managing multiple strong passwords?",
                "options": [
                    "Write passwords in a notebook kept in your desk drawer",
                    "Use a password manager",
                    "Use a single strong master password for all accounts",
                    "Change all passwords every 30 days"
                ],
                "correct_index": 1,
                "explanation": "The NCSC explicitly recommends password managers as the best way to use unique, strong passwords for every account without needing to memorise them all."
            },
            {
                "question": "Under Cyber Essentials v3.2, MFA is required for which type of access?",
                "options": [
                    "Only administrator accounts",
                    "Only financial systems",
                    "All remote access and cloud services",
                    "MFA is not a CE requirement"
                ],
                "correct_index": 2,
                "explanation": "CE v3.2 requires MFA for all remote access (VPN, RDP) and cloud services. This is a mandatory control — failure to implement it will result in CE audit failure."
            }
        ]
    },
    {
        "title": "Cyber Essentials: What Your Organisation Needs to Know",
        "category": "Compliance",
        "difficulty": "Intermediate",
        "estimated_minutes": 20,
        "pass_mark": 80,
        "description": "Understand the five Cyber Essentials controls, why certification matters for UK SMEs, and what auditors check.",
        "content_html": """
<h3>What is Cyber Essentials?</h3>
<p>Cyber Essentials is a UK government-backed cybersecurity certification scheme developed by the NCSC (National Cyber Security Centre). It defines five fundamental technical controls that protect against the most common cyber threats.</p>
<p>CE certification is mandatory for UK government contracts over £25,000 involving sensitive information. It is increasingly required by NHS suppliers, insurers, and large enterprise procurement teams.</p>

<h3>The Five Controls</h3>

<h4>A1 — Firewalls (Boundary Firewalls and Internet Gateways)</h4>
<p>All devices must be protected by a correctly configured firewall. For CE v3.2, this includes home worker devices and cloud services. Unnecessary inbound ports must be blocked. The firewall must be password protected with default credentials changed.</p>

<h4>A2 — Secure Configuration</h4>
<p>All devices and software must be securely configured before use. Default passwords must be changed. Unnecessary software, accounts, and services must be removed or disabled. Auto-run features for removable media must be disabled.</p>

<h4>A3 — User Access Control</h4>
<p>User accounts must be created only for people who need them. Users must have only the privileges they need for their role (principle of least privilege). Administrative accounts must only be used for administrative tasks — not for web browsing or email. MFA is required for all cloud services and remote access.</p>

<h4>A4 — Malware Protection</h4>
<p>All in-scope devices must be protected against malware. Acceptable methods include: anti-malware software, application whitelisting, or sandboxing. CE v3.2 accepts Windows Defender and similar built-in tools as compliant.</p>

<h4>A5 — Patch Management (Software Updates)</h4>
<p>All software on in-scope devices must be licensed and supported. Critical patches must be applied within 14 days of release. Unsupported software (e.g. Windows 7, Office 2010) must be removed or isolated. This is the control most commonly failed in initial audits.</p>

<h3>CE v3.2 Changes (April 2025)</h3>
<p>The most significant change in v3.2 is the expanded asset inventory requirement. Organisations must now maintain a complete, up-to-date register of all in-scope devices — including cloud instances, home worker laptops, and BYOD devices. Manual spreadsheets are no longer considered sufficient for larger organisations.</p>

<h3>Cyber Essentials Plus</h3>
<p>CE+ involves a hands-on technical verification by an assessor who remotely tests your controls rather than relying on self-assessment. CE+ is required for some NHS contracts and higher-value government work.</p>

<h3>Cost and Frequency</h3>
<p>CE self-assessment costs approximately £300–450 for most SMEs. Certification is valid for 12 months and must be renewed annually. Re-certification requires demonstrating continued compliance — not starting from scratch.</p>
""",
        "questions_json": [
            {
                "question": "Under Cyber Essentials v3.2, critical security patches must be applied within how many days of release?",
                "options": [
                    "30 days",
                    "14 days",
                    "7 days",
                    "90 days"
                ],
                "correct_index": 1,
                "explanation": "CE v3.2 requires critical patches to be applied within 14 days of release. This is the most commonly failed control in initial CE audits."
            },
            {
                "question": "Which of the following is NOT one of the five Cyber Essentials controls?",
                "options": [
                    "Firewalls",
                    "Penetration Testing",
                    "Patch Management",
                    "Secure Configuration"
                ],
                "correct_index": 1,
                "explanation": "The five CE controls are: Firewalls, Secure Configuration, User Access Control, Malware Protection, and Patch Management. Penetration testing is part of CHECK and other schemes, not CE."
            },
            {
                "question": "What was the most significant new requirement introduced in Cyber Essentials v3.2?",
                "options": [
                    "Mandatory penetration testing",
                    "Requirement for ISO 27001 certification",
                    "Expanded asset inventory requirements covering cloud and home worker devices",
                    "Requirement to encrypt all email communications"
                ],
                "correct_index": 2,
                "explanation": "CE v3.2 (April 2025) significantly expanded the asset inventory requirement to include cloud instances, home worker devices, and BYOD. Manual spreadsheets are no longer sufficient."
            },
            {
                "question": "Under the User Access Control requirement, when should an administrator account be used?",
                "options": [
                    "For all daily tasks including email and web browsing to save time",
                    "Only for administrative tasks — not for email, web browsing, or general work",
                    "Only when installing new software",
                    "Whenever the user needs elevated permissions temporarily"
                ],
                "correct_index": 1,
                "explanation": "CE requires that admin accounts are used exclusively for admin tasks. Using an admin account for daily work dramatically increases the impact of a malware infection or phishing attack."
            },
            {
                "question": "How long is a Cyber Essentials certification valid?",
                "options": [
                    "2 years",
                    "3 years",
                    "12 months",
                    "6 months"
                ],
                "correct_index": 2,
                "explanation": "CE certification is valid for 12 months and must be renewed annually. The renewal process checks continued compliance rather than requiring a full reassessment from scratch."
            }
        ]
    },
    {
        "title": "API Keys & Credential Security",
        "category": "Developer Security",
        "difficulty": "Intermediate",
        "estimated_minutes": 15,
        "pass_mark": 80,
        "description": "Understand how API keys and credentials get leaked, the real-world consequences, and how to store and manage them securely.",
        "content_html": """
<h3>What Are API Keys?</h3>
<p>An API key is a secret string that grants access to a service — AWS, Stripe, GitHub, Slack, OpenAI, and thousands of others. They function like passwords for machine-to-machine communication. A leaked API key is as dangerous as a leaked password — sometimes more so, because they often grant access to billing, customer data, or infrastructure.</p>

<h3>How API Keys Get Leaked</h3>
<p>The most common causes of API key exposure:</p>
<ul>
<li><strong>Committed to version control</strong> — hardcoding keys directly in source code and pushing to GitHub. Public repositories are automatically scanned by attackers within seconds of any commit.</li>
<li><strong>Left in configuration files</strong> — .env files, config.json, or settings.py accidentally included in deployments or repositories.</li>
<li><strong>Included in client-side code</strong> — embedding API keys in JavaScript served to browsers exposes them to any visitor.</li>
<li><strong>Shared via insecure channels</strong> — sending keys via Slack, email, or WhatsApp. These platforms are frequently breached or misconfigured.</li>
<li><strong>Logged by applications</strong> — if your application logs request headers or parameters, API keys may end up in log files.</li>
</ul>

<h3>Real-World Consequences</h3>
<p>From the founder's experience conducting 30+ SME security audits, API key exposures were found in 78% of environments. Consequences observed include:</p>
<ul>
<li>AWS keys used by attackers to spin up crypto-mining infrastructure — costs of £15,000–50,000 before detection.</li>
<li>Stripe keys used to issue refunds to attacker-controlled accounts.</li>
<li>GitHub tokens used to access private repositories and exfiltrate source code.</li>
<li>Slack webhook URLs used to send phishing messages to employees from internal-looking sources.</li>
</ul>

<h3>Secure Key Management</h3>
<ul>
<li><strong>Never hardcode keys</strong> — use environment variables (.env files) that are excluded from version control via .gitignore.</li>
<li><strong>Use secrets management services</strong> — AWS Secrets Manager, Azure Key Vault, HashiCorp Vault for production environments.</li>
<li><strong>Rotate keys regularly</strong> — treat API keys like passwords. Rotate them every 90 days and immediately upon any suspected exposure.</li>
<li><strong>Use least privilege</strong> — create keys with the minimum permissions needed. A key for reading S3 should not also have permission to create EC2 instances.</li>
<li><strong>Monitor for exposure</strong> — use tools that scan your repositories and endpoints for accidentally committed secrets.</li>
</ul>

<h3>What to Do If a Key Is Compromised</h3>
<ol>
<li>Revoke the key immediately via the service's dashboard — do not wait.</li>
<li>Generate a new key and update all systems using the old key.</li>
<li>Review the service's access logs for any suspicious activity during the exposure window.</li>
<li>Report the incident to your security team or manager.</li>
<li>Assess whether any customer data may have been accessed — this may trigger GDPR notification requirements.</li>
</ol>
""",
        "questions_json": [
            {
                "question": "A developer accidentally commits a Stripe API key to a public GitHub repository. What is the correct first action?",
                "options": [
                    "Delete the commit from Git history — this removes the exposure",
                    "Revoke the key immediately via Stripe's dashboard, then rotate to a new key",
                    "Make the repository private to prevent further exposure",
                    "Wait to see if any fraudulent activity occurs before acting"
                ],
                "correct_index": 1,
                "explanation": "Revoke the key immediately. Deleting from Git history does not help — automated scanners capture public commits within seconds. Making the repo private also does not help if it was already scanned. Assume the key is compromised from the moment of commit."
            },
            {
                "question": "What is the safest way to store an API key used by a web application?",
                "options": [
                    "Hardcode it directly in the application source code",
                    "Store it in an environment variable, excluded from version control via .gitignore",
                    "Include it in the client-side JavaScript so the application can use it",
                    "Store it in a database table alongside other configuration"
                ],
                "correct_index": 1,
                "explanation": "Environment variables stored outside the codebase and excluded from version control is the correct approach. Client-side JavaScript is served to every browser visitor — never put secrets there."
            },
            {
                "question": "According to the principle of least privilege, how should an API key's permissions be configured?",
                "options": [
                    "Grant full admin access so it never needs to be changed",
                    "Grant only the minimum permissions required for the specific task",
                    "Grant read-only access to all resources by default",
                    "Match the permissions of the developer who created it"
                ],
                "correct_index": 1,
                "explanation": "Least privilege means granting only what is needed. A key that only reads from S3 should not also have permission to delete buckets or create EC2 instances. This limits the blast radius if the key is compromised."
            },
            {
                "question": "A leaked AWS key is used by attackers to run crypto-mining operations. Who is responsible for the resulting charges?",
                "options": [
                    "AWS — they should detect and block the usage",
                    "The attacker — they incurred the charges fraudulently",
                    "The organisation that owned the compromised key",
                    "The developer who wrote the code"
                ],
                "correct_index": 2,
                "explanation": "AWS charges are the responsibility of the account owner. AWS may offer goodwill credits in some cases but is not obligated to. Organisations have lost tens of thousands of pounds to crypto-mining attacks via leaked keys."
            },
            {
                "question": "How frequently should API keys be rotated as a security best practice?",
                "options": [
                    "Never — rotation breaks applications and should be avoided",
                    "Only when a breach is suspected",
                    "Every 90 days as standard, and immediately upon any suspected exposure",
                    "Annually, in line with password policy"
                ],
                "correct_index": 2,
                "explanation": "Regular 90-day rotation limits the window of opportunity for an attacker who has obtained a key. Immediate rotation upon suspected exposure is non-negotiable."
            }
        ]
    },
    {
        "title": "Secure Remote Working",
        "category": "Operational Security",
        "difficulty": "Beginner",
        "estimated_minutes": 10,
        "pass_mark": 80,
        "description": "Essential security practices for working from home or remotely — covering home networks, VPNs, device security, and physical security.",
        "content_html": """
<h3>Why Remote Working Increases Risk</h3>
<p>Remote workers operate outside the corporate network perimeter — typically without enterprise firewalls, network monitoring, or IT oversight. The shift to remote working has significantly expanded the attack surface for UK SMEs. Common threats include unsecured home Wi-Fi, use of personal devices for work, and shoulder-surfing in public places.</p>

<h3>Home Network Security</h3>
<ul>
<li><strong>Change your router's default admin password</strong> — most home routers ship with the same default credentials (admin/admin or admin/password), which are publicly documented.</li>
<li><strong>Use WPA3 or WPA2 encryption</strong> — never WEP (obsolete and broken). Check your router settings.</li>
<li><strong>Keep router firmware updated</strong> — routers contain vulnerabilities that vendors patch. Enable auto-update if available.</li>
<li><strong>Use a separate guest network for IoT devices</strong> — smart TVs, thermostats, and other IoT devices should not share a network with your work laptop.</li>
</ul>

<h3>Using a VPN</h3>
<p>A VPN (Virtual Private Network) encrypts your internet traffic and routes it through your organisation's network, protecting data in transit and allowing access to internal resources.</p>
<ul>
<li><strong>Always use the corporate VPN</strong> when accessing internal systems or sensitive data remotely.</li>
<li><strong>Do not use free public VPN services</strong> for work — many log and sell traffic data.</li>
<li><strong>Disconnect from public Wi-Fi</strong> (cafes, hotels, airports) when handling sensitive data, even on VPN — public networks may intercept traffic before it reaches the VPN.</li>
</ul>

<h3>Device Security</h3>
<ul>
<li><strong>Lock your screen</strong> — use Win+L (Windows) or Ctrl+Cmd+Q (Mac) whenever you step away from your device, even for a moment.</li>
<li><strong>Full disk encryption</strong> — BitLocker (Windows) or FileVault (Mac) must be enabled on all work devices. This protects data if the device is stolen.</li>
<li><strong>Keep software updated</strong> — enable automatic updates for your OS, browser, and applications. Most attacks exploit known vulnerabilities for which patches already exist.</li>
<li><strong>Avoid personal devices for work</strong> — if you must use a personal device, ensure it has a screen lock, encryption, and up-to-date software.</li>
</ul>

<h3>Physical Security</h3>
<ul>
<li><strong>Position your screen away from windows and public view</strong> — shoulder-surfing is a real risk in home offices near public areas.</li>
<li><strong>Secure physical documents</strong> — shred any printed documents containing sensitive information rather than putting them in recycling.</li>
<li><strong>Do not take work calls in public</strong> where confidential information may be overheard.</li>
</ul>

<h3>Cyber Essentials Implications</h3>
<p>CE v3.2 requires that remote worker devices are treated as in-scope and meet the same security controls as office devices. Home worker laptops must have: updated OS and applications, active anti-malware, a host-based firewall, and encrypted storage. IT teams must be able to account for all remote devices in the asset inventory.</p>
""",
        "questions_json": [
            {
                "question": "You are working from a coffee shop and need to access your company's CRM system. What is the correct approach?",
                "options": [
                    "Connect directly — coffee shop Wi-Fi is fast and convenient",
                    "Use your phone's mobile hotspot or connect via the corporate VPN before accessing the CRM",
                    "Wait until you return to the office",
                    "Use a private browsing window to protect your session"
                ],
                "correct_index": 1,
                "explanation": "Public Wi-Fi is untrusted. Use mobile data or connect via your corporate VPN before accessing any company systems. Private browsing does not protect your network traffic."
            },
            {
                "question": "Which encryption standard should your home Wi-Fi router use?",
                "options": [
                    "WEP — it is the most widely supported standard",
                    "No encryption — it makes the network faster",
                    "WPA2 or WPA3",
                    "WPA1"
                ],
                "correct_index": 2,
                "explanation": "WEP is obsolete and can be cracked in minutes. WPA2 is the minimum acceptable standard; WPA3 is preferred. Check your router settings to confirm the encryption type."
            },
            {
                "question": "Under Cyber Essentials v3.2, are home worker laptops in-scope for CE controls?",
                "options": [
                    "No — home devices are personal and outside CE scope",
                    "Only if they are company-owned devices",
                    "Yes — all devices used to access organisational data are in-scope",
                    "Only if the employee works remotely more than 3 days per week"
                ],
                "correct_index": 2,
                "explanation": "CE v3.2 explicitly includes home worker and remote devices in scope. Any device used to access organisational systems or data must meet CE controls, regardless of ownership."
            },
            {
                "question": "What is the purpose of enabling BitLocker (Windows) or FileVault (Mac) on a work laptop?",
                "options": [
                    "It speeds up the laptop by compressing files",
                    "It prevents unauthorised access to data if the device is lost or stolen",
                    "It automatically backs up files to the cloud",
                    "It prevents malware from running"
                ],
                "correct_index": 1,
                "explanation": "Full disk encryption (BitLocker/FileVault) ensures that if a device is lost or stolen, the data cannot be read without the encryption key. It does not prevent malware or provide backup functionality."
            },
            {
                "question": "You step away from your desk in a shared home space for 5 minutes. What should you do?",
                "options": [
                    "Leave the screen as-is — it is only 5 minutes",
                    "Close the laptop lid",
                    "Lock the screen using Win+L or Ctrl+Cmd+Q",
                    "Sign out of all applications"
                ],
                "correct_index": 2,
                "explanation": "Lock your screen every time you leave your device unattended, even briefly. Locking (Win+L or Ctrl+Cmd+Q) is faster and sufficient — you do not need to sign out of everything."
            }
        ]
    }
]


# ---------------------------------------------------------------------------
# Seed helper
# ---------------------------------------------------------------------------

def _ensure_seeded(db: Session) -> None:
    from models.training import TrainingModule

    count = db.query(TrainingModule).filter(TrainingModule.tenant_id.is_(None)).count()
    if count >= len(SEED_MODULES):
        return

    for m in SEED_MODULES:
        exists = db.query(TrainingModule).filter(
            TrainingModule.tenant_id.is_(None),
            TrainingModule.title == m["title"],
        ).first()
        if not exists:
            db.add(TrainingModule(
                tenant_id=None,
                title=m["title"],
                category=m["category"],
                difficulty=m["difficulty"],
                estimated_minutes=m["estimated_minutes"],
                pass_mark=m["pass_mark"],
                description=m["description"],
                content_html=m["content_html"],
                questions_json=m["questions_json"],
                is_active=True,
            ))
    db.commit()
    logger.info("Training seed modules created.")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_modules(db: Session, tenant_id: str) -> list[dict]:
    from models.training import TrainingModule, TrainingProgress

    _ensure_seeded(db)

    modules = db.query(TrainingModule).filter(
        TrainingModule.is_active.is_(True),
        (TrainingModule.tenant_id.is_(None)) | (TrainingModule.tenant_id == tenant_id),
    ).order_by(TrainingModule.id).all()

    result = []
    for m in modules:
        progress = db.query(TrainingProgress).filter(
            TrainingProgress.tenant_id == tenant_id,
            TrainingProgress.module_id == m.id,
        ).first()

        result.append({
            "id": m.id,
            "title": m.title,
            "category": m.category,
            "difficulty": m.difficulty,
            "description": m.description,
            "estimated_minutes": m.estimated_minutes,
            "question_count": len(m.questions_json or []),
            "pass_mark": m.pass_mark,
            "status": progress.status if progress else "not_started",
            "best_score": progress.best_score if progress else 0,
            "attempts": progress.attempts if progress else 0,
        })
    return result


def get_module(db: Session, module_id: int, tenant_id: str) -> dict | None:
    from models.training import TrainingModule, TrainingProgress

    _ensure_seeded(db)

    m = db.query(TrainingModule).filter(
        TrainingModule.id == module_id,
        TrainingModule.is_active.is_(True),
    ).first()
    if not m:
        return None

    progress = db.query(TrainingProgress).filter(
        TrainingProgress.tenant_id == tenant_id,
        TrainingProgress.module_id == module_id,
    ).first()

    # Mark as in_progress if not yet started
    if not progress:
        progress = TrainingProgress(
            tenant_id=tenant_id,
            module_id=module_id,
            status="in_progress",
        )
        db.add(progress)
        db.commit()
        db.refresh(progress)
    elif progress.status == "not_started":
        progress.status = "in_progress"
        db.commit()

    return {
        "id": m.id,
        "title": m.title,
        "category": m.category,
        "difficulty": m.difficulty,
        "description": m.description,
        "estimated_minutes": m.estimated_minutes,
        "pass_mark": m.pass_mark,
        "content_html": m.content_html,
        "questions": [
            {
                "index": i,
                "question": q["question"],
                "options": q["options"],
            }
            for i, q in enumerate(m.questions_json or [])
        ],
        "status": progress.status,
        "best_score": progress.best_score,
        "attempts": progress.attempts,
    }


def submit_quiz(
    db: Session,
    module_id: int,
    tenant_id: str,
    answers: list[int],
    user_label: str = "default",
) -> dict:
    from models.training import TrainingModule, TrainingProgress, TrainingQuizAttempt

    m = db.query(TrainingModule).filter(TrainingModule.id == module_id).first()
    if not m:
        return {"error": "Module not found"}

    questions = m.questions_json or []
    if not questions:
        return {"error": "No questions in module"}

    # Score
    correct = 0
    feedback = []
    for i, q in enumerate(questions):
        selected = answers[i] if i < len(answers) else -1
        is_correct = selected == q["correct_index"]
        if is_correct:
            correct += 1
        feedback.append({
            "question": q["question"],
            "selected": selected,
            "correct_index": q["correct_index"],
            "is_correct": is_correct,
            "explanation": q.get("explanation", ""),
        })

    score = round((correct / len(questions)) * 100)
    passed = score >= (m.pass_mark or 80)

    # Record attempt
    attempt = TrainingQuizAttempt(
        tenant_id=tenant_id,
        module_id=module_id,
        user_label=user_label,
        answers_json=answers,
        score=score,
        passed=passed,
    )
    db.add(attempt)

    # Update progress
    progress = db.query(TrainingProgress).filter(
        TrainingProgress.tenant_id == tenant_id,
        TrainingProgress.module_id == module_id,
    ).first()
    if not progress:
        progress = TrainingProgress(tenant_id=tenant_id, module_id=module_id)
        db.add(progress)

    progress.attempts += 1
    progress.last_attempted_at = datetime.now(timezone.utc)
    if score > (progress.best_score or 0):
        progress.best_score = score
    if passed and progress.status != "completed":
        progress.status = "completed"
        progress.completed_at = datetime.now(timezone.utc)
    elif progress.status == "not_started":
        progress.status = "in_progress"

    db.commit()

    return {
        "score": score,
        "passed": passed,
        "pass_mark": m.pass_mark,
        "correct": correct,
        "total": len(questions),
        "feedback": feedback,
    }


def get_progress_summary(db: Session, tenant_id: str) -> dict:
    from models.training import TrainingModule, TrainingProgress

    _ensure_seeded(db)

    total = db.query(TrainingModule).filter(
        TrainingModule.is_active.is_(True),
        (TrainingModule.tenant_id.is_(None)) | (TrainingModule.tenant_id == tenant_id),
    ).count()

    completed = db.query(TrainingProgress).filter(
        TrainingProgress.tenant_id == tenant_id,
        TrainingProgress.status == "completed",
    ).count()

    in_progress = db.query(TrainingProgress).filter(
        TrainingProgress.tenant_id == tenant_id,
        TrainingProgress.status == "in_progress",
    ).count()

    scores = db.query(TrainingProgress).filter(
        TrainingProgress.tenant_id == tenant_id,
        TrainingProgress.best_score > 0,
    ).all()

    avg_score = round(sum(p.best_score for p in scores) / len(scores)) if scores else 0

    return {
        "total_modules": total,
        "completed": completed,
        "in_progress": in_progress,
        "not_started": max(0, total - completed - in_progress),
        "completion_pct": round((completed / total) * 100) if total else 0,
        "avg_score": avg_score,
    }
