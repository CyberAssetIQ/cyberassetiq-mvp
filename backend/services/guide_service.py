"""
CyberAssetIQ AI Guide Service
Wizard step-by-step instructions + intent classification + LLM adaptation
Designed for non-technical users in urgent situations.

Drop into: backend/services/guide_service.py
"""

import json
import logging
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DATA MODELS
# ---------------------------------------------------------------------------

class GuideRequest(BaseModel):
    intent: str = ""           # detected or user-specified intent
    step: int = 0              # current wizard step (0 = not started)
    free_text: str = ""        # raw user message
    context: dict = {}         # e.g. {"current_tab": "vulnerabilities", "tenant_id": "..."}
    tenant_id: str = "tenant-001"

class GuideResponse(BaseModel):
    mode: str                   # "copilot" | "wizard" | "escalate"
    intent: str = ""
    step: int = 0
    total_steps: int = 0
    step_title: str = ""
    message: str = ""           # plain-English instruction
    tip: str = ""               # optional extra tip
    action_label: Optional[str] = None   # button label e.g. "Open Integrations"
    action_route: Optional[str] = None  # frontend hash e.g. "#integrations"
    api_call: Optional[dict] = None     # {"method": "POST", "url": "/api/...", "body": {...}}
    prev_enabled: bool = False
    next_enabled: bool = False
    escalate_reason: Optional[str] = None
    suggested_intents: list = []        # quick-start suggestions shown on open


# ---------------------------------------------------------------------------
# WIZARD STEP LIBRARY
# Every intent maps to a list of steps. Each step has:
#   title       - short heading shown in the widget
#   instruction - plain English, zero assumed IT knowledge
#   tip         - optional extra context
#   action_label / action_route - optional navigation shortcut button
#   api_call    - optional direct API call the widget can make on user's behalf
# ---------------------------------------------------------------------------

WIZARD_STEPS: dict = {

    # ---- VULNERABILITY SCANNING -----------------------------------------------
    "scan_vulnerabilities": [
        {
            "title": "Let's scan for vulnerabilities",
            "instruction": (
                "A vulnerability scan checks your computers and servers for known security "
                "weaknesses — things like outdated software that attackers could exploit. "
                "CyberAssetIQ can run this scan for you automatically. Ready to start?"
            ),
            "tip": "This won't change anything on your systems — it only reads and reports.",
            "action_label": "Go to Vulnerabilities",
            "action_route": "#vulnerabilities",
        },
        {
            "title": "Find the Scan button",
            "instruction": (
                "You should now be on the Vulnerabilities tab. Look for a button that says "
                "\"Run Scan\" or \"New Scan\" near the top of the page. Click it."
            ),
            "tip": "If you can't see it, make sure you're on the Vulnerabilities tab, not the Dashboard.",
            "action_label": "Go to Vulnerabilities",
            "action_route": "#vulnerabilities",
        },
        {
            "title": "Choose what to scan",
            "instruction": (
                "A box will appear asking what you want to scan. If you want to check everything, "
                "choose \"All Assets\". If you only want to check specific computers, you can type "
                "their names or IP addresses. For now, \"All Assets\" is the safe choice."
            ),
            "tip": "An IP address is a number like 192.168.1.5 that identifies a computer on your network.",
        },
        {
            "title": "Start the scan",
            "instruction": (
                "Click the \"Start Scan\" or \"Run\" button. The scan will begin and you'll see a "
                "progress bar. It usually takes between 2 and 10 minutes depending on how many "
                "devices you have. You don't need to stay on this page — the results will be saved."
            ),
            "tip": "You'll receive a notification when the scan is complete.",
            "api_call": {"method": "POST", "url": "/api/vulnerabilities/scan", "body": {"scan_type": "all"}},
            "action_label": "Start Scan Now",
        },
        {
            "title": "Review the results",
            "instruction": (
                "When the scan finishes, you'll see a list of findings. Each one is colour-coded: "
                "RED means critical (fix as soon as possible), ORANGE means high priority, YELLOW "
                "means medium, and BLUE means low. Start with anything in RED."
            ),
            "tip": "Click any finding to see what it is, which computer it affects, and how to fix it.",
            "action_label": "View Results",
            "action_route": "#vulnerabilities",
        },
    ],

    # ---- CONNECT QUALYS -------------------------------------------------------
    "connect_qualys": [
        {
            "title": "Connecting Qualys to CyberAssetIQ",
            "instruction": (
                "Qualys is a vulnerability scanning tool. We're going to link it to CyberAssetIQ "
                "so your Qualys findings appear here automatically. You'll need your Qualys "
                "username and password. If you don't have them, ask whoever set up your Qualys account."
            ),
            "tip": "You only need to do this once. After it's connected, data syncs automatically.",
            "action_label": "Go to Integrations",
            "action_route": "#integrations",
        },
        {
            "title": "Open the Integrations page",
            "instruction": (
                "Click \"Integrations\" in the top navigation bar. Scroll down until you see a "
                "section called \"Vulnerability Scanners\". Find the Qualys card and click "
                "\"Connect\" or \"Configure\"."
            ),
            "action_label": "Go to Integrations",
            "action_route": "#integrations",
        },
        {
            "title": "Enter your Qualys credentials",
            "instruction": (
                "You'll see a form with three fields: Username, Password, and Host. "
                "Enter your Qualys username and password. The Host field should already say "
                "qualysapi.qualys.com — leave it as is unless your IT team uses a private Qualys server."
            ),
            "tip": "Your credentials are encrypted and never stored in plain text.",
        },
        {
            "title": "Test the connection",
            "instruction": (
                "Click \"Test Connection\". After a few seconds you'll see either a green tick "
                "(success) or a red error message. "
                "If you see a red error, the most common fixes are: (1) check your username and "
                "password are correct, (2) ask your IT admin if your Qualys account has API access enabled."
            ),
            "tip": "API access is a setting inside Qualys that needs to be turned on by a Qualys admin.",
        },
        {
            "title": "Pull your vulnerability data",
            "instruction": (
                "Once the test shows a green tick, click \"Save & Sync\" or \"Pull Data\". "
                "CyberAssetIQ will import all your Qualys vulnerability findings. "
                "This takes about 30–60 seconds. When it's done, your findings will appear "
                "on the Vulnerabilities tab."
            ),
            "tip": "From now on, Qualys data will sync automatically every 24 hours.",
            "api_call": {"method": "POST", "url": "/api/integrations/qualys/pull", "body": {}},
            "action_label": "Pull Qualys Data",
        },
    ],

    # ---- CONNECT TENABLE ------------------------------------------------------
    "connect_tenable": [
        {
            "title": "Connecting Tenable to CyberAssetIQ",
            "instruction": (
                "Tenable (also sold as Nessus) is a vulnerability scanner. To connect it, "
                "you'll need an API Access Key and API Secret Key from your Tenable account. "
                "These are like a password specifically for software connections."
            ),
            "tip": "Don't have the API keys? Log into Tenable, go to Settings → My Account → API Keys.",
            "action_label": "Go to Integrations",
            "action_route": "#integrations",
        },
        {
            "title": "Open the Tenable integration card",
            "instruction": (
                "On the Integrations page, find the \"Vulnerability Scanners\" section and "
                "click the Tenable card. You'll see fields for Access Key, Secret Key, and URL."
            ),
            "action_label": "Go to Integrations",
            "action_route": "#integrations",
        },
        {
            "title": "Enter your API keys",
            "instruction": (
                "Paste your Tenable Access Key into the first field and your Secret Key into "
                "the second. The URL should be https://cloud.tenable.com unless your company "
                "runs its own private Tenable server."
            ),
            "tip": "Copy-paste the keys carefully — they are long and a single wrong character will cause an error.",
        },
        {
            "title": "Test and save",
            "instruction": (
                "Click \"Test Connection\". If you get a green tick, click \"Save & Sync\". "
                "Your Tenable scan data will import within 60 seconds and appear in Vulnerabilities."
            ),
            "api_call": {"method": "POST", "url": "/api/integrations/tenable/pull", "body": {}},
            "action_label": "Pull Tenable Data",
        },
    ],

    # ---- CONNECT RAPID7 -------------------------------------------------------
    "connect_rapid7": [
        {
            "title": "Connecting Rapid7 InsightVM",
            "instruction": (
                "Rapid7 InsightVM (or InsightIDR) is a vulnerability and risk management tool. "
                "To connect it, you'll need your Rapid7 API key. "
                "You can find this in Rapid7 by going to User Settings → API Key Management."
            ),
            "tip": "If you use InsightIDR (not InsightVM), the steps are the same — just select InsightIDR on the integration card.",
            "action_label": "Go to Integrations",
            "action_route": "#integrations",
        },
        {
            "title": "Find and open the Rapid7 card",
            "instruction": (
                "On the Integrations page, scroll to \"Vulnerability Scanners\" and click the "
                "Rapid7 card. Enter your API key and your Rapid7 region URL "
                "(usually https://us.api.insight.rapid7.com or the EU equivalent)."
            ),
        },
        {
            "title": "Test, save, and pull",
            "instruction": (
                "Click \"Test Connection\" — look for the green tick. Then click \"Save & Sync\" "
                "to import your Rapid7 vulnerability data into CyberAssetIQ."
            ),
            "api_call": {"method": "POST", "url": "/api/integrations/rapid7/pull", "body": {}},
            "action_label": "Pull Rapid7 Data",
        },
    ],

    # ---- CONNECT SPLUNK -------------------------------------------------------
    "connect_splunk": [
        {
            "title": "Connecting Splunk for event logs",
            "instruction": (
                "Splunk collects log data from your systems — things like who logged in, what "
                "files were accessed, and any security alerts. Connecting it lets CyberAssetIQ "
                "pull those event logs and correlate them with your assets. "
                "You'll need: your Splunk server address, a username, and a password (or token)."
            ),
            "tip": "A token is an alternative to a password — some organisations use these for security. Ask your Splunk admin if unsure.",
            "action_label": "Go to Integrations",
            "action_route": "#integrations",
        },
        {
            "title": "Open the Splunk integration card",
            "instruction": (
                "On the Integrations page, scroll to the \"SIEM\" section and click the Splunk card. "
                "SIEM stands for Security Information and Event Management — it's the category "
                "Splunk belongs to."
            ),
            "action_label": "Go to Integrations",
            "action_route": "#integrations",
        },
        {
            "title": "Enter your Splunk connection details",
            "instruction": (
                "Fill in: Host (your Splunk server address, e.g. splunk.yourcompany.com or an "
                "IP address), Port (usually 8089), and your Username + Password or API Token. "
                "If you see a dropdown for authentication type, choose \"Token\" if you have one, "
                "otherwise choose \"Password\"."
            ),
            "tip": "Port 8089 is Splunk's management port. If your company uses a different port, check with your Splunk admin.",
        },
        {
            "title": "Test the connection",
            "instruction": (
                "Click \"Test Connection\". A green tick means success. "
                "If you get a connection refused error, Splunk may be blocking external connections — "
                "ask your IT team to whitelist the CyberAssetIQ server IP address."
            ),
        },
        {
            "title": "Pull event log data",
            "instruction": (
                "Click \"Pull Events\" or \"Sync Now\". CyberAssetIQ will pull the last 24 hours "
                "of security events from Splunk and map them to your assets. "
                "You'll see event data appear on the Events or Alerts tab within 1–2 minutes."
            ),
            "api_call": {"method": "POST", "url": "/api/integrations/splunk/pull", "body": {"hours": 24}},
            "action_label": "Pull Splunk Events",
        },
    ],

    # ---- CONNECT QRADAR -------------------------------------------------------
    "connect_qradar": [
        {
            "title": "Connecting IBM QRadar",
            "instruction": (
                "QRadar is IBM's security event management system. Connecting it will pull "
                "QRadar offenses (security alerts) and events into CyberAssetIQ. "
                "You'll need your QRadar server address and a QRadar API token."
            ),
            "tip": "To get a QRadar API token: log into QRadar → Admin → Authorized Services → Add Authorized Service.",
            "action_label": "Go to Integrations",
            "action_route": "#integrations",
        },
        {
            "title": "Open the QRadar card and enter details",
            "instruction": (
                "On the Integrations page in the SIEM section, click the QRadar card. "
                "Enter your QRadar server URL (e.g. https://qradar.yourcompany.com) and "
                "paste in your API token. Leave \"Verify SSL\" ticked unless your IT team "
                "says otherwise."
            ),
        },
        {
            "title": "Test and sync",
            "instruction": (
                "Click \"Test Connection\" for the green tick, then \"Save & Pull\". "
                "QRadar offenses will appear in the Alerts section within a few minutes."
            ),
            "api_call": {"method": "POST", "url": "/api/integrations/qradar/pull", "body": {}},
            "action_label": "Pull QRadar Offenses",
        },
    ],

    # ---- CONNECT CYBERARK -----------------------------------------------------
    "connect_cyberark": [
        {
            "title": "Connecting CyberArk",
            "instruction": (
                "CyberArk manages privileged accounts — the powerful administrator accounts "
                "that, if compromised, could give an attacker full control of your systems. "
                "Connecting it lets CyberAssetIQ check which privileged accounts exist, "
                "whether they've been used recently, and flag any suspicious activity. "
                "You'll need your CyberArk server URL and an application credential."
            ),
            "tip": "Ask your CyberArk admin to create a dedicated API user for this integration rather than using a personal account.",
            "action_label": "Go to Integrations",
            "action_route": "#integrations",
        },
        {
            "title": "Open the CyberArk PAM card",
            "instruction": (
                "On the Integrations page, scroll to \"Identity & Access Management\" (IAM) "
                "or \"PAM\" section. Click the CyberArk card. PAM stands for Privileged Access "
                "Management — it's the security category CyberArk belongs to."
            ),
        },
        {
            "title": "Enter connection details",
            "instruction": (
                "Fill in: CyberArk URL, Application ID (a name given to this integration in "
                "CyberArk), and Authentication Token. The Authentication Token comes from your "
                "CyberArk admin who set up the API application."
            ),
        },
        {
            "title": "Test and pull account data",
            "instruction": (
                "Click \"Test Connection\", then \"Pull Accounts\". CyberAssetIQ will import "
                "a list of privileged accounts and their recent activity. Review these in the "
                "Identity or Privileged Accounts section."
            ),
            "api_call": {"method": "POST", "url": "/api/integrations/cyberark/pull", "body": {}},
            "action_label": "Pull CyberArk Accounts",
        },
    ],

    # ---- NETWORK DISCOVERY ----------------------------------------------------
    "network_scan": [
        {
            "title": "Let's discover your network",
            "instruction": (
                "A network scan finds every device connected to your network — computers, "
                "servers, printers, phones, cameras, anything with an IP address. "
                "This is important because you can't protect devices you don't know about. "
                "The scan is read-only and won't affect how your devices work."
            ),
            "tip": "This is often called 'asset discovery' — finding all the assets (devices) on your network.",
            "action_label": "Go to Network",
            "action_route": "#network",
        },
        {
            "title": "Enter your network range",
            "instruction": (
                "On the Network tab, find the \"Run Discovery\" or \"New Scan\" button and click it. "
                "You'll be asked for a network range. If you're not sure what yours is, the most "
                "common values are 192.168.1.0/24 or 10.0.0.0/8. Your IT team or router settings "
                "can confirm this."
            ),
            "tip": "The /24 at the end means 'scan all addresses in this range' — you don't need to understand it, just leave it as shown.",
        },
        {
            "title": "Start the discovery",
            "instruction": (
                "Click \"Start Discovery\" or \"Run Scan\". You'll see devices appearing in real "
                "time as they're found. A typical office network of 50 devices takes 2–5 minutes. "
                "Larger networks take longer."
            ),
            "api_call": {"method": "POST", "url": "/api/network/scan", "body": {"scan_type": "discovery"}},
            "action_label": "Start Network Scan",
        },
        {
            "title": "Review discovered assets",
            "instruction": (
                "When the scan finishes, every device found will appear in the Asset list. "
                "Look for anything unexpected — devices you don't recognise could be "
                "unauthorised equipment. Click any device to see more details."
            ),
            "tip": "New assets that weren't in your previous inventory are highlighted. Review these first.",
            "action_label": "View Assets",
            "action_route": "#assets",
        },
    ],

    # ---- EVENT LOG COLLECTION (GENERIC) ---------------------------------------
    "collect_event_logs": [
        {
            "title": "Collecting event logs",
            "instruction": (
                "Event logs are records of everything that happens on your systems — logins, "
                "file access, configuration changes, errors. Collecting them helps you spot "
                "suspicious activity. Which system do you want to collect logs from? "
                "Common sources are: Splunk, QRadar, Windows Event Logs, or Azure/Microsoft Sentinel."
            ),
            "tip": "If you're not sure, click the button for the tool your IT team uses most.",
            "action_label": "Go to Integrations",
            "action_route": "#integrations",
        },
        {
            "title": "Choose your log source",
            "instruction": (
                "On the Integrations page, look for your log collection tool in the SIEM section. "
                "If it's already connected (shown with a green dot), click \"Pull Events\" or "
                "\"Sync Now\" to get the latest logs. If it's not connected yet, click the card "
                "and follow the setup steps."
            ),
        },
        {
            "title": "View your event logs",
            "instruction": (
                "Once pulled, logs appear on the Events or Alerts tab. You can filter by time, "
                "severity, or asset. Red and orange alerts should be reviewed first. "
                "Click any event to see the full details and which asset it relates to."
            ),
            "action_label": "View Events",
            "action_route": "#events",
        },
    ],

    # ---- CYBER ESSENTIALS COMPLIANCE ------------------------------------------
    "cyber_essentials_audit": [
        {
            "title": "Preparing for Cyber Essentials",
            "instruction": (
                "Cyber Essentials is a UK government-backed certification that shows your "
                "organisation takes cybersecurity seriously. CyberAssetIQ automates most of "
                "the evidence collection for you. Let's check how ready you are."
            ),
            "tip": "Cyber Essentials v3.2 now requires an automated asset inventory — CyberAssetIQ provides this.",
            "action_label": "Go to Compliance",
            "action_route": "#compliance",
        },
        {
            "title": "Run a compliance check",
            "instruction": (
                "On the Compliance tab, click \"Run CE Assessment\" or \"Check Readiness\". "
                "CyberAssetIQ will check your current asset data against all Cyber Essentials "
                "requirements and produce a gap report."
            ),
            "api_call": {"method": "POST", "url": "/api/compliance/ce-assessment", "body": {}},
            "action_label": "Run CE Assessment",
        },
        {
            "title": "Review your readiness score",
            "instruction": (
                "Your Cyber Essentials readiness score will appear as a percentage. "
                "Below it you'll see a list of controls: green ticks mean you're compliant, "
                "red crosses mean there's a gap to fix. Click any red item for "
                "a plain-English explanation of what needs to be done."
            ),
        },
        {
            "title": "Generate your evidence package",
            "instruction": (
                "When you're ready to apply, click \"Generate Evidence Package\". "
                "CyberAssetIQ will produce a PDF document with all the evidence your "
                "certifier needs — asset inventory, patch status, access controls, and more. "
                "This replaces weeks of manual documentation."
            ),
            "api_call": {"method": "POST", "url": "/api/compliance/generate-evidence", "body": {"framework": "CE"}},
            "action_label": "Generate Evidence PDF",
        },
    ],

    # ---- DARK WEB MONITORING --------------------------------------------------
    "dark_web_check": [
        {
            "title": "Checking dark web exposure",
            "instruction": (
                "The dark web is a hidden part of the internet where stolen data is bought "
                "and sold. CyberAssetIQ checks whether your company's email addresses, "
                "API keys, or credentials have been leaked there. "
                "Let's run a check now."
            ),
            "tip": "This is read-only monitoring — we only search for your data, we don't interact with any dark web content.",
            "action_label": "Go to Dark Web",
            "action_route": "#darkweb",
        },
        {
            "title": "Start a dark web scan",
            "instruction": (
                "On the Dark Web tab, click \"Run Exposure Check\". CyberAssetIQ will search "
                "known breach databases and dark web sources for your company's email domain "
                "and any credentials linked to your assets."
            ),
            "api_call": {"method": "POST", "url": "/api/darkweb/scan", "body": {}},
            "action_label": "Run Exposure Check",
        },
        {
            "title": "Review exposure findings",
            "instruction": (
                "Results appear sorted by severity. Each finding shows what was exposed "
                "(e.g. an email and password combination), where it was found, and how recent it is. "
                "For any exposed passwords, those accounts should have their passwords changed immediately."
            ),
            "tip": "If an API key is found exposed, it must be revoked in the originating service (AWS, GitHub, etc.) right away.",
        },
    ],
}


# ---------------------------------------------------------------------------
# INTENT KEYWORD MAP
# Maps keyword signals to wizard intents.
# ---------------------------------------------------------------------------

INTENT_KEYWORDS: dict = {
    "scan_vulnerabilities": [
        "vulnerability", "vuln", "scan", "cve", "patch", "security scan",
        "run a scan", "check for vulnerabilities", "security check",
    ],
    "connect_qualys": ["qualys"],
    "connect_tenable": ["tenable", "nessus"],
    "connect_rapid7": ["rapid7", "insight", "insightvm", "insightidr"],
    "connect_splunk": ["splunk"],
    "connect_qradar": ["qradar", "ibm siem"],
    "connect_cyberark": ["cyberark", "cyberark", "privileged", "pam"],
    "network_scan": [
        "network", "discover", "asset discovery", "find devices",
        "network scan", "ip scan", "nmap", "what's on my network",
    ],
    "collect_event_logs": [
        "event log", "logs", "siem", "events", "log collection",
        "audit log", "windows event",
    ],
    "cyber_essentials_audit": [
        "cyber essentials", "ce certification", "ce audit", "compliance",
        "ncsc", "certification", "evidence", "ce v3",
    ],
    "dark_web_check": [
        "dark web", "breach", "leaked", "credential leak", "data breach",
        "exposed", "stolen credentials",
    ],
}

# Escalation triggers — user needs human help
ESCALATION_KEYWORDS = [
    "emergency", "urgent", "breach", "hacked", "attacked", "ransomware",
    "incident", "help me now", "crisis", "compromised", "i need a human",
    "speak to someone", "call someone", "escalate",
]

# Tier 1/2 actions that always require human approval
HIGH_RISK_ACTIONS = [
    "isolate", "block", "disable account", "revoke access", "firewall",
    "delete", "terminate", "shut down",
]


# ---------------------------------------------------------------------------
# SERVICE CLASS
# ---------------------------------------------------------------------------

class GuideService:
    """
    Handles intent classification and step-by-step wizard responses.
    Falls back to AI copilot for free-form questions.
    """

    def __init__(self, ai_provider=None):
        """
        ai_provider: optional AIProviderService instance for LLM-adapted responses.
        If None, returns static step text only.
        """
        self.ai_provider = ai_provider

    # ------------------------------------------------------------------
    def classify_intent(self, text: str) -> str:
        """
        Fast keyword-based intent classifier.
        Returns matched intent key or empty string.
        """
        text_lower = text.lower()

        # Check escalation first
        for kw in ESCALATION_KEYWORDS:
            if kw in text_lower:
                return "escalate"

        # Check high-risk actions
        for kw in HIGH_RISK_ACTIONS:
            if kw in text_lower:
                return "high_risk"

        # Check wizard intents
        for intent, keywords in INTENT_KEYWORDS.items():
            for kw in keywords:
                if kw in text_lower:
                    return intent

        return ""

    # ------------------------------------------------------------------
    def get_suggested_intents(self, current_tab: str = "") -> list:
        """
        Returns contextual quick-start suggestions based on current tab.
        """
        tab_suggestions = {
            "vulnerabilities": [
                {"label": "Run a vulnerability scan", "intent": "scan_vulnerabilities"},
                {"label": "Connect Qualys", "intent": "connect_qualys"},
                {"label": "Connect Tenable", "intent": "connect_tenable"},
            ],
            "network": [
                {"label": "Discover network assets", "intent": "network_scan"},
                {"label": "Run a vulnerability scan", "intent": "scan_vulnerabilities"},
            ],
            "integrations": [
                {"label": "Connect Splunk", "intent": "connect_splunk"},
                {"label": "Connect Qualys", "intent": "connect_qualys"},
                {"label": "Connect QRadar", "intent": "connect_qradar"},
                {"label": "Connect CyberArk", "intent": "connect_cyberark"},
            ],
            "compliance": [
                {"label": "Check Cyber Essentials readiness", "intent": "cyber_essentials_audit"},
            ],
            "darkweb": [
                {"label": "Check dark web exposure", "intent": "dark_web_check"},
            ],
            "events": [
                {"label": "Collect event logs", "intent": "collect_event_logs"},
                {"label": "Connect Splunk", "intent": "connect_splunk"},
            ],
        }
        default_suggestions = [
            {"label": "Run a vulnerability scan", "intent": "scan_vulnerabilities"},
            {"label": "Discover network assets", "intent": "network_scan"},
            {"label": "Check dark web exposure", "intent": "dark_web_check"},
            {"label": "Prepare Cyber Essentials", "intent": "cyber_essentials_audit"},
        ]
        return tab_suggestions.get(current_tab, default_suggestions)

    # ------------------------------------------------------------------
    async def process(self, req: GuideRequest) -> GuideResponse:
        """
        Main entry point. Returns a GuideResponse.
        """
        current_tab = req.context.get("current_tab", "")

        # No input yet → show suggestions
        if not req.free_text and not req.intent:
            return GuideResponse(
                mode="copilot",
                message="Hi! I'm your CyberAssetIQ guide. I can walk you through any task step by step — no IT knowledge needed. What do you need to do right now?",
                suggested_intents=self.get_suggested_intents(current_tab),
            )

        # Determine intent
        intent = req.intent
        if not intent and req.free_text:
            intent = self.classify_intent(req.free_text)

        # Escalation
        if intent == "escalate":
            return GuideResponse(
                mode="escalate",
                intent="escalate",
                message=(
                    "This sounds like an urgent security situation. "
                    "I'm flagging this for your security team right now and creating an incident record. "
                    "While I do that, if you believe you have an active breach, consider: "
                    "disconnecting affected machines from the network (unplug the ethernet cable or turn off Wi-Fi)."
                ),
                escalate_reason="User reported urgent/emergency situation",
                action_label="Create Incident & Notify Team",
                api_call={"method": "POST", "url": "/api/incidents", "body": {"severity": "critical", "source": "guide_bot", "description": req.free_text}},
            )

        # High-risk action
        if intent == "high_risk":
            return GuideResponse(
                mode="escalate",
                intent="high_risk",
                message=(
                    "This action (like isolating a device, disabling an account, or changing firewall rules) "
                    "requires approval from a security analyst before it can be executed. "
                    "I've added it to the approval queue. Your analyst will be notified."
                ),
                escalate_reason="Tier 1/2 action requires human approval",
                action_label="View Approval Queue",
                action_route="#agentic",
            )

        # Known wizard intent
        if intent in WIZARD_STEPS:
            steps = WIZARD_STEPS[intent]
            step_index = max(0, min(req.step, len(steps) - 1))
            step_data = steps[step_index]

            # Optionally adapt the instruction via LLM
            adapted_message = step_data["instruction"]
            if self.ai_provider and req.free_text:
                adapted_message = await self._adapt_with_llm(
                    intent=intent,
                    step_data=step_data,
                    user_question=req.free_text,
                    step_index=step_index,
                    total_steps=len(steps),
                )

            return GuideResponse(
                mode="wizard",
                intent=intent,
                step=step_index,
                total_steps=len(steps),
                step_title=step_data["title"],
                message=adapted_message,
                tip=step_data.get("tip", ""),
                action_label=step_data.get("action_label"),
                action_route=step_data.get("action_route"),
                api_call=step_data.get("api_call"),
                prev_enabled=step_index > 0,
                next_enabled=step_index < len(steps) - 1,
            )

        # Unknown intent → AI copilot mode
        ai_answer = await self._ask_copilot(req.free_text, req.tenant_id, req.context)
        return GuideResponse(
            mode="copilot",
            message=ai_answer,
            suggested_intents=self.get_suggested_intents(current_tab),
        )

    # ------------------------------------------------------------------
    async def _adapt_with_llm(
        self,
        intent: str,
        step_data: dict,
        user_question: str,
        step_index: int,
        total_steps: int,
    ) -> str:
        """
        Uses the LLM to adapt the static step instruction to what the user actually asked.
        Falls back to static text on any error.
        """
        try:
            system = (
                "You are CyberAssetIQ Guide. You explain ONE thing at a time to non-technical IT users "
                "in urgent situations. Never assume IT knowledge. Explain every acronym. "
                "If the user's question shows they're already further ahead, skip to that. "
                "Keep your response under 100 words. No bullet points. Plain English only."
            )
            prompt = (
                f"We are on step {step_index + 1} of {total_steps} for task: {intent}.\n"
                f"The standard instruction is:\n{step_data['instruction']}\n\n"
                f"The user said: '{user_question}'\n\n"
                "Adapt the instruction to directly address what the user asked. "
                "If their question shows they're past this step, advance. "
                "If they're confused, simplify further."
            )
            response = await self.ai_provider.generate(
                messages=[{"role": "user", "content": prompt}],
                system=system,
                max_tokens=200,
            )
            return response.strip()
        except Exception as e:
            logger.warning(f"LLM adaptation failed, using static text: {e}")
            return step_data["instruction"]

    # ------------------------------------------------------------------
    async def _ask_copilot(self, question: str, tenant_id: str, context: dict) -> str:
        """
        Passes free-form question to AI copilot. Returns answer as string.
        """
        if not self.ai_provider:
            return (
                "I'm not sure how to help with that specific request. "
                "Try asking about: running a vulnerability scan, connecting Splunk or Qualys, "
                "discovering network assets, or checking Cyber Essentials compliance."
            )
        try:
            system = (
                "You are CyberAssetIQ Guide, an assistant for non-technical users of a cybersecurity platform. "
                "Answer in plain English. No jargon without explanation. Keep answers under 120 words. "
                "If you don't know the answer, suggest the user contact their IT admin."
            )
            response = await self.ai_provider.generate(
                messages=[{"role": "user", "content": question}],
                system=system,
                max_tokens=300,
            )
            return response.strip()
        except Exception as e:
            logger.error(f"Copilot call failed: {e}")
            return "I couldn't get an answer right now. Please try again in a moment."
