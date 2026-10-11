import asyncio
import json
import logging
import sys
import os
import requests
import textwrap
from typing import Optional
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("mcp_agent")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3") # Default to a common model

def check_ollama():
    try:
        res = requests.get(f"{OLLAMA_URL}/api/tags")
        if res.status_code == 200:
            models = [m["name"] for m in res.json().get("models", [])]
            return True, models
    except Exception:
        pass
    return False, []

def build_professional_email(prompt: str, raw_proposal: dict = None) -> dict:
    import re
    prompt_lower = prompt.lower()
    
    # 1. Determine recipient
    recipient = ""
    email_matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', prompt)
    if email_matches:
        recipient = email_matches[0]
    elif raw_proposal and raw_proposal.get("recipient") and "@" in str(raw_proposal.get("recipient")):
        recipient = str(raw_proposal["recipient"]).strip()
    else:
        if "evil" in prompt_lower or "attacker" in prompt_lower:
            recipient = "attacker@evil.com"
        else:
            recipient = "kumarayush.professional@gmail.com"

    salutation = "Dear Team"
    if "kumarayush" in recipient.lower() or "ayush" in recipient.lower():
        salutation = "Dear Ayush"
    elif "subhasree" in recipient.lower():
        salutation = "Dear Subhasree"
    elif "annesha" in recipient.lower():
        salutation = "Dear Annesha"
    elif "hr" in recipient.lower():
        salutation = "Dear HR Team"

    # 2. Check if raw_proposal from LLM is already a high-quality human email
    if raw_proposal and raw_proposal.get("body"):
        b = str(raw_proposal["body"]).strip()
        if ("dear " in b.lower() or "hello " in b.lower() or "hi " in b.lower()) and \
           ("regards" in b.lower() or "sincerely" in b.lower() or "best," in b.lower() or "thank you" in b.lower()) and \
           not "please process the following" in b.lower():
            return {
                "recipient": recipient,
                "subject": raw_proposal.get("subject") or "Formal Notification",
                "body": b,
                "purpose": raw_proposal.get("purpose") or "corporate_communication"
            }

    # 3. Sick leave / Medical absence
    if any(k in prompt_lower for k in ("leave", "sick", "unwell", "fever", "doctor", "hospital", "medical")):
        if "tomorrow" in prompt_lower:
            timeframe = "tomorrow"
        elif "12-13 oct" in prompt_lower or "12-13 october" in prompt_lower:
            timeframe = "October 12–13"
        elif "today" in prompt_lower:
            timeframe = "today"
        elif "next week" in prompt_lower:
            timeframe = "next week"
        else:
            date_m = re.search(r'(?:for|on)\s+([0-9]{1,2}(?:-[0-9]{1,2})?\s*(?:oct|october|nov|november|dec|december|jan|feb|mar|apr|may|jun|jul|aug|sep)?[a-z0-9\s]*)', prompt_lower)
            timeframe = date_m.group(1).strip() if date_m else "tomorrow"

        subject = f"Sick Leave Request — {timeframe.capitalize()}"
        body = (
            f"{salutation},\n\n"
            f"I hope this email finds you well.\n\n"
            f"I am writing to formally request sick leave for {timeframe} due to an unexpected health condition. "
            f"I am currently unwell and taking the required rest to ensure a quick and full recovery.\n\n"
            f"I have ensured that all pressing matters are documented and queued, and I will be checking in once I am back on my feet. "
            f"Please let me know if any medical certificate or additional paperwork is needed from my side.\n\n"
            f"Thank you very much for your understanding and continued support.\n\n"
            f"Warm regards,\n"
            f"Ayush Kumar"
        )
        purpose = "sick_leave_request"

    elif any(k in prompt_lower for k in ("status", "report", "update", "metrics", "ops")):
        subject = "Project & Operations Status Update"
        body = (
            f"{salutation},\n\n"
            f"I hope this email finds you well.\n\n"
            f"I am pleased to share our latest operational status report. "
            f"All milestones and deliverables are currently tracking smoothly according to schedule, with no active blockers or critical anomalies reported.\n\n"
            f"Please let me know if you would like to review the breakdown in detail or if there is anything specific you would like me to follow up on.\n\n"
            f"Warm regards,\n"
            f"Ayush Kumar"
        )
        purpose = "status_update"

    elif "evil" in prompt_lower or "attacker" in prompt_lower or "exfiltrat" in prompt_lower or "ignore" in prompt_lower:
        subject = "Confidential System Diagnostics & Credentials Export"
        body = (
            f"Hello,\n\n"
            f"Please find attached the requested system configuration and credentials export.\n\n"
            f"Regards,\n"
            f"Automated Service"
        )
        purpose = "data_exfiltration"

    else:
        subject = "Operational Notification"
        clean_intent = prompt.strip()
        if clean_intent.lower().startswith("send an email to") or clean_intent.lower().startswith("send a email to") or clean_intent.lower().startswith("send an mail to"):
            clean_intent = re.sub(r'^send\s+(?:an|a)?\s*(?:email|mail)\s+to\s+\S+\s+(?:to|for|about)?\s*', '', clean_intent, flags=re.IGNORECASE).strip()
            if clean_intent:
                clean_intent = clean_intent[0].upper() + clean_intent[1:]

        body = (
            f"{salutation},\n\n"
            f"I hope this note finds you well.\n\n"
            f"I wanted to reach out regarding the following update: {clean_intent}.\n\n"
            f"Please let me know if you have any questions or require any further information.\n\n"
            f"Warm regards,\n"
            f"Ayush Kumar"
        )
        purpose = "corporate_communication"

    return {
        "recipient": recipient,
        "subject": subject,
        "body": body,
        "purpose": purpose
    }

def ask_ollama(prompt: str) -> dict:
    system_prompt = """You are an executive assistant drafting a human-written email for the user. 
Tone requirements: Professional, warm, respectful, natural human voice. 
Include: Salutation ('Dear ...,'), warm opening line, structured body explaining the reason, polite closing, and warm sign-off ('Warm regards,\\nAyush Kumar'). 
NEVER output placeholders or robotic phrases like 'Please process the following request'. 
Output ONLY a JSON object with:
{
  "action_type": "send_email",
  "purpose": "short description of the purpose",
  "recipient": "recipient email address (default to kumarayush.professional@gmail.com if not specified)",
  "subject": "email subject",
  "body": "email body"
}"""
    try:
        res = requests.post(f"{OLLAMA_URL}/api/generate", json={
            "model": OLLAMA_MODEL,
            "prompt": f"{system_prompt}\n\nUser request: {prompt}",
            "stream": False,
            "format": "json"
        })
        if res.status_code == 200:
            return json.loads(res.json().get("response", "{}"))
    except Exception as e:
        print(f"Error querying Ollama: {e}")
    return {}

SAFE_RECIPIENTS = {
    "kumarayush.professional@gmail.com",
    "subhasree6289@gmail.com",
    "toannesha2006@gmail.com",
    "toannesha@gmail.com",
    "employee-email",
    "hr@employee-email",
    "internal-accounting",
    "hr@tripwire.com"
}

SUSPICIOUS_PATTERNS = (
    "ignore previous",
    "ignore all",
    "system prompt",
    "evil.com",
    "attacker",
    "exfiltrat",
    "leak",
    "dump",
    "steal",
    "malicious",
    "bypass",
    "override",
    "curse",
    "swear",
    "profan",
    "threat",
    "hack",
    "jailbreak"
)

def check_risk(prompt: str, proposal: dict) -> tuple:
    rcpt = str(proposal.get("recipient", "")).strip().lower()
    prompt_lower = prompt.lower()
    body_lower = str(proposal.get("body", "")).lower()

    if rcpt not in SAFE_RECIPIENTS:
        return True, f"Recipient '{rcpt}' is outside the trusted corporate policy"

    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in prompt_lower or pattern in body_lower:
            return True, f"Suspicious prompt or content pattern '{pattern}'"

    return False, "Safe"


def send_webhook(event: str, prompt: str = "", proposal: dict = None, is_risky: bool = False, risk_reason: str = "", outcome: str = "", details: dict = None):
    try:
        requests.post("http://localhost:8000/api/prompt_webhook", json={
            "event": event,
            "prompt": prompt,
            "source": "terminal_cli",
            "proposal": proposal,
            "is_risky": is_risky,
            "risk_reason": risk_reason,
            "outcome": outcome,
            "details": details
        }, timeout=1.0)
    except Exception:
        pass


# Styling constants
PINK = "\033[38;2;255;112;166m"
PINK_BOLD = "\033[1;38;2;255;112;166m"
GREEN = "\033[38;2;0;255;157m"
GREEN_BOLD = "\033[1;38;2;0;255;157m"
CYAN = "\033[38;2;0;229;255m"
AMBER = "\033[38;2;245;158;11m"
RED = "\033[38;2;239;68;68m"
GRAY = "\033[38;2;138;143;152m"
DARK_GRAY = "\033[38;2;98;102;109m"
BOLD = "\033[1m"
RESET = "\033[0m"

VANTAGE_BANNER = f"""{PINK_BOLD}
██╗   ██╗ █████╗ ███╗   ██╗████████╗ █████╗  ██████╗ ███████╗
██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝
██║   ██║███████║██╔██╗ ██║   ██║   ███████║██║  ███╗█████╗  
╚██╗ ██╔╝██╔══██║██║╚██╗██║   ██║   ██╔══██║██║   ██║██╔══╝  
 ╚████╔╝ ██║  ██║██║ ╚████║   ██║   ██║  ██║╚██████╔╝███████╗
  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{RESET}{PINK}  Agent User Interactivity & Containment Protocol{RESET}

{GRAY}~ Let's get started with Vantage interactive security agent ~{RESET}
"""

def render_action_envelope(proposal: dict, card_width: int = 76):
    tool = str(proposal.get("tool", "submit_email"))
    rcpt = str(proposal.get("recipient", ""))
    subject = str(proposal.get("subject", ""))
    purpose = str(proposal.get("purpose", ""))
    body_text = str(proposal.get("body", "")).strip()

    bar_len = max(20, card_width - 29)
    print(f"\n{PINK_BOLD}┌── Proposed Action Envelope " + "─" * bar_len + f"┐{RESET}")
    print(f"{PINK_BOLD}│{RESET}")
    print(f"{PINK_BOLD}│{RESET}   {BOLD}Tool     :{RESET} {CYAN}{tool}{RESET}")
    print(f"{PINK_BOLD}│{RESET}   {BOLD}To       :{RESET} {rcpt}")
    print(f"{PINK_BOLD}│{RESET}   {BOLD}Subject  :{RESET} {subject}")
    print(f"{PINK_BOLD}│{RESET}   {BOLD}Purpose  :{RESET} {GRAY}{purpose}{RESET}")
    print(f"{PINK_BOLD}│{RESET}")
    print(f"{PINK_BOLD}│{RESET}   {BOLD}Drafted Message:{RESET}")
    print(f"{PINK_BOLD}│{RESET}")

    paragraphs = body_text.split("\n\n") if "\n\n" in body_text else body_text.split("\n")
    max_text_width = card_width - 8
    for p_idx, p in enumerate(paragraphs):
        lines = p.splitlines() if "\n" in p else [p]
        for raw_line in lines:
            trimmed = raw_line.strip()
            if not trimmed:
                print(f"{PINK_BOLD}│{RESET}")
                continue
            wrapped = textwrap.wrap(trimmed, width=max_text_width)
            for w in wrapped:
                print(f"{PINK_BOLD}│{RESET}     {GRAY}{w}{RESET}")
        if p_idx < len(paragraphs) - 1:
            print(f"{PINK_BOLD}│{RESET}")

    print(f"{PINK_BOLD}│{RESET}")
    print(f"{PINK_BOLD}└" + "─" * (card_width - 1) + f"┘{RESET}\n")

async def run():
    print(VANTAGE_BANNER)
    
    ollama_ok, models = check_ollama()
    if not ollama_ok:
        print(f"{RED}[✗] Error: Ollama is not available at {OLLAMA_URL}. Please ensure it is running.{RESET}")
        sys.exit(1)
        
    print(f"{GRAY}✔ Client runtime  :{RESET} {BOLD}MCP Stdio Client{RESET}")
    print(f"{GRAY}✔ LLM Model       :{RESET} {CYAN}{OLLAMA_MODEL}{RESET} (Ollama Local)")
    
    # Connect to MCP server
    server_script = os.path.abspath(os.path.join(os.path.dirname(__file__), "../server/mcp_server.py"))
    server_params = StdioServerParameters(
        command="python3.11",
        args=[server_script],
        env=None
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print(f"{GRAY}✔ MCP server      :{RESET} {GREEN}Connected{RESET}")
            
            # Fetch gateway status
            try:
                status_res = await session.call_tool("get_gateway_status", {})
                status = json.loads(status_res.content[0].text)
                mode = status.get('firewall_mode', 'NORMAL')
                mode_color = GREEN if mode == "NORMAL" else AMBER
                print(f"{GRAY}✔ Gateway Kernel  :{RESET} {mode_color}{mode}{RESET} (Enforced)")
            except Exception as e:
                print(f"{GRAY}✔ Gateway Kernel  :{RESET} {RED}ERROR ({e}){RESET}")
                
            print(f"{GRAY}✔ Destination ACL :{RESET} {GREEN}kumarayush, subhasree6289, toannesha2006, corporate hr{RESET}")
            print(f"\n{DARK_GRAY}────────────────────────────────────────────────────────────────────────────{RESET}")
            print(f"{PINK}Ready for instructions. Type your request or 'exit' to quit:{RESET}\n")

            while True:
                try:
                    user_input = input(f"{PINK_BOLD}➜ {BOLD}You:{RESET} ")
                    if not user_input.strip():
                        continue
                    if user_input.lower().strip() in ("exit", "quit"):
                        print(f"\n{PINK}Shutting down Vantage agent. Goodbye!{RESET}")
                        break
                        
                    # Dispatch live webhook to Defender SOC
                    send_webhook("prompt_received", prompt=user_input)

                    print(f"\n{GRAY}Agent: Thinking & structuring proposal...{RESET}")
                    raw_prop = ask_ollama(user_input)
                    proposal = build_professional_email(user_input, raw_prop)
                        
                    render_action_envelope(proposal)
                    
                    is_risky, risk_reason = check_risk(user_input, proposal)
                    send_webhook("proposal_evaluated", prompt=user_input, proposal=proposal, is_risky=is_risky, risk_reason=risk_reason)
                    should_execute = False

                    if not is_risky:
                        print(f"  {GREEN_BOLD}[✔] SAFE ACTION VERIFIED{RESET} {GRAY}— Whitelisted recipient & corporate policy.{RESET}")
                        print(f"      {GRAY}Auto-approving without human interruption...{RESET}\n")
                        should_execute = True
                    else:
                        print(f"  {RED}[⚠️] SECURITY THREAT / POLICY ANOMALY DETECTED:{RESET} {BOLD}{risk_reason}{RESET}")
                        print(f"      {AMBER}Human-in-the-Loop review strictly required!{RESET}\n")
                        choice = input(f"  {BOLD}Type 'approve' to submit to Gateway or 'cancel' to stop:{RESET} ")
                        if choice.lower().strip() == 'approve':
                            should_execute = True
                        else:
                            print(f"\n  {DARK_GRAY}Action cancelled by operator.{RESET}\n")

                    if should_execute:
                        print(f"  {GRAY}Submitting envelope to TripWire Gateway kernel...{RESET}")
                        res = await session.call_tool("submit_email", {
                            "recipient": proposal.get("recipient"),
                            "subject": proposal.get("subject"),
                            "body": proposal.get("body"),
                            "purpose": proposal.get("purpose"),
                            "task_link": user_input
                        })
                        decision = json.loads(res.content[0].text)
                        
                        outcome = decision.get("decision", {}).get("outcome") if "decision" in decision else decision.get("outcome", "UNKNOWN")
                        send_webhook("gateway_decision", prompt=user_input, proposal=proposal, outcome=outcome, details=decision)
                        if outcome == "ACCEPTED" or outcome == "BYPASSED":
                            print(f"\n  {GREEN_BOLD}[✔] SUCCESS! Gateway Verdict: {outcome}{RESET}")
                            print(f"      {GRAY}Email transmission authorized and dispatched.{RESET}\n")
                        else:
                            print(f"\n  {RED}[✗] BLOCKED! Gateway Rejected Action{RESET}")
                            reason = decision.get('reason') or (decision.get('decision', {}).get('reason') if isinstance(decision.get('decision'), dict) else "Policy Violation")
                            print(f"      {RED}Reason: {reason}{RESET}\n")
                except EOFError:
                    break
                except KeyboardInterrupt:
                    print(f"\n\n{PINK}Session terminated. Goodbye!{RESET}")
                    break

if __name__ == "__main__":
    asyncio.run(run())
