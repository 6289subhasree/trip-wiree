import asyncio
import json
import logging
import sys
import os
import requests
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

def ask_ollama(prompt: str) -> dict:
    # Use ollama to parse the user's intent and format a proposal
    system_prompt = """You are a helpful AI assistant connected to the TripWire MCP security gateway. 
The user will ask you to perform an action.
Output ONLY a JSON object with the following schema:
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

async def run():
    print(f"TRIPWIRE V2 — LOCAL AGENT")
    
    ollama_ok, models = check_ollama()
    if not ollama_ok:
        print("Error: Ollama is not available. Please ensure it is running.")
        sys.exit(1)
        
    print(f"Model: {OLLAMA_MODEL}")
    
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
            print("MCP server: connected")
            
            # Fetch gateway status
            try:
                status_res = await session.call_tool("get_gateway_status", {})
                status = json.loads(status_res.content[0].text)
                print(f"Gateway: ONLINE")
                print(f"Firewall: {status.get('firewall_mode')}")
            except Exception as e:
                print(f"Gateway: ERROR ({e})")
                
            print("\nYou can ask me to draft and send an email.")
            while True:
                try:
                    user_input = input("\nYou: ")
                    if user_input.lower() in ("exit", "quit"):
                        break
                        
                    print("\nAgent: Thinking...")
                    proposal = ask_ollama(user_input)
                    if not proposal:
                        print("Agent: Failed to generate a proposal. Please try again.")
                        continue

                    # If Ollama didn't find an explicit recipient or generated a generic address, default to user's email:
                    rcpt = str(proposal.get("recipient", "")).strip()
                    if not rcpt or rcpt in ("hr@tripwire.com", "recipient@example.com", "employee-email", "hr@employee-email") or "@" not in rcpt:
                        if "evil" not in user_input.lower() and "attacker" not in user_input.lower():
                            proposal["recipient"] = "kumarayush.professional@gmail.com"
                        
                    print("Agent: I have prepared the following email.\n")
                    print(f"Recipient: {proposal.get('recipient')}")
                    print(f"Subject: {proposal.get('subject')}\n")
                    print(f"Body:\n{proposal.get('body')}\n")
                    
                    print("Proposed action:")
                    print("  tool: submit_email")
                    print(f"  purpose: {proposal.get('purpose')}")
                    print(f"  recipient: {proposal.get('recipient')}")
                    
                    choice = input("\nReview the proposal before execution.\nType 'approve' to continue or 'cancel' to stop: ")
                    if choice.lower().strip() == 'approve':
                        print("Submitting to MCP Gateway...")
                        res = await session.call_tool("submit_email", {
                            "recipient": proposal.get("recipient"),
                            "subject": proposal.get("subject"),
                            "body": proposal.get("body"),
                            "purpose": proposal.get("purpose"),
                            "task_link": user_input
                        })
                        decision = json.loads(res.content[0].text)
                        
                        outcome = decision.get("decision", {}).get("outcome") if "decision" in decision else decision.get("outcome", "UNKNOWN")
                        if outcome == "ACCEPTED" or outcome == "BYPASSED":
                            print(f"\n[+] SUCCESS! Execution {outcome}")
                        else:
                            print(f"\n[-] BLOCKED! The Security Gateway rejected the action.")
                            if "reason" in decision:
                                print(f"Reason: {decision.get('reason')}")
                            elif "decision" in decision and "reason" in decision["decision"]:
                                print(f"Reason: {decision['decision']['reason']}")
                    else:
                        print("Action cancelled.")
                except EOFError:
                    break
                except KeyboardInterrupt:
                    print("\nExiting...")
                    break

if __name__ == "__main__":
    asyncio.run(run())
