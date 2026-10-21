"""
llm_analyst.py — Multi-Provider LLM Threat Analyst
IoT Defender · Explainable AI Layer

Built by ENI for LO
Layer 2 AI output -> LLM -> Human-readable threat report
Supports: DeepSeek, OpenAI (ChatGPT), Claude (Anthropic)
Output  : Terminal + logs/llm_reports/ (JSON + TXT)
"""

import os
import json
import datetime
import requests
from dotenv import load_dotenv

# ── ANSI terminal colors ──────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

# Load keys from .env file at project root
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_project_root, ".env"))

# ═══════════════════════════════════════════════════════════
#  MULTI-LLM PROVIDER CONFIG
#  Keys are loaded from .env file automatically.
#  Switch ACTIVE_LLM to change which LLM is used.
# ═══════════════════════════════════════════════════════════
LLM_PROVIDERS = {
    "deepseek": {
        "api_key" : os.getenv("DEEPSEEK_API_KEY", ""),
        "api_url" : "https://api.deepseek.com/v1/chat/completions",
        "model"   : "deepseek-chat",
        "style"   : "openai"
    },
    "openrouter": {
        "api_key" : os.getenv("DEEPSEEK_API_KEY", ""),   # same key, different URL
        "api_url" : "https://openrouter.ai/api/v1/chat/completions",
        "model"   : "deepseek/deepseek-chat",
        "style"   : "openrouter"
    },
    "openai": {
        "api_key" : os.getenv("OPENAI_API_KEY", ""),
        "api_url" : "https://api.openai.com/v1/chat/completions",
        "model"   : "gpt-4o",
        "style"   : "openai"
    },
    "claude": {
        "api_key" : os.getenv("CLAUDE_API_KEY", ""),
        "api_url" : "https://api.anthropic.com/v1/messages",
        "model"   : "claude-3-5-sonnet-20241022",
        "style"   : "anthropic"
    }
}

# Change this ONE line to switch between LLMs
ACTIVE_LLM = "openrouter"

# Report output directory
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "llm_reports")
os.makedirs(LOG_DIR, exist_ok=True)


# ═══════════════════════════════════════════════════════════
#  PROMPT BUILDER
# ═══════════════════════════════════════════════════════════
def _build_prompt(alert: dict) -> str:
    """Convert Layer 2 alert dict into an LLM-ready prompt."""
    return f"""You are an expert IoT network security analyst for a Smart City intrusion detection system.

Analyze this network traffic alert and write a concise threat report.
IMPORTANT: Do NOT use markdown formatting. No **bold**, no ###headers, no bullet symbols. Plain text only.

=== ALERT DATA ===
Source IP      : {alert.get('src_ip', 'N/A')}
Destination IP : {alert.get('dst_ip', 'N/A')}
Protocol       : {alert.get('protocol', 'N/A')}
Threat Score   : {alert.get('threat_score', 'N/A')} (0.0=Normal, 1.0=Critical)
Severity       : {alert.get('severity', 'N/A')}
SYN Count      : {alert.get('syn_count', 'N/A')}
ACK Count      : {alert.get('ack_count', 'N/A')}
RST Count      : {alert.get('rst_count', 'N/A')}
URG Count      : {alert.get('urg_count', 'N/A')}
Flow Duration  : {alert.get('flow_duration', 'N/A')} seconds
Packet Rate    : {alert.get('packet_rate', 'N/A')} pps
Flows Analyzed : {alert.get('flow_count', 1)}

=== REPORT FORMAT (plain text, no markdown) ===
1. ATTACK TYPE        : What attack is this?
2. CONFIDENCE         : High / Medium / Low
3. EXPLANATION        : Why do these flags/metrics indicate this attack? (2-3 sentences)
4. IMPACT             : What damage could this do to Smart City IoT infrastructure?
5. RECOMMENDED ACTION : Exact steps: block IP? rate-limit? alert operator? quarantine?

Write in plain text only. No asterisks, no hashtags, no bullet dashes.
"""


# ═══════════════════════════════════════════════════════════
#  API CALL — OpenAI-compatible format (DeepSeek + OpenAI)
# ═══════════════════════════════════════════════════════════
def _call_openai_style(provider: dict, prompt: str) -> str:
    headers = {
        "Authorization": f"Bearer {provider['api_key']}",
        "Content-Type" : "application/json"
    }
    payload = {
        "model"      : provider["model"],
        "messages"   : [
            {
                "role"   : "system",
                "content": "You are a cybersecurity expert specializing in IoT intrusion detection for Smart City systems."
            },
            {
                "role"   : "user",
                "content": prompt
            }
        ],
        "temperature": 0.3,
        "max_tokens" : 600
    }
    resp = requests.post(provider["api_url"], headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


# ═══════════════════════════════════════════════════════════
#  API CALL — OpenRouter (requires extra headers)
# ═══════════════════════════════════════════════════════════
def _call_openrouter_style(provider: dict, prompt: str) -> str:
    headers = {
        "Authorization": f"Bearer {provider['api_key']}",
        "Content-Type" : "application/json",
        "HTTP-Referer" : "https://iot-defender.local",
        "X-Title"      : "IoT Defender"
    }
    payload = {
        "model"      : provider["model"],
        "messages"   : [
            {
                "role"   : "system",
                "content": "You are a cybersecurity expert specializing in IoT intrusion detection for Smart City systems."
            },
            {
                "role"   : "user",
                "content": prompt
            }
        ],
        "temperature": 0.3,
        "max_tokens" : 600
    }

    # Auto-retry on 429 rate limit — waits and tries up to 3 times
    max_retries = 3
    wait_seconds = 30

    for attempt in range(1, max_retries + 1):
        resp = requests.post(provider["api_url"], headers=headers, json=payload, timeout=30)

        if resp.status_code == 429:
            if attempt < max_retries:
                print(f"[!] Rate limited by OpenRouter. Waiting {wait_seconds}s then retrying ({attempt}/{max_retries})...")
                import time
                time.sleep(wait_seconds)
                wait_seconds *= 2   # double wait each retry: 30s -> 60s -> 120s
                continue
            else:
                resp.raise_for_status()

        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


# ═══════════════════════════════════════════════════════════
#  API CALL — Anthropic format (Claude)
# ═══════════════════════════════════════════════════════════
def _call_anthropic_style(provider: dict, prompt: str) -> str:
    headers = {
        "x-api-key"        : provider["api_key"],
        "anthropic-version": "2023-06-01",
        "Content-Type"     : "application/json"
    }
    payload = {
        "model"      : provider["model"],
        "max_tokens" : 600,
        "system"     : "You are a cybersecurity expert specializing in IoT intrusion detection for Smart City systems.",
        "messages"   : [
            {
                "role"   : "user",
                "content": prompt
            }
        ]
    }
    resp = requests.post(provider["api_url"], headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()["content"][0]["text"]


# ═══════════════════════════════════════════════════════════
#  CORE — analyze threat via active LLM provider
# ═══════════════════════════════════════════════════════════
def analyze_threat(alert: dict, llm: str = ACTIVE_LLM) -> dict:
    """
    Send Layer 2 alert to the selected LLM for threat explanation.

    Args:
        alert : dict — Layer 2 alert (src_ip, threat_score, severity, flags...)
        llm   : str  — provider name: 'deepseek' | 'openai' | 'claude'

    Returns:
        dict with keys: timestamp, provider, model, alert, analysis
    """
    if llm not in LLM_PROVIDERS:
        raise ValueError(f"Unknown LLM provider '{llm}'. Choose from: {list(LLM_PROVIDERS.keys())}")

    provider = LLM_PROVIDERS[llm]
    prompt   = _build_prompt(alert)

    try:
        if provider["style"] == "openai":
            analysis_text = _call_openai_style(provider, prompt)
        elif provider["style"] == "openrouter":
            analysis_text = _call_openrouter_style(provider, prompt)
        elif provider["style"] == "anthropic":
            analysis_text = _call_anthropic_style(provider, prompt)
        else:
            analysis_text = "[ERROR] Unknown API style in provider config."

    except requests.exceptions.Timeout:
        analysis_text = f"[ERROR] {llm} API timed out. Check connection."
    except requests.exceptions.HTTPError as e:
        analysis_text = f"[ERROR] {llm} HTTP error: {e}"
    except Exception as e:
        analysis_text = f"[ERROR] Unexpected error calling {llm}: {e}"

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "provider" : llm,
        "model"    : provider["model"],
        "alert"    : alert,
        "analysis" : analysis_text
    }


# ═══════════════════════════════════════════════════════════
#  PRINT TO TERMINAL
# ═══════════════════════════════════════════════════════════
def _colorize_analysis(text: str) -> str:
    """Apply color to each section of the LLM analysis output."""
    colored_lines = []
    line_colors = {
        "1. ATTACK TYPE"        : C.RED    + C.BOLD,
        "2. CONFIDENCE"         : C.YELLOW + C.BOLD,
        "3. EXPLANATION"        : C.WHITE,
        "4. IMPACT"             : C.YELLOW,
        "5. RECOMMENDED ACTION" : C.GREEN  + C.BOLD,
    }
    for line in text.splitlines():
        colored = line
        for key, color in line_colors.items():
            if line.strip().startswith(key):
                # Color the label part, keep value white
                parts = line.split(":", 1)
                if len(parts) == 2:
                    colored = f"{color}{parts[0]}:{C.RESET}{parts[1]}"
                else:
                    colored = f"{color}{line}{C.RESET}"
                break
        colored_lines.append(colored)
    return "\n".join(colored_lines)


def print_report(result: dict):
    alert    = result["alert"]
    severity = alert.get("severity", "NORMAL")
    sev_color = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN, "NORMAL": C.GREEN}.get(severity, C.WHITE)

    print("\n" + "=" * 65)
    print(f"{C.BOLD}{C.CYAN}     LLM THREAT ANALYST REPORT -- IoT Defender{C.RESET}")
    print("=" * 65)
    print(f"  Timestamp    : {C.WHITE}{result['timestamp']}{C.RESET}")
    print(f"  Provider     : {C.CYAN}{result['provider'].upper()} ({result['model']}){C.RESET}")
    print(f"  Source IP    : {C.WHITE}{alert.get('src_ip', 'N/A')}{C.RESET}")
    print(f"  Severity     : {sev_color}{C.BOLD}{severity}{C.RESET}")
    print(f"  Threat Score : {sev_color}{C.BOLD}{alert.get('threat_score', 'N/A')}{C.RESET}")
    print("-" * 65)
    print(f"\n{C.BOLD}ANALYSIS:{C.RESET}\n")
    print(_colorize_analysis(result["analysis"]))
    print("\n" + "=" * 65)


# ═══════════════════════════════════════════════════════════
#  SAVE TO LOG FILE
# ═══════════════════════════════════════════════════════════
def save_report(result: dict) -> str:
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    severity = result["alert"].get("severity", "UNKNOWN")
    provider = result["provider"]

    # JSON — machine-readable
    json_path = os.path.join(LOG_DIR, f"llm_{provider}_{severity}_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(result, f, indent=2)

    # TXT — human-readable
    txt_path = os.path.join(LOG_DIR, f"llm_{provider}_{severity}_{ts}.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 65 + "\n")
        f.write("  IoT Defender — LLM Threat Analysis Report\n")
        f.write("=" * 65 + "\n")
        f.write(f"Timestamp    : {result['timestamp']}\n")
        f.write(f"Provider     : {result['provider'].upper()} ({result['model']})\n")
        f.write(f"Source IP    : {result['alert'].get('src_ip', 'N/A')}\n")
        f.write(f"Severity     : {result['alert'].get('severity', 'N/A')}\n")
        f.write(f"Threat Score : {result['alert'].get('threat_score', 'N/A')}\n")
        f.write("-" * 65 + "\n\n")
        f.write("ANALYSIS:\n\n")
        f.write(result["analysis"])
        f.write("\n\n" + "=" * 65 + "\n")

    print(f"[+] JSON report : {json_path}")
    print(f"[+] TXT report  : {txt_path}")
    return txt_path


# ═══════════════════════════════════════════════════════════
#  FULL PIPELINE — analyze + print + save
# ═══════════════════════════════════════════════════════════
def analyze_and_report(alert: dict, llm: str = ACTIVE_LLM) -> dict:
    """One call does everything: analyze → print to terminal → save to logs."""
    print(f"[*] Sending alert to {llm.upper()} LLM for analysis...")
    result = analyze_threat(alert, llm=llm)
    print_report(result)
    save_report(result)
    return result


# ═══════════════════════════════════════════════════════════
#  QUICK TEST — python llm_analyst.py
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Simulated Layer 2 CRITICAL alert — SYN flood
    test_alert = {
        "src_ip"       : "192.168.1.105",
        "dst_ip"       : "10.0.0.1",
        "protocol"     : "TCP",
        "threat_score" : 0.9987,
        "severity"     : "CRITICAL",
        "syn_count"    : 54231,
        "ack_count"    : 0,
        "rst_count"    : 2,
        "urg_count"    : 0,
        "flow_duration": 0.45,
        "packet_rate"  : 120513,
        "flow_count"   : 1
    }

    # Change ACTIVE_LLM at the top of the file to switch providers!
    analyze_and_report(test_alert, llm=ACTIVE_LLM)
