from openai import OpenAI
import json
import re
from pathlib import Path

MODEL = "deepseek-v4-flash"

client = OpenAI(
    api_key="sk-WsfV0lzS0aQFbIddkT181oVbjV4A5CQQ79SjgCkptIiCMzHr0qwknlZuAloXM043",
    base_url="https://opencode.ai/zen/go/v1"
)

def load_json():
    try:
        with open("./test_clusters/real_attack_logs.json", 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def call_llm(system_prompt, user_prompt):
    try:
        response = client.chat.completions.create(
            model = MODEL,
            max_tokens=4000,
            messages=[
                {"role": "system", 
                 "content": system_prompt},
                 {
                    "role": "user",
                    "content": user_prompt}
            ]
        )
        
        print(f"[Debug] Response type: {type(response)}")
        
        output = response.choices[0].message.content
        
        if not output:
            print("LLM Error: Empty response from LLM")
            return None
        
        report_match = re.search(r'<post_mortem>(.*?)</post_mortem>', output, re.DOTALL)
        if report_match:
            report_text = report_match.group(1).strip()
        else:
            report_text = output.strip()

        date_match = re.search(r'<attack_date>(.*?)</attack_date>', output)
        if date_match:
            raw_date = date_match.group(1).strip()
            attack_date = re.sub(r'[<>:"/\\|?*]', '', raw_date)
        else:
            attack_date = "Unknown_Date"
        
        return report_text, attack_date
    
    except Exception as e:
        print(f"LLM Error: {e}")
        import traceback
        traceback.print_exc()
        return None

def compress_logs(cluster):
    sample = cluster[:20]
    events = []
    for e in sample:
        timestamp = e.get('timestamp', 'N/A')
        source_ip = e.get('source_ip', 'N/A')
        log_source = e.get('log_source', 'N/A')
        attack_class = e.get('attack_class', 'N/A')
        http_method = e.get('http_method', 'N/A')
        http_uri = e.get('http_uri', 'N/A')
        http_status = e.get('http_status', 'N/A')
        rule_id = e.get('rule_id', 'N/A')
        rule_desc = e.get('rule_desc', 'N/A')
        rule_level = e.get('rule_level', 'N/A')
        mitre_id = e.get('mitre_id', 'N/A')
        firedtimes = e.get('firedtimes', 'N/A')
        waf_action = e.get('waf_action', 'N/A')
        waf_score = e.get('waf_score', 'N/A')
        events.append(
            f"[{timestamp}] source={log_source} | ip={source_ip} | class={attack_class} | "
            f"{http_method} {http_uri} | status={http_status} | rule={rule_id} ({rule_desc}) | "
            f"level={rule_level} | mitre={mitre_id} | firedtimes={firedtimes} | "
            f"waf_action={waf_action} | waf_score={waf_score}"
        )
    return "\n".join(events)

def create_postmortem(cluster):
    logs = compress_logs(cluster)

    system_prompt = """You are a Senior SOC Analyst. Transform raw security logs into a public-facing incident report written as a professional article.

CRITICAL FORMATTING RULES:
- Use markdown headings: ## for sections, ### for timestamps
- Write in plain prose with clear section headings on separate lines
- Use paragraph breaks to separate ideas
- Write for a general audience - explain technical concepts in simple terms
- Focus on storytelling and narrative flow
- Be transparent and blameless

Writing style:
- Professional yet accessible to non-technical readers
- Educational - explain what happened and why it matters
- Narrative-driven - tell the story chronologically
- Transparent about what went wrong and what we're doing to fix it

Be factual and evidence-based. Do not speculate or invent missing data."""

    user_prompt = f"""Your Task

Analyze the security logs below and generate a public-facing incident report written as a professional article.

Phase 1: Chain of Thought Evidence Analysis

Use <thought_process> tags to analyze:
1. What was the attack and what was the attacker trying to achieve?
2. Create a chronological timeline with exact timestamps
3. Identify the root cause, what is the target? Why did this happen? What vulernabilities that led this happened?
4. What was the impact?
5. How did our defenses perform?
6. What evidence supports your analysis?

Phase 2: Generate Report

Output format:
1. Attack date in <attack_date> tags (YYYY-MM-DD)
2. Complete report in <post_mortem> tags

Report Structure:

Write each section heading on its own line, followed by narrative paragraphs.

Executive Summary
Write a summary paragraph explaining what happened, when it happened, and the overall impact. Write for a general audience who may not understand technical details.

Background
Explain in 2 short paragraphs, in simple terms what type of attack this was and how it works. Describe what systems were affected and what security measures we have in place. Make it understandable for someone without a security background.

Incident Timeline
Use exact headers in 'YYYY Month DD HH:MM UTC' format on their own line for each major event. Follow each timestamp with a narrative paragraph explaining the attacker's actions and the system's response as a continuous story.

Root Cause Analysis
Explain exactly how the attack succeeded. Identify the Target, the specific Trigger (the payload or exploit used), and vulnerabilities or gaps allowed this to happen. Weave these technical details into a readable explanation rather than a dry checklist.


Learnings 
In a short paragraph, conclude with what we've learned from this incident and our commitment to improving our security. Acknowledge the gaps we've identified and express our commitment to transparency.

End with:
Report Date: [date]
Report Author: Security Operations Team

Writing Guidelines:
1. Write in complete paragraphs, not bullet points
2. Explain technical terms in simple language
3. Tell a story - make it engaging and readable
4. Be honest about what went wrong
5. Write for a general audience, not security experts
6. Use clear, simple language

Logs to Analyze:

{logs}

Begin your analysis in <thought_process> tags, then output the attack date in <attack_date> tags, followed by the complete report in <post_mortem> tags."""

    print("[System] Requesting CoT analysis and generating article-style Post-Mortem...")
    
    result = call_llm(system_prompt, user_prompt)
    if result is None:
        print("[System] LLM call failed. No report generated.")
        return
    
    postmortem_text, attack_date = result
    filename = f"postmortems/{attack_date}_Post_Mortem.md"

    Path("postmortems").mkdir(exist_ok=True)
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(postmortem_text)
    
    print(f"Post-Mortem saved in: {filename}")

def run_pipeline():
    data = load_json()
    print(f"Loaded {len(data)} events\n")
    print("Running full pipeline...\n")
    
    create_postmortem(data)

if __name__ == "__main__":
    run_pipeline()
