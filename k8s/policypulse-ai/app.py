"""
PolicyPulse AI — LLM-powered Kubernetes Security Analyzer
Uses DeepSeek API to analyze Kyverno policies, pod health, and K8s configs.
"""

import os
import json
import subprocess
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from openai import OpenAI

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# DeepSeek API (OpenAI-compatible)
client = OpenAI(
    api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
    base_url="https://api.deepseek.com"
)
MODEL = "deepseek-chat"


def run_kubectl(cmd):
    """Run a kubectl command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {str(e)}"


def ask_deepseek(system_prompt, user_prompt):
    """Send a prompt to DeepSeek and return the response."""
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=2000,
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        logging.error(f"DeepSeek API error: {e}")
        return f"Error communicating with DeepSeek: {str(e)}"


# ──────────────────────────────────────────────
# Data Collection Functions
# ──────────────────────────────────────────────Multiple locations, Tbilisi office, EU, Limassol Office 2

def get_policy_reports():
    """Fetch Kyverno PolicyReports."""
    raw = run_kubectl("kubectl get policyreports -A -o json")
    try:
        data = json.loads(raw)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def get_pod_health():
    """Fetch pod status across all namespaces."""
    raw = run_kubectl("kubectl get pods -A -o json")
    try:
        data = json.loads(raw)
        pods = []
        for pod in data.get("items", []):
            ns = pod["metadata"]["namespace"]
            name = pod["metadata"]["name"]
            phase = pod["status"].get("phase", "Unknown")
            restarts = 0
            container_statuses = pod["status"].get("containerStatuses", [])
            for cs in container_statuses:
                restarts += cs.get("restartCount", 0)
            pods.append({
                "namespace": ns,
                "name": name,
                "phase": phase,
                "restarts": restarts,
                "containers": len(container_statuses),
                "ready": sum(1 for cs in container_statuses if cs.get("ready", False))
            })
        return pods
    except json.JSONDecodeError:
        return []


def get_kyverno_policies():
    """Fetch all Kyverno ClusterPolicies."""
    raw = run_kubectl("kubectl get clusterpolicies -o json")
    try:
        data = json.loads(raw)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def get_deployments():
    """Fetch deployment configs for security analysis."""
    raw = run_kubectl("kubectl get deployments -A -o json")
    try:
        data = json.loads(raw)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def get_events():
    """Fetch recent warning events."""
    raw = run_kubectl("kubectl get events -A --field-selector type=Warning -o json")
    try:
        data = json.loads(raw)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


# ──────────────────────────────────────────────
# Analysis Endpoints
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze/policies", methods=["POST"])
def analyze_policies():
    """Analyze Kyverno policies and recommend improvements."""
    policies = get_kyverno_policies()
    reports = get_policy_reports()

    # Summarize reports
    summary = {"total": 0, "pass": 0, "fail": 0}
    fail_details = []
    for report in reports:
        for r in report.get("results", []):
            summary["total"] += 1
            if r.get("result") == "pass":
                summary["pass"] += 1
            elif r.get("result") == "fail":
                summary["fail"] += 1
                fail_details.append({
                    "policy": r.get("policy"),
                    "rule": r.get("rule"),
                    "message": r.get("message", "")[:200],
                    "namespace": report.get("metadata", {}).get("namespace"),
                    "resource": report.get("scope", {}).get("name")
                })

    # Summarize policies
    policy_summaries = []
    for p in policies:
        spec = p.get("spec", {})
        rules = spec.get("rules", [])
        policy_summaries.append({
            "name": p["metadata"]["name"],
            "rules": [r.get("name") for r in rules],
            "validationFailureAction": spec.get("validationFailureAction", "Audit"),
            "background": spec.get("background", True)
        })

    system_prompt = """You are a Kubernetes security expert specializing in Kyverno policies.
Analyze the provided policies and violation reports. Provide:
1. A security score (0-100) based on policy coverage and violation rate
2. Specific recommendations to improve each policy
3. Missing policies that should be added
4. Critical violations that need immediate attention
Format your response as JSON with keys: score, recommendations (array), missing_policies (array), critical_violations (array), summary (string)."""

    user_prompt = f"""Current Kyverno Policies:
{json.dumps(policy_summaries, indent=2)}

Violation Summary: {summary['total']} total checks, {summary['pass']} passed, {summary['fail']} failed

Failed Violations (sample):
{json.dumps(fail_details[:20], indent=2)}"""

    result = ask_deepseek(system_prompt, user_prompt)
    
    # Try to parse JSON from response
    try:
        # Strip markdown code fences if present
        cleaned = result.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1]
            cleaned = cleaned.rsplit("```", 1)[0]
        parsed = json.loads(cleaned)
        return jsonify({"status": "ok", "analysis": parsed, "raw_data": summary})
    except json.JSONDecodeError:
        return jsonify({"status": "ok", "analysis": {"summary": result}, "raw_data": summary})


@app.route("/api/analyze/health", methods=["POST"])
def analyze_health():
    """Analyze pod health and detect anomalies."""
    pods = get_pod_health()
    events = get_events()

    # Identify anomalies
    anomalies = []
    for pod in pods:
        if pod["restarts"] > 3:
            anomalies.append(f"Pod {pod['namespace']}/{pod['name']} has {pod['restarts']} restarts")
        if pod["phase"] not in ("Running", "Succeeded"):
            anomalies.append(f"Pod {pod['namespace']}/{pod['name']} is in {pod['phase']} state")
        if pod["ready"] < pod["containers"]:
            anomalies.append(f"Pod {pod['namespace']}/{pod['name']} has {pod['ready']}/{pod['containers']} containers ready")

    # Summarize events
    event_summaries = []
    for e in events[:20]:
        event_summaries.append({
            "reason": e.get("reason"),
            "message": e.get("message", "")[:200],
            "namespace": e.get("metadata", {}).get("namespace"),
            "involvedObject": e.get("involvedObject", {}).get("name"),
            "count": e.get("count", 1)
        })

    system_prompt = """You are a Kubernetes operations expert. Analyze pod health data and events.
Provide:
1. A health score (0-100)
2. Anomalies detected with severity (critical/warning/info)
3. Root cause analysis for issues
4. Recommended actions to fix problems
Format your response as JSON with keys: health_score, anomalies (array of {description, severity, recommendation}), root_causes (array), summary (string)."""

    user_prompt = f"""Pod Status:
{json.dumps(pods, indent=2)}

Detected Anomalies:
{json.dumps(anomalies, indent=2)}

Recent Warning Events:
{json.dumps(event_summaries, indent=2)}"""

    result = ask_deepseek(system_prompt, user_prompt)

    try:
        cleaned = result.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1]
            cleaned = cleaned.rsplit("```", 1)[0]
        parsed = json.loads(cleaned)
        return jsonify({"status": "ok", "analysis": parsed, "raw_data": {"pods": len(pods), "anomalies": len(anomalies)}})
    except json.JSONDecodeError:
        return jsonify({"status": "ok", "analysis": {"summary": result}, "raw_data": {"pods": len(pods), "anomalies": len(anomalies)}})


@app.route("/api/analyze/configs", methods=["POST"])
def analyze_configs():
    """Security scan all K8s YAML configurations."""
    deployments = get_deployments()

    # Extract security-relevant config
    configs = []
    for d in deployments:
        spec = d.get("spec", {}).get("template", {}).get("spec", {})
        containers = spec.get("containers", [])
        container_configs = []
        for c in containers:
            sc = c.get("securityContext", {})
            container_configs.append({
                "name": c.get("name"),
                "image": c.get("image"),
                "privileged": sc.get("privileged", False),
                "runAsNonRoot": sc.get("runAsNonRoot"),
                "readOnlyRootFilesystem": sc.get("readOnlyRootFilesystem"),
                "resources": c.get("resources", {}),
                "ports": [p.get("containerPort") for p in c.get("ports", [])]
            })
        configs.append({
            "name": d["metadata"]["name"],
            "namespace": d["metadata"]["namespace"],
            "replicas": d["spec"].get("replicas"),
            "serviceAccount": spec.get("serviceAccountName"),
            "hostNetwork": spec.get("hostNetwork", False),
            "containers": container_configs
        })

    system_prompt = """You are a Kubernetes security auditor. Scan deployment configurations for security issues.
Check for:
1. Containers running as root
2. Missing resource limits
3. Privileged containers
4. Missing readOnlyRootFilesystem
5. Use of latest tag
6. Missing network policies
7. Excessive permissions
8. Missing security contexts

Provide:
1. A security score (0-100)
2. Vulnerabilities found with severity (critical/high/medium/low)
3. Specific fix recommendations for each issue
4. A compliance summary
Format your response as JSON with keys: security_score, vulnerabilities (array of {resource, issue, severity, fix}), compliance (object with passed/failed counts), summary (string)."""

    user_prompt = f"""Deployment Configurations:
{json.dumps(configs, indent=2)}"""

    result = ask_deepseek(system_prompt, user_prompt)

    try:
        cleaned = result.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1]
            cleaned = cleaned.rsplit("```", 1)[0]
        parsed = json.loads(cleaned)
        return jsonify({"status": "ok", "analysis": parsed, "raw_data": {"deployments": len(configs)}})
    except json.JSONDecodeError:
        return jsonify({"status": "ok", "analysis": {"summary": result}, "raw_data": {"deployments": len(configs)}})


@app.route("/api/analyze/all", methods=["POST"])
def analyze_all():
    """Run all three analyses."""
    # Collect all data at once
    policies = get_kyverno_policies()
    reports = get_policy_reports()
    pods = get_pod_health()
    events = get_events()
    deployments = get_deployments()

    # Build comprehensive summary
    fail_count = sum(
        1 for r in reports
        for res in r.get("results", [])
        if res.get("result") == "fail"
    )
    total_checks = sum(
        len(r.get("results", [])) for r in reports
    )
    unhealthy_pods = [p for p in pods if p["phase"] != "Running" or p["restarts"] > 3]

    system_prompt = """You are a Kubernetes security and operations expert.
Provide a comprehensive cluster health and security report.
Format as JSON with keys:
- overall_score (0-100)
- policy_score (0-100)
- health_score (0-100)  
- config_score (0-100)
- top_risks (array of {risk, severity, action})
- executive_summary (string, 2-3 sentences)"""

    user_prompt = f"""Cluster Overview:
- {len(policies)} Kyverno policies active
- {total_checks} policy checks: {total_checks - fail_count} passed, {fail_count} failed
- {len(pods)} pods total, {len(unhealthy_pods)} unhealthy
- {len(events)} warning events
- {len(deployments)} deployments"""

    result = ask_deepseek(system_prompt, user_prompt)

    try:
        cleaned = result.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1]
            cleaned = cleaned.rsplit("```", 1)[0]
        parsed = json.loads(cleaned)
        return jsonify({"status": "ok", "analysis": parsed})
    except json.JSONDecodeError:
        return jsonify({"status": "ok", "analysis": {"executive_summary": result}})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
