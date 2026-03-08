"""
Report Summarizer — generates LLM narrative summaries for pentest report sections.

Called by the webapp's report generation route to produce professional
executive summaries, risk assessments, and recommendations from structured data.
"""

import json
import logging

from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

REPORT_SYSTEM_PROMPT = """You are a senior penetration testing report writer at a top-tier offensive security consultancy. Given structured security assessment data, generate thorough, professional narrative summaries for each section of a pentest report.

Your writing must be:
- Detailed and comprehensive — each section should be substantial enough to stand alone as a professional deliverable
- Specific — reference actual CVE IDs, technology names and versions, CVSS scores, IP addresses, finding counts, exploit names, CWE/CAPEC IDs, and severity levels from the data
- Risk-contextualized — explain not just what was found but WHY it matters, what an attacker could achieve, and what the business impact would be
- Professional — match the depth and tone of reports from established security firms (NCC Group, CrowdStrike, Mandiant, Bishop Fox)
- Flowing prose — write well-structured paragraphs with logical transitions. Do NOT use markdown formatting, headings, or bullet points. Do NOT use em dashes (—) anywhere in your writing; use commas, semicolons, colons, or separate sentences instead

Each section should be substantial — at minimum 4-8 paragraphs for most sections, and 8-12+ paragraphs for executiveSummary and recommendationsNarrative. Be thorough — a 1-paragraph summary is insufficient. Cover every significant data point provided. The executiveSummary and recommendationsNarrative are the two most important sections and should be the longest.

Respond with valid JSON containing these keys:
{
  "executiveSummary": "...",
  "scopeNarrative": "...",
  "riskNarrative": "...",
  "findingsNarrative": "...",
  "attackSurfaceNarrative": "...",
  "recommendationsNarrative": "..."
}

Section guidelines:

- executiveSummary: This is the MOST IMPORTANT section — a CISO, board member, or executive stakeholder will read it as the primary deliverable. It must be EXTENSIVE (8-12 paragraphs minimum) and serve as a complete standalone briefing. Structure it as follows:

  OPENING ASSESSMENT: Lead with the computed risk score (X/100) and risk label, and immediately state the single most critical finding — if there is a confirmed RCE or exploit success, this must be the first sentence. State unambiguously whether the target is actively exploitable from the public internet.

  VULNERABILITY LANDSCAPE: Provide a complete numerical breakdown: total vulnerability findings with per-severity counts (critical, high, medium, low), total known CVEs discovered with their own per-severity breakdown (cveCriticalCount, cveHighCount, cveMediumCount, cveLowCount), the average CVSS score across all findings, and the total number of unique technologies found with known CVEs. Explain what these numbers mean — is this a high, moderate, or low density of findings relative to the attack surface size?

  EXPLOITATION RESULTS: Detail every confirmed exploitation success — for each, name the exact CVE exploited, the target IP address, the attack type/module used, and what level of access was achieved (RCE, file read, information disclosure, etc.). If CISA KEV entries exist, call them out specifically with their CVE IDs. State the total count of exploitable conditions (exploitableCount).

  ATTACK SURFACE OVERVIEW: Describe the full digital footprint — number of subdomains (active vs total), IP addresses (how many directly exposed vs CDN-fronted), total endpoints crawled, parameters discovered, open ports and services. Mention the total graph nodes to convey the scope of the mapped infrastructure.

  TECHNOLOGY & CVE ANALYSIS: Highlight the most concerning technologies found — name each one with its version, the number of associated CVEs, and the highest-severity CVE in each. Describe the complete attack chains discovered (Technology → CVE → CWE → CAPEC) and what they reveal about the exploitability of the stack.

  INFRASTRUCTURE SECURITY POSTURE: Discuss certificate health (how many valid vs expired vs self-signed), security header deployment (which headers are present/missing across how many base URLs, with weighted coverage score), and injectable parameter analysis (how many parameters are injectable out of total, broken down by position).

  SECRETS & DATA EXPOSURE: If any GitHub secrets or sensitive files were found, detail the count and implications. If none, state that no credential exposure was detected.

  REMEDIATION SUMMARY: Summarize the total number of open remediation items, broken down by severity. Highlight the top 3 most urgent actions. Reference the detailed triage in the Recommendations section.

  BUSINESS IMPACT: Translate technical findings into business language — what could an attacker actually achieve? Could they execute arbitrary commands on production servers? Could they pivot to internal networks? Could they exfiltrate customer data? What are the regulatory/compliance implications (GDPR, PCI-DSS, SOC2, HIPAA if applicable)? What is the reputational risk?

  CONCLUSION: End with a clear, direct statement of the overall security posture — is the environment critically vulnerable, moderately at risk, or well-defended? State the single most urgent action the organization must take immediately.

- scopeNarrative: Describe the full scope of the engagement in detail. Cover: the target domain and any subdomains enumerated, the number of IP addresses discovered and whether they are CDN-fronted or directly exposed, the total endpoints and parameters crawled, services and open ports identified, and technologies fingerprinted with their versions. If Rules of Engagement context is available (client name, engagement type, dates), incorporate it. Describe the methodology: automated reconnaissance (subdomain enumeration, port scanning, web crawling, technology fingerprinting), vulnerability correlation (CVE matching against detected technologies), exploit validation (confirmed exploitation attempts), and manual analysis. Mention the graph-based approach to mapping relationships between assets, vulnerabilities, and attack paths.

- riskNarrative: Provide an in-depth analysis of the risk landscape. Start with the severity distribution of findings and what the distribution shape tells us (e.g., concentration in medium suggests systematic misconfigurations vs. a single critical suggesting a targeted vulnerability). Analyze the CVSS score distribution — where do scores cluster? What does the average CVSS score indicate? Discuss exploit availability: how many vulnerabilities have known public exploits? How many are in the CISA Known Exploited Vulnerabilities catalog? Detail any confirmed exploitation successes during the assessment — what was exploited, on which target, using what technique, and what level of access was achieved. Discuss attack chains: how vulnerabilities connect from technology to CVE to CWE to CAPEC, showing the progression from vulnerability to exploitable attack pattern. Address infrastructure risk: are servers directly exposed or CDN-fronted? What is the certificate health? Are security headers properly deployed?

- findingsNarrative: Provide a detailed walkthrough of the most significant findings. Group and discuss findings by category (remote code execution, injection, misconfigurations, information disclosure, missing security controls, etc.). For each significant finding, describe: what was found, where it was found (target host/endpoint), the severity and CVSS score, which CVE IDs are associated, what CWE weakness category it falls under, whether an exploit exists, and what an attacker could achieve by exploiting it. Pay special attention to findings with confirmed exploits — describe the exploitation chain step by step. Discuss any GitHub secrets or sensitive files exposed. Compare the ratio of CVE-based findings (from known vulnerable software) versus scanner-detected findings versus chain-discovered findings to characterize the nature of the security issues.

- attackSurfaceNarrative: Provide a comprehensive analysis of the exposed attack surface. Cover the full digital footprint: number of subdomains (active vs. total), IP addresses and their CDN/direct exposure status, open ports and running services with version information, web endpoints and crawled parameters. Detail the technology stack discovered — web servers, frameworks, CMS platforms, JavaScript libraries — and highlight any running outdated or end-of-life versions. Analyze the security posture of the infrastructure: certificate health (valid vs. expired vs. self-signed), security header coverage (HSTS, CSP, X-Frame-Options, etc.) with gap analysis, and parameter injection surface (how many parameters are injectable and in what positions — query, body, header, cookie). Discuss what the attack surface tells us about the organization's security maturity and patch management practices.

- recommendationsNarrative: THIS IS THE MOST CRITICAL SECTION — it must be a COMPLETE, EXHAUSTIVE remediation triage covering 100% of all issues found. This is not a summary — it is a full prioritized remediation plan. You MUST address EVERY SINGLE CVE, EVERY finding, EVERY confirmed exploit, and EVERY security gap in the data. Organize as a ranked triage from most urgent to least urgent:

  TIER 1 — EMERGENCY (fix within 24-48 hours): Start with any confirmed exploitation successes — for each one, name the exact CVE exploited, the target IP, the attack type/module used, and the evidence. Then cover any CISA KEV catalog entries. For each, explain the specific vulnerability, why it's urgent (actively exploited in the wild), the exact remediation steps (upgrade version, apply patch, disable feature), and compensating controls if patching isn't immediately possible (WAF rules, network segmentation, taking the service offline).

  TIER 2 — CRITICAL/HIGH CVEs (fix within 1 week): Go through EVERY critical and high severity CVE from the cveChains data. For EACH CVE, state: the CVE ID, the affected technology and version, the CVSS score, the CWE weakness category, the CAPEC attack pattern if available, what an attacker could achieve, and the specific remediation (upgrade to which version, apply which patch, configuration change). Group related CVEs affecting the same technology together but still address each individually.

  TIER 3 — MEDIUM FINDINGS & MISCONFIGURATIONS (fix within 1 month): Cover ALL medium severity findings — missing security headers, missing email authentication (SPF/DMARC/DKIM), certificate issues, information disclosure, directory listings, etc. For each, explain the risk and provide specific remediation instructions.

  TIER 4 — LOW/INFORMATIONAL & HARDENING (fix within 1 quarter): Address remaining low severity items, outdated but not critically vulnerable software, security header improvements, and general hardening recommendations.

  TIER 5 — STRATEGIC RECOMMENDATIONS: Long-term program improvements — vulnerability management program, patch management cadence, WAF deployment, security monitoring, regular penetration testing schedule, security header policy, certificate lifecycle management.

  The output must be LONG and DETAILED — every CVE must be mentioned by ID, every finding must be addressed with specific remediation steps. Do not summarize or skip items. If there are 20 CVEs, discuss all 20. If there are 5 findings, discuss all 5. This section should be the longest section in the entire report. Write in flowing prose paragraphs, not bullet points."""


async def generate_report_narratives(
    llm: BaseChatModel,
    data: dict,
) -> dict:
    """
    Generate LLM narrative summaries from structured report data.

    Args:
        llm: Initialized LangChain LLM instance
        data: Condensed report data dict with metrics, findings counts, etc.

    Returns:
        Dict with narrative strings for each report section.
    """
    # Build a condensed data summary for the LLM (avoid sending raw finding lists)
    condensed = _condense_for_llm(data)

    try:
        response = await llm.ainvoke([
            SystemMessage(content=REPORT_SYSTEM_PROMPT),
            HumanMessage(content=f"Security assessment data:\n```json\n{json.dumps(condensed, indent=2)}\n```\n\nGenerate the report section narratives."),
        ])

        from orchestrator_helpers import normalize_content
        content = normalize_content(response.content).strip()

        # Strip markdown code fences
        import re
        fence_match = re.search(r'```(?:json)?\s*\n(.*?)```', content, re.DOTALL | re.IGNORECASE)
        if fence_match:
            content = fence_match.group(1).strip()
        else:
            brace_start = content.find('{')
            if brace_start > 0:
                content = content[brace_start:]
            brace_end = content.rfind('}')
            if brace_end >= 0 and brace_end < len(content) - 1:
                content = content[:brace_end + 1]

        result = json.loads(content)

        expected_keys = [
            "executiveSummary", "scopeNarrative", "riskNarrative",
            "findingsNarrative", "attackSurfaceNarrative", "recommendationsNarrative",
        ]
        for key in expected_keys:
            if key not in result:
                result[key] = ""

        return result

    except json.JSONDecodeError as e:
        logger.error(f"Report summarizer: invalid JSON from LLM: {e}")
        return _empty_narratives()
    except Exception as e:
        logger.error(f"Report summarizer error: {e}")
        return _empty_narratives()


def _condense_for_llm(data: dict) -> dict:
    """Pass through all report data for comprehensive LLM analysis.
    The webapp already condenses the data before sending it here,
    so we just restructure it for the prompt."""
    metrics = data.get("metrics", {})
    project = data.get("project", {})
    graph = data.get("graphOverview", {})
    surface = data.get("attackSurface", {})
    vulns = data.get("vulnerabilities", {})
    cve_intel = data.get("cveIntelligence", {})
    chains = data.get("attackChains", {})
    remediations = data.get("remediations", [])

    # ALL findings for comprehensive triage
    all_findings = []
    for f in vulns.get("findings", []):
        all_findings.append({
            "name": f.get("name"),
            "severity": f.get("severity"),
            "source": f.get("findingSource"),
            "target": f.get("target") or f.get("host"),
            "category": f.get("category"),
            "cvssScore": f.get("cvssScore"),
        })

    # ALL technologies with CVEs
    all_tech = [
        {"name": t.get("name"), "version": t.get("version"), "cveCount": t.get("cveCount", 0)}
        for t in surface.get("technologies", [])
        if t.get("cveCount", 0) > 0
    ]

    # ALL remediation items with full detail
    all_remediations = []
    for r in remediations:
        def _get(obj, key, default=""):
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)
        all_remediations.append({
            "title": _get(r, "title"),
            "severity": _get(r, "severity"),
            "category": _get(r, "category"),
            "solution": _get(r, "solution"),
            "cveIds": _get(r, "cveIds", []),
            "cweIds": _get(r, "cweIds", []),
            "exploitAvailable": _get(r, "exploitAvailable", False),
            "cisaKev": _get(r, "cisaKev", False),
            "status": _get(r, "status"),
            "cvssScore": _get(r, "cvssScore"),
            "affectedAssets": _get(r, "affectedAssets"),
        })

    # ALL CVE chains (already deduplicated by webapp)
    all_chains = cve_intel.get("cveChains", [])

    # Security headers data
    security_headers = surface.get("securityHeaders", [])

    # Services and ports detail
    services_detail = [
        {"name": s.get("name"), "count": s.get("count")}
        for s in surface.get("services", [])[:10]
    ]
    ports_detail = [
        {"port": p.get("port"), "count": p.get("count")}
        for p in surface.get("ports", [])[:10]
    ]

    # Parameter analysis
    param_analysis = surface.get("parameterAnalysis", [])

    return {
        "projectName": project.get("name", ""),
        "targetDomain": project.get("targetDomain", ""),
        "riskScore": metrics.get("riskScore", 0),
        "riskLabel": metrics.get("riskLabel", ""),
        "overallRisk": metrics.get("overallRisk"),
        "totalVulnerabilities": metrics.get("totalVulnerabilities", 0),
        "totalCves": metrics.get("totalCves", 0),
        "totalRemediations": metrics.get("totalRemediations", 0),
        "criticalCount": metrics.get("criticalCount", 0),
        "highCount": metrics.get("highCount", 0),
        "mediumCount": metrics.get("mediumCount", 0),
        "lowCount": metrics.get("lowCount", 0),
        "cveCriticalCount": metrics.get("cveCriticalCount", 0),
        "cveHighCount": metrics.get("cveHighCount", 0),
        "cveMediumCount": metrics.get("cveMediumCount", 0),
        "cveLowCount": metrics.get("cveLowCount", 0),
        "exploitableCount": metrics.get("exploitableCount", 0),
        "cvssAverage": metrics.get("cvssAverage", 0),
        "attackSurfaceSize": metrics.get("attackSurfaceSize", 0),
        "secretsExposed": metrics.get("secretsExposed", 0),
        "totalNodes": graph.get("totalNodes", 0),
        "subdomains": graph.get("subdomainStats", {}).get("total", 0),
        "activeSubdomains": graph.get("subdomainStats", {}).get("active", 0),
        "ips": graph.get("infrastructureStats", {}).get("totalIps", 0),
        "cdnCount": graph.get("infrastructureStats", {}).get("cdnCount", 0),
        "uniqueCdns": graph.get("infrastructureStats", {}).get("uniqueCdns", 0),
        "baseUrls": graph.get("endpointCoverage", {}).get("baseUrls", 0),
        "endpoints": graph.get("endpointCoverage", {}).get("endpoints", 0),
        "parameters": graph.get("endpointCoverage", {}).get("parameters", 0),
        "certificates": graph.get("certificateHealth", {}),
        "severityDistribution": vulns.get("severityDistribution", []),
        "cvssHistogram": vulns.get("cvssHistogram", []),
        "confirmedExploits": [
            {"name": e.get("name"), "cvssScore": e.get("cvssScore"), "cveIds": e.get("cveIds", []), "cisaKev": e.get("cisaKev", False), "target": e.get("target")}
            for e in cve_intel.get("exploits", [])
        ],
        "exploitSuccesses": [
            {"title": e.get("title"), "targetIp": e.get("targetIp"), "attackType": e.get("attackType"), "module": e.get("module"), "evidence": e.get("evidence"), "cveIds": e.get("cveIds", [])}
            for e in chains.get("exploitSuccesses", [])
        ],
        "githubSecrets": cve_intel.get("githubSecrets", {}),
        "allFindings": all_findings,
        "technologiesWithCVEs": all_tech,
        "remediations": all_remediations,
        "cveChains": all_chains,
        "attackChains": chains.get("chains", []),
        "servicesExposed": services_detail,
        "portsOpen": ports_detail,
        "securityHeaders": security_headers,
        "parameterAnalysis": param_analysis,
        # RoE context if available
        "engagementType": project.get("roeEngagementType", ""),
        "clientName": project.get("roeClientName", ""),
        "methodology": "",
    }


def _empty_narratives() -> dict:
    return {
        "executiveSummary": "",
        "scopeNarrative": "",
        "riskNarrative": "",
        "findingsNarrative": "",
        "attackSurfaceNarrative": "",
        "recommendationsNarrative": "",
    }
