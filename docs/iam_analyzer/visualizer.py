import json
from pathlib import Path
from html import escape


REPORT_FILE = Path(__file__).parent / "security_report.json"
OUTPUT_FILE = Path(__file__).parent / "attack_path_visualization.html"


def load_report():
    with open(REPORT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def build_attack_path(finding):
    entry = escape(str(finding["entry_point"]))
    role = escape(str(finding["permission"]))
    target = escape(str(finding["target"]))

    return f"""
    <div class="path">

        <div class="node entry">
            <div class="label">ENTRY POINT</div>
            <div class="value">{entry}</div>
        </div>

        <div class="arrow">↓</div>

        <div class="relationship">ASSIGNED ROLE</div>

        <div class="node role">
            <div class="label">PRIVILEGED ROLE</div>
            <div class="value">{role}</div>
        </div>

        <div class="arrow">↓</div>

        <div class="relationship">CAN ACCESS</div>

        <div class="node vault">
            <div class="label">KEY VAULT</div>
            <div class="value">kvseccloud01</div>
        </div>

        <div class="arrow">↓</div>

        <div class="relationship">CONTAINS</div>

        <div class="node secret">
            <div class="label">SENSITIVE TARGET</div>
            <div class="value">{target}</div>
        </div>

    </div>
    """


def build_finding(finding):

    risk_factors = ""

    for factor in finding.get("risk_factors", []):
        risk_factors += f"""
        <div class="factor">
            <span>+{factor["points"]}</span>
            {escape(str(factor["reason"]))}
        </div>
        """

    remediation = finding.get("remediation", {})

    return f"""
    <section class="finding">

        <div class="finding-header">

            <div>
                <div class="finding-id">
                    {escape(str(finding["finding_id"]))}
                </div>

                <h2>
                    {escape(str(finding["title"]))}
                </h2>
            </div>

            <div class="risk">
                <div class="score">
                    {finding["risk_score"]}/100
                </div>

                <div class="severity">
                    {escape(str(finding["severity"]))}
                </div>
            </div>

        </div>

        {build_attack_path(finding)}

        <div class="details">

            <div class="panel">

                <h3>Risk Factors</h3>

                {risk_factors}

            </div>

            <div class="panel">

                <h3>Why It Matters</h3>

                <p>
                    {escape(str(finding["reason"]))}
                </p>

                <h3>Potential Impact</h3>

                <p>
                    {escape(str(finding["impact"]))}
                </p>

            </div>

            <div class="panel remediation">

                <h3>Remediation</h3>

                <p>
                    <strong>Action</strong><br>
                    {escape(str(remediation.get("action", "N/A")))}
                </p>

                <p>
                    <strong>Least Privilege</strong><br>
                    {escape(str(remediation.get("least_privilege", "N/A")))}
                </p>

                <p>
                    <strong>Verification</strong><br>
                    {escape(str(remediation.get("verification", "N/A")))}
                </p>

            </div>

        </div>

    </section>
    """


def generate_html(report):

    findings_html = ""

    for finding in report.get("findings", []):
        findings_html += build_finding(finding)

    summary = report.get("summary", {})

    return f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
Security Across Cloud Stack
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background: #0b1020;
    color: #e5e7eb;
    font-family:
        Arial,
        Helvetica,
        sans-serif;
}}

.container {{
    width: min(1200px, 94%);
    margin: 40px auto;
}}

.header {{
    margin-bottom: 35px;
}}

.header h1 {{
    margin: 0;
    font-size: 32px;
}}

.header p {{
    color: #94a3b8;
    margin-top: 8px;
}}

.summary {{
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 30px;
}}

.summary-card {{
    background: #111827;
    border: 1px solid #263244;
    border-radius: 12px;
    padding: 20px;
}}

.summary-card .number {{
    font-size: 30px;
    font-weight: bold;
}}

.summary-card .label {{
    color: #94a3b8;
    margin-top: 5px;
}}

.finding {{
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 16px;
    padding: 28px;
    margin-bottom: 30px;
}}

.finding-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 20px;
}}

.finding-id {{
    color: #94a3b8;
    font-size: 13px;
}}

.finding h2 {{
    margin: 7px 0 0;
    font-size: 23px;
}}

.risk {{
    text-align: right;
}}

.score {{
    font-size: 28px;
    font-weight: bold;
}}

.severity {{
    color: #f87171;
    font-weight: bold;
    margin-top: 4px;
}}

.path {{
    display: flex;
    flex-direction: column;
    align-items: center;
    margin: 35px 0;
}}

.node {{
    width: 360px;
    border: 2px solid;
    border-radius: 12px;
    padding: 17px 20px;
    text-align: center;
}}

.node .label {{
    font-size: 11px;
    letter-spacing: 1.5px;
    color: #94a3b8;
    margin-bottom: 7px;
}}

.node .value {{
    font-size: 17px;
    font-weight: bold;
    word-break: break-word;
}}

.entry {{
    border-color: #60a5fa;
    background: #0c1a31;
}}

.role {{
    border-color: #f59e0b;
    background: #241a08;
}}

.vault {{
    border-color: #a78bfa;
    background: #18142b;
}}

.secret {{
    border-color: #ef4444;
    background: #2a1010;
}}

.arrow {{
    font-size: 30px;
    margin: 7px 0;
    color: #64748b;
}}

.relationship {{
    color: #94a3b8;
    font-size: 11px;
    letter-spacing: 1.5px;
    margin: 4px 0;
}}

.details {{
    display: grid;
    grid-template-columns:
        repeat(3, 1fr);
    gap: 18px;
}}

.panel {{
    background: #111827;
    border: 1px solid #263244;
    border-radius: 12px;
    padding: 20px;
}}

.panel h3 {{
    margin-top: 0;
    font-size: 16px;
}}

.panel p {{
    color: #cbd5e1;
    line-height: 1.6;
    font-size: 14px;
}}

.factor {{
    padding: 9px 0;
    border-bottom: 1px solid #263244;
    color: #cbd5e1;
    font-size: 14px;
}}

.factor span {{
    display: inline-block;
    width: 45px;
    color: #f87171;
    font-weight: bold;
}}

.remediation {{
    border-color: #22c55e;
}}

@media (max-width: 800px) {{

    .summary {{
        grid-template-columns:
            repeat(2, 1fr);
    }}

    .details {{
        grid-template-columns: 1fr;
    }}

    .node {{
        width: 100%;
    }}

    .finding-header {{
        align-items: flex-start;
    }}

}}

</style>

</head>

<body>

<div class="container">

    <div class="header">

        <h1>
            Security Across Cloud Stack
        </h1>

        <p>
            Attack Path Visualization
        </p>

    </div>

    <div class="summary">

        <div class="summary-card">
            <div class="number">
                {summary.get("total_findings", 0)}
            </div>
            <div class="label">
                Findings
            </div>
        </div>

        <div class="summary-card">
            <div class="number">
                {summary.get("critical", 0)}
            </div>
            <div class="label">
                Critical
            </div>
        </div>

        <div class="summary-card">
            <div class="number">
                {summary.get("high", 0)}
            </div>
            <div class="label">
                High
            </div>
        </div>

        <div class="summary-card">
            <div class="number">
                {summary.get("medium", 0)}
            </div>
            <div class="label">
                Medium
            </div>
        </div>

    </div>

    {findings_html}

</div>

</body>

</html>
"""


def main():

    report = load_report()

    html = generate_html(
        report
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    print(
        "\n[+] Attack path visualization generated:"
    )

    print(
        f"    {OUTPUT_FILE}"
    )


if __name__ == "__main__":

    main()