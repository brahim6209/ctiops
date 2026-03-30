"""pdf_report.py — Rapport PDF automatique CTI Cloud-Native"""
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from database import get_conn, get_stats

DARK    = HexColor("#0f1117")
BLUE    = HexColor("#63b3ed")
RED     = HexColor("#fc8181")
AMBER   = HexColor("#f6ad55")
GREEN   = HexColor("#68d391")
GRAY    = HexColor("#718096")
SURFACE = HexColor("#1a1d2e")

SEV_COLORS = {"CRITICAL": RED, "HIGH": AMBER, "MEDIUM": HexColor("#fbd38d"), "LOW": GREEN}

def build_report(output_path: str = "data/cti_report.pdf") -> str:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    stats = get_stats()
    now   = datetime.now().strftime("%d/%m/%Y %H:%M")

    doc   = SimpleDocTemplate(output_path, pagesize=A4,
                               leftMargin=2*cm, rightMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    title_style = ParagraphStyle("title", fontSize=24, textColor=BLUE,
                                  spaceAfter=6, alignment=TA_CENTER, fontName="Helvetica-Bold")
    sub_style   = ParagraphStyle("sub", fontSize=12, textColor=GRAY,
                                  spaceAfter=20, alignment=TA_CENTER)
    h2_style    = ParagraphStyle("h2", fontSize=14, textColor=BLUE,
                                  spaceBefore=20, spaceAfter=8, fontName="Helvetica-Bold")
    body_style  = ParagraphStyle("body", fontSize=10, textColor=black,
                                  spaceAfter=6, leading=14)

    # ── TITRE ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("CTI Cloud-Native Platform", title_style))
    story.append(Paragraph("Rapport de Cyber Threat Intelligence — Sécurité Cloud", sub_style))
    story.append(Paragraph(f"Généré le {now}", ParagraphStyle("date", fontSize=9, textColor=GRAY, alignment=TA_CENTER)))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE, spaceAfter=20))

    # ── RÉSUMÉ EXÉCUTIF ───────────────────────────────────────────────────────
    story.append(Paragraph("Résumé Exécutif", h2_style))
    story.append(Paragraph(
        f"Cette plateforme CTI cloud-native a collecté et analysé <b>{stats['total_cve']} vulnérabilités</b> "
        f"cloud au cours des 30 derniers jours, dont <b>{stats['critical_cve']} critiques</b>. "
        f"<b>{stats['total_incidents']} incidents CI/CD</b> ont été détectés et corrélés avec les techniques "
        f"MITRE ATT&CK Cloud. <b>{stats['total_ioc']} IOC</b> ont été identifiés et enrichis via VirusTotal, "
        f"dont <b>{stats['malicious_ioc']} confirmés malveillants</b>.",
        body_style
    ))

    # ── STATS KPI ─────────────────────────────────────────────────────────────
    story.append(Paragraph("Indicateurs Clés", h2_style))
    kpi_data = [
        ["Indicateur", "Valeur", "Statut"],
        ["CVE cloud collectées",    str(stats['total_cve']),       "Collecte active"],
        ["CVE critiques (CVSS≥9)",  str(stats['critical_cve']),    "Patch urgent"],
        ["Incidents CI/CD détectés",str(stats['total_incidents']), "Sous surveillance"],
        ["IOC identifiés",          str(stats['total_ioc']),       "En enrichissement"],
        ["IOC malveillants",        str(stats['malicious_ioc']),   "Blocage recommandé"],
    ]
    kpi_table = Table(kpi_data, colWidths=[7*cm, 4*cm, 5*cm])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), SURFACE),
        ("TEXTCOLOR",   (0,0), (-1,0), BLUE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [HexColor("#f8f9fa"), white]),
        ("GRID",        (0,0), (-1,-1), 0.5, HexColor("#dee2e6")),
        ("PADDING",     (0,0), (-1,-1), 8),
        ("ALIGN",       (1,0), (1,-1), "CENTER"),
    ]))
    story.append(kpi_table)

    # ── TOP CVE CRITIQUES ─────────────────────────────────────────────────────
    story.append(Paragraph("Top CVE Critiques", h2_style))
    with get_conn() as conn:
        cves = conn.execute(
            "SELECT id, severity, cvss_score, description, tlp FROM cve "
            "WHERE severity IN ('CRITICAL','HIGH') ORDER BY cvss_score DESC LIMIT 15"
        ).fetchall()

    if cves:
        cve_data = [["CVE ID", "Sévérité", "CVSS", "TLP", "Description"]]
        for c in cves:
            cve_data.append([
                c["id"], c["severity"] or "—",
                str(c["cvss_score"] or "—"), c["tlp"] or "—",
                (c["description"] or "")[:60] + "…",
            ])
        cve_table = Table(cve_data, colWidths=[3.5*cm, 2.2*cm, 1.5*cm, 2.5*cm, 7.3*cm])
        style = [
            ("BACKGROUND",  (0,0), (-1,0), SURFACE),
            ("TEXTCOLOR",   (0,0), (-1,0), BLUE),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("GRID",        (0,0), (-1,-1), 0.3, HexColor("#dee2e6")),
            ("PADDING",     (0,0), (-1,-1), 5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [HexColor("#f8f9fa"), white]),
        ]
        for i, c in enumerate(cves, start=1):
            color = SEV_COLORS.get(c["severity"], GRAY)
            style.append(("TEXTCOLOR", (1,i), (1,i), color))
            style.append(("FONTNAME",  (1,i), (1,i), "Helvetica-Bold"))
        cve_table.setStyle(TableStyle(style))
        story.append(cve_table)

    # ── INCIDENTS CI/CD ───────────────────────────────────────────────────────
    story.append(Paragraph("Incidents CI/CD Détectés", h2_style))
    with get_conn() as conn:
        incs = conn.execute(
            "SELECT event_type, severity, ml_severity, mitre_id, mitre_name, repo, tlp, created_at "
            "FROM incident ORDER BY created_at DESC LIMIT 10"
        ).fetchall()

    if incs:
        inc_data = [["Type", "Sévérité", "ML Prédit", "MITRE", "Repo", "TLP"]]
        for i in incs:
            inc_data.append([
                i["event_type"] or "—", i["severity"] or "—",
                i["ml_severity"] or "—", i["mitre_id"] or "—",
                (i["repo"] or "—")[:25], i["tlp"] or "—",
            ])
        inc_table = Table(inc_data, colWidths=[4*cm, 2.5*cm, 2.5*cm, 2.5*cm, 4*cm, 2.5*cm])
        inc_table.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), SURFACE),
            ("TEXTCOLOR",   (0,0), (-1,0), BLUE),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("GRID",        (0,0), (-1,-1), 0.3, HexColor("#dee2e6")),
            ("PADDING",     (0,0), (-1,-1), 5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [HexColor("#f8f9fa"), white]),
        ]))
        story.append(inc_table)
    else:
        story.append(Paragraph("Aucun incident CI/CD enregistré.", body_style))

    # ── RECOMMANDATIONS ───────────────────────────────────────────────────────
    story.append(Paragraph("Recommandations Posture Sécurité Cloud", h2_style))
    recommendations = [
        ("CRITIQUE", "Patcher immédiatement les CVE avec CVSS ≥ 9.0",
         "Appliquer les correctifs disponibles sur les environnements AWS, Azure et GCP dans les 24h."),
        ("HAUTE",    "Activer la rotation automatique des secrets CI/CD",
         "Utiliser HashiCorp Vault ou AWS Secrets Manager pour éviter l'exposition de credentials."),
        ("HAUTE",    "Implémenter la signature d'images Docker",
         "Utiliser Cosign ou Notary v2 pour signer et vérifier toutes les images de conteneurs."),
        ("MOYENNE",  "Appliquer le principe de moindre privilège IAM",
         "Auditer et restreindre les rôles IAM — supprimer les permissions *:*."),
        ("MOYENNE",  "Activer la surveillance des workflows CI/CD",
         "Mettre en place des alertes sur les jobs nocturnes et les patterns anormaux."),
    ]
    prio_colors = {"CRITIQUE": RED, "HAUTE": AMBER, "MOYENNE": HexColor("#fbd38d")}
    for prio, title, desc in recommendations:
        story.append(Paragraph(
            f'<font color="{prio_colors[prio].hexval().replace("0x","#")}">[{prio}]</font> <b>{title}</b>',
            ParagraphStyle("rec_title", fontSize=10, spaceBefore=8, spaceAfter=2)
        ))
        story.append(Paragraph(desc, ParagraphStyle("rec_desc", fontSize=9, textColor=GRAY, leftIndent=20)))

    # ── PIED DE PAGE ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY))
    story.append(Paragraph(
        f"CTI Cloud-Native Platform — Rapport généré le {now} — Classification TLP:AMBER",
        ParagraphStyle("footer", fontSize=8, textColor=GRAY, alignment=TA_CENTER, spaceBefore=8)
    ))

    doc.build(story)
    print(f"[PDF] Rapport généré : {output_path}")
    return output_path

if __name__ == "__main__":
    path = build_report()
    print(f"[PDF] Ouverture : {path}")
