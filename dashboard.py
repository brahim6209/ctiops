"""
dashboard.py — CTI Cloud-Native Platform v4.0
Dashboard interactif : navbar 5 sections, recherche, filtres,
export PDF/JSON par section, retour MISP enrichi, graphiques interactifs
"""
import os, io, datetime, json
from flask import Flask, jsonify, render_template_string, send_file, request, Response
from database import get_conn, get_stats
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

# ── PDF HELPERS ──────────────────────────────────────────────────────────────
def _pdf_styles():
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
    GREEN=colors.HexColor("#00aa2b"); RED=colors.HexColor("#cc1133")
    AMBER=colors.HexColor("#cc7700"); GREY=colors.HexColor("#4a5a4a")
    LG=colors.HexColor("#f0f4f0"); BD=colors.HexColor("#c8d8c8")
    DARK=colors.HexColor("#0a0f0a")
    return {
        "GREEN":GREEN,"RED":RED,"AMBER":AMBER,"GREY":GREY,"LG":LG,"BD":BD,"DARK":DARK,
        "h1":ParagraphStyle("h1",fontName="Helvetica-Bold",fontSize=14,textColor=GREEN,spaceBefore=14,spaceAfter=6),
        "h2":ParagraphStyle("h2",fontName="Helvetica-Bold",fontSize=11,textColor=DARK,spaceBefore=10,spaceAfter=4),
        "body":ParagraphStyle("body",fontName="Helvetica",fontSize=9,textColor=DARK,spaceAfter=5,leading=13,alignment=TA_JUSTIFY),
        "ctr":ParagraphStyle("ctr",fontName="Helvetica",fontSize=9,textColor=DARK,alignment=TA_CENTER),
        "tlp":ParagraphStyle("tlp",fontName="Helvetica-Bold",fontSize=8,textColor=AMBER,alignment=TA_CENTER),
        "kv":ParagraphStyle("kv",fontName="Helvetica-Bold",fontSize=20,textColor=GREEN,alignment=TA_CENTER),
        "kvr":ParagraphStyle("kvr",fontName="Helvetica-Bold",fontSize=20,textColor=RED,alignment=TA_CENTER),
        "kl":ParagraphStyle("kl",fontName="Helvetica",fontSize=7,textColor=GREY,alignment=TA_CENTER),
    }

def _pdf_header_footer(c, doc, title="CTI CLOUD-NATIVE"):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    W, H = A4
    GREEN=colors.HexColor("#00aa2b"); LG=colors.HexColor("#f0f4f0"); GREY=colors.HexColor("#4a5a4a")
    c.saveState()
    c.setFillColor(GREEN); c.rect(0,H-1.1*2.54/2.54*28,W,28,fill=1,stroke=0)  # ~1cm
    c.setFillColor(colors.white); c.setFont("Helvetica-Bold",8)
    c.drawString(56,H-18,title)
    c.setFont("Helvetica",8)
    c.drawRightString(W-56,H-18,datetime.date.today().strftime("%d/%m/%Y")+"  |  CONFIDENTIEL")
    c.setFillColor(LG); c.rect(0,0,W,28,fill=1,stroke=0)
    c.setFillColor(GREY); c.setFont("Helvetica",7)
    c.drawCentredString(W/2,9,f"Page {doc.page}  |  TLP:AMBER  |  Master CTI 2025-2026  |  Securite Cloud-Native")
    c.restoreState()

def _make_pdf_doc(buf):
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate
    return SimpleDocTemplate(buf,pagesize=A4,leftMargin=56,rightMargin=56,topMargin=50,bottomMargin=50)

def _tbl_style(st, header_color=None):
    from reportlab.platypus import TableStyle
    from reportlab.lib import colors
    GREEN = header_color or st["GREEN"]
    BD = st["BD"]; LG = st["LG"]
    return TableStyle([
        ("BACKGROUND",(0,0),(-1,0),GREEN),("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
        ("FONTNAME",(0,1),(-1,-1),"Helvetica"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[LG,colors.white]),
        ("BOX",(0,0),(-1,-1),1,BD),("INNERGRID",(0,0),(-1,-1),0.5,BD),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
    ])

# ── PDF: RAPPORT MANAGEMENT ──────────────────────────────────────────────────
def gen_pdf_management():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Spacer, Table, HRFlowable
    buf = io.BytesIO()
    st = _pdf_styles()
    W, H = A4
    def hf(c,doc): _pdf_header_footer(c,doc,"CTI CLOUD-NATIVE — RAPPORT TOP MANAGEMENT")
    doc = _make_pdf_doc(buf)
    try:
        s=get_stats(); tc=s.get("total_cve",172); cc=s.get("critical_cve",21)
        ti=s.get("total_incidents",56); mi=s.get("malicious_ioc",4)
    except: tc,cc,ti,mi=172,21,56,4
    story=[]
    story.append(Spacer(1,0.5*cm))
    story.append(Paragraph("RAPPORT TOP MANAGEMENT — CTI CLOUD-NATIVE",st["h1"]))
    story.append(Paragraph(f"Periode : Mars 2026  |  Genere le : {datetime.date.today().strftime('%d %B %Y')}",st["ctr"]))
    story.append(Paragraph("Classification : TLP:AMBER — Usage interne uniquement",st["tlp"]))
    story.append(Spacer(1,0.4*cm))
    story.append(HRFlowable(width="100%",thickness=2,color=st["GREEN"]))
    story.append(Spacer(1,0.3*cm))
    kd=[[Paragraph(str(tc),st["kv"]),Paragraph(str(cc),st["kvr"]),Paragraph(str(ti),st["kvr"]),Paragraph(str(mi),st["kvr"]),Paragraph("85",st["kv"])],
        [Paragraph("CVE Cloud",st["kl"]),Paragraph("CVE Critiques",st["kl"]),Paragraph("Incidents CI/CD",st["kl"]),Paragraph("IOC Malveillants",st["kl"]),Paragraph("MISP Events",st["kl"])]]
    from reportlab.platypus import TableStyle as TS
    kt=Table(kd,colWidths=[2.8*cm]*5,rowHeights=[1*cm,0.5*cm])
    kt.setStyle(TS([("BACKGROUND",(0,0),(-1,-1),st["LG"]),("BACKGROUND",(1,0),(3,1),colors.HexColor("#fff0f0")),
        ("BOX",(0,0),(-1,-1),1,st["BD"]),("INNERGRID",(0,0),(-1,-1),0.5,st["BD"]),
        ("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
    story.append(kt); story.append(Spacer(1,0.5*cm))
    story.append(HRFlowable(width="100%",thickness=1,color=st["BD"]))
    story.append(Paragraph("1. Resume Executif",st["h1"]))
    story.append(Paragraph(
        f"La plateforme CTI Cloud-Native a identifie {tc} vulnerabilites cloud dont {cc} de niveau CRITIQUE "
        "(CVSS superieur a 9.0). {ti} incidents CI/CD detectes via GitHub Actions. "
        "Technique dominante : T1552.001 (Credentials In Files). Niveau de risque : ELEVE.",st["body"]))
    story.append(HRFlowable(width="100%",thickness=1,color=st["BD"]))
    story.append(Paragraph("2. CTI Multi-Niveaux",st["h1"]))
    cti=[["Niveau","Audience","Notre plateforme"],
         ["STRATEGIQUE","Direction / RSSI","Dashboard KPI + rapport PDF automatique"],
         ["TACTIQUE","Analystes CTI","MISP 85 events + MITRE ATT&CK T1552.001"],
         ["OPERATIONNEL","Equipe SOC","Webhook temps reel + alertes ML"],
         ["TECHNIQUE","Ingenieurs","IOC VirusTotal + CVE CVSS + STIX 2.1"]]
    ct=Table(cti,colWidths=[2.5*cm,3.5*cm,8.8*cm])
    ct.setStyle(_tbl_style(st)); story.append(ct); story.append(Spacer(1,0.4*cm))
    story.append(HRFlowable(width="100%",thickness=1,color=st["BD"]))
    story.append(Paragraph("3. Recommandations Prioritaires",st["h1"]))
    rec=[["Priorite","Action","Delai"],
         ["CRITIQUE","Rotater tous les secrets exposes dans les pipelines CI/CD","24h"],
         ["CRITIQUE","Patcher les 21 CVE critiques CVSS >= 9.0","72h"],
         ["ELEVE","Bloquer les 4 IOC malveillants identifies par VirusTotal","48h"],
         ["ELEVE","Activer Secret Scanning GitHub Actions sur tous les repos","1 semaine"],
         ["MOYEN","Audit configurations Kubernetes et Docker","2 semaines"]]
    from reportlab.platypus import TableStyle as TS2
    rt=Table(rec,colWidths=[2.2*cm,10.3*cm,2.3*cm])
    ts2=_tbl_style(st)
    ts2.add("TEXTCOLOR",(0,1),(0,2),st["RED"]); ts2.add("TEXTCOLOR",(0,3),(0,4),st["AMBER"])
    ts2.add("FONTNAME",(0,1),(0,-1),"Helvetica-Bold"); ts2.add("ALIGN",(0,0),(0,-1),"CENTER"); ts2.add("ALIGN",(2,0),(2,-1),"CENTER")
    rt.setStyle(ts2); story.append(rt); story.append(Spacer(1,0.3*cm))
    story.append(HRFlowable(width="100%",thickness=1,color=st["BD"]))
    story.append(Paragraph("Sources : NVD API, VirusTotal, GitHub Actions, MISP Docker v2.5.35. Classification TLP:AMBER — Master Bac+6 CTI 2025-2026.",st["tlp"]))
    doc.build(story,onFirstPage=hf,onLaterPages=hf)
    buf.seek(0); return buf

# ── PDF: CVE ─────────────────────────────────────────────────────────────────
def gen_pdf_cve(severity="", tlp="", cluster="", q=""):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Spacer, Table, HRFlowable
    from ml_models import cluster_cve
    CN={0:'Injection & RCE',1:'Credentials',2:'Privilege Esc.',3:'Supply Chain',4:'Misconfig'}
    buf = io.BytesIO()
    st = _pdf_styles()
    def hf(c,doc): _pdf_header_footer(c,doc,"CTI — RAPPORT CVE CLOUD")
    doc = _make_pdf_doc(buf)
    with get_conn() as c2:
        rows = c2.execute("SELECT id,description,cvss_score,severity,tlp FROM cve WHERE severity IN ('CRITICAL','HIGH') ORDER BY cvss_score DESC").fetchall()
    data = []
    for r in rows:
        d=dict(r)
        try: cl=cluster_cve(d.get("description","")); d["cluster_id"]=cl["cluster_id"]
        except: d["cluster_id"]=None
        if severity and d["severity"]!=severity: continue
        if tlp and d["tlp"]!=tlp: continue
        if cluster!='' and str(d["cluster_id"])!=cluster: continue
        if q and q.lower() not in (d["id"]+""+str(d.get("description",""))).lower(): continue
        data.append(d)
    story=[]
    story.append(Spacer(1,0.3*cm))
    story.append(Paragraph(f"RAPPORT CVE CLOUD — {len(data)} vulnerabilites",st["h1"]))
    story.append(Paragraph(f"Filtres : Severite={severity or 'Tous'} | TLP={tlp or 'Tous'} | Cluster={cluster or 'Tous'} | Recherche={q or 'Aucune'}",st["ctr"]))
    story.append(Paragraph(f"Genere le {datetime.date.today().strftime('%d %B %Y')} | TLP:AMBER",st["tlp"]))
    story.append(Spacer(1,0.3*cm))
    story.append(HRFlowable(width="100%",thickness=1,color=st["GREEN"]))
    story.append(Spacer(1,0.2*cm))
    tbl=[["CVE ID","CVSS","Severite","TLP","Cluster","Description (extrait)"]]
    for d in data[:100]:
        tbl.append([d["id"],str(d["cvss_score"]or"—"),d["severity"]or"—",d["tlp"]or"—",
                    CN.get(d["cluster_id"],"—"),(d["description"]or"")[:60]])
    t=Table(tbl,colWidths=[2.5*cm,1.2*cm,1.8*cm,2*cm,2.5*cm,4.8*cm])
    t.setStyle(_tbl_style(st)); story.append(t)
    doc.build(story,onFirstPage=hf,onLaterPages=hf)
    buf.seek(0); return buf

# ── PDF: INCIDENTS ───────────────────────────────────────────────────────────
def gen_pdf_incidents(severity="", itype="", q=""):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Spacer, Table, HRFlowable
    buf = io.BytesIO()
    st = _pdf_styles()
    def hf(c,doc): _pdf_header_footer(c,doc,"CTI — RAPPORT INCIDENTS CI/CD")
    doc = _make_pdf_doc(buf)
    with get_conn() as c2:
        rows = c2.execute("SELECT * FROM incident ORDER BY created_at DESC LIMIT 200").fetchall()
    data=[]
    for r in rows:
        d=dict(r)
        if severity and d.get("severity")!=severity: continue
        if itype and d.get("event_type")!=itype: continue
        if q and q.lower() not in (str(d.get("repo",""))+str(d.get("mitre_id",""))+str(d.get("actor",""))).lower(): continue
        data.append(d)
    story=[]
    story.append(Spacer(1,0.3*cm))
    story.append(Paragraph(f"RAPPORT INCIDENTS CI/CD — {len(data)} incidents",st["h1"]))
    story.append(Paragraph(f"Filtres : Severite={severity or 'Tous'} | Type={itype or 'Tous'} | Recherche={q or 'Aucune'}",st["ctr"]))
    story.append(Paragraph(f"Genere le {datetime.date.today().strftime('%d %B %Y')} | TLP:AMBER",st["tlp"]))
    story.append(Spacer(1,0.3*cm))
    story.append(HRFlowable(width="100%",thickness=1,color=st["GREEN"]))
    story.append(Spacer(1,0.2*cm))
    tbl=[["Date","Repo","Type","Severite","ML","Anomaly","MITRE","TLP"]]
    for d in data[:100]:
        tbl.append([(d.get("created_at")or"")[:16],(d.get("repo")or"").replace("brahim6209/",""),
                    d.get("event_type")or"—",d.get("severity")or"—",d.get("ml_severity")or"—",
                    str(d.get("anomaly_score")or"—")[:5],d.get("mitre_id")or"—",d.get("tlp")or"—"])
    t=Table(tbl,colWidths=[2.6*cm,3*cm,2.2*cm,1.6*cm,1.6*cm,1.4*cm,2*cm,1.6*cm])
    t.setStyle(_tbl_style(st)); story.append(t)
    doc.build(story,onFirstPage=hf,onLaterPages=hf)
    buf.seek(0); return buf

# ── PDF: IOC ─────────────────────────────────────────────────────────────────
def gen_pdf_ioc(itype="", min_score=0, q=""):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Spacer, Table, HRFlowable
    buf = io.BytesIO()
    st = _pdf_styles()
    def hf(c,doc): _pdf_header_footer(c,doc,"CTI — RAPPORT IOC & VIRUSTOTAL")
    doc = _make_pdf_doc(buf)
    with get_conn() as c2:
        rows = c2.execute("SELECT i.*,e.score,e.malicious_count,e.total_engines FROM ioc i LEFT JOIN enrichment e ON i.value=e.ioc_value ORDER BY e.score DESC NULLS LAST").fetchall()
    data=[]
    for r in rows:
        d=dict(r)
        sc=float(d.get("score") or 0)
        if itype and d.get("type")!=itype: continue
        if min_score and sc<min_score: continue
        if q and q.lower() not in (d.get("value")or"").lower(): continue
        data.append(d)
    story=[]
    story.append(Spacer(1,0.3*cm))
    story.append(Paragraph(f"RAPPORT IOC & VIRUSTOTAL — {len(data)} indicateurs",st["h1"]))
    story.append(Paragraph(f"Filtres : Type={itype or 'Tous'} | Score min={min_score or '0'}% | Recherche={q or 'Aucune'}",st["ctr"]))
    story.append(Paragraph(f"Genere le {datetime.date.today().strftime('%d %B %Y')} | TLP:AMBER",st["tlp"]))
    story.append(Spacer(1,0.3*cm))
    story.append(HRFlowable(width="100%",thickness=1,color=st["GREEN"]))
    story.append(Spacer(1,0.2*cm))
    tbl=[["Type","Valeur IOC","Score VT","Moteurs","Source","TLP"]]
    for d in data[:100]:
        sc=float(d.get("score") or 0)
        mc=d.get("malicious_count")or"—"; te=d.get("total_engines")or"—"
        tbl.append([(d.get("type")or"?").upper(),(d.get("value")or"")[:45],
                    f"{sc:.1f}%",f"{mc}/{te}",d.get("source")or"—",d.get("tlp")or"—"])
    t=Table(tbl,colWidths=[1.5*cm,5.5*cm,1.8*cm,1.8*cm,2.5*cm,1.8*cm])
    t.setStyle(_tbl_style(st)); story.append(t)
    doc.build(story,onFirstPage=hf,onLaterPages=hf)
    buf.seek(0); return buf

# ── HTML ─────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CTI CLOUD-NATIVE // THREAT INTELLIGENCE v4.0</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Exo+2:wght@300;400;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--g:#00ff41;--gd:#00aa2b;--gk:#003b0e;--r:#ff2d55;--am:#ffa500;--b:#00d4ff;--p:#bf5fff;
  --bg:#020c02;--bg2:#050f05;--bg3:#081508;--bd:#0a2a0a;--tx:#c8ffc8;--td:#5a8a5a;
  --fm:'Share Tech Mono',monospace;--fd:'Orbitron',monospace;--fb:'Exo 2',sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:var(--fb);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,65,.018) 2px,rgba(0,255,65,.018) 4px);pointer-events:none;z-index:0}

/* TOPBAR */
.topbar{position:sticky;top:0;z-index:100;background:#000;border-bottom:1px solid var(--gd);display:flex;align-items:center;height:52px;padding:0 16px;gap:12px}
.logo{font-family:var(--fd);font-size:10px;font-weight:900;color:var(--g);letter-spacing:.15em;text-shadow:0 0 12px var(--g);white-space:nowrap}
.logo span{color:var(--td);font-weight:400}
.sdot{width:7px;height:7px;border-radius:50%;background:var(--g);box-shadow:0 0 8px var(--g);animation:pd 1.5s ease-in-out infinite;flex-shrink:0}
@keyframes pd{50%{opacity:.4;transform:scale(.8)}}
.tbadge{font-family:var(--fm);font-size:9px;color:var(--r);border:1px solid var(--r);padding:2px 7px;border-radius:2px;white-space:nowrap}

/* SEARCH */
.sw{flex:1;max-width:340px;position:relative}
.sw input{width:100%;background:#0a1a0a;border:1px solid var(--bd);color:var(--tx);font-family:var(--fm);font-size:10px;padding:5px 8px 5px 24px;outline:none;border-radius:2px;transition:border .2s}
.sw input:focus{border-color:var(--gd)}
.sw input::placeholder{color:var(--td)}
.sw::before{content:'⌕';position:absolute;left:7px;top:50%;transform:translateY(-50%);color:var(--td);font-size:12px;pointer-events:none}
#sr{position:absolute;top:calc(100% + 4px);left:0;right:0;background:#0a1a0a;border:1px solid var(--gd);max-height:260px;overflow-y:auto;z-index:200;display:none}
.sri{padding:6px 10px;font-family:var(--fm);font-size:9px;cursor:pointer;border-bottom:1px solid var(--bd)}
.sri:hover{background:var(--bg3);color:var(--g)}
.sri-t{font-size:7px;color:var(--td);margin-right:5px;padding:1px 4px;border:1px solid var(--bd);border-radius:2px}

/* NAVBAR */
nav{background:var(--bg2);border-bottom:1px solid var(--bd);display:flex;position:sticky;top:52px;z-index:99}
.nb{font-family:var(--fm);font-size:9px;color:var(--td);padding:9px 16px;cursor:pointer;border:none;background:none;border-bottom:2px solid transparent;transition:all .2s;letter-spacing:.07em;white-space:nowrap}
.nb:hover{color:var(--tx);background:var(--bg3)}
.nb.active{color:var(--g);border-bottom-color:var(--g);text-shadow:0 0 8px var(--g)}
.nr{margin-left:auto;display:flex;align-items:center;gap:6px;padding-right:10px}
.btn{font-family:var(--fm);font-size:8px;padding:3px 9px;border-radius:2px;cursor:pointer;border:1px solid;transition:all .2s;letter-spacing:.05em;text-decoration:none;display:inline-flex;align-items:center;gap:4px}
.bg{color:var(--g);border-color:var(--g);background:transparent}.bg:hover{background:var(--gk)}
.bb{color:var(--b);border-color:var(--b);background:transparent}.bb:hover{background:#001a2a}
.bj{color:var(--am);border-color:var(--am);background:transparent}.bj:hover{background:#1a0e00}
.br{color:var(--r);border-color:var(--r);background:transparent}.br:hover{background:#1a0005}

/* EXPORT BAR */
.ebar{background:#020c02;border-bottom:1px solid var(--bd);padding:5px 16px;display:flex;align-items:center;gap:8px;font-family:var(--fm);font-size:8px;color:var(--td)}
.ebar span{margin-right:4px}

/* TICKER */
.ticker{background:#050000;border-bottom:1px solid #200;padding:5px 16px;overflow:hidden;z-index:1;position:relative}
.ti{display:flex;gap:44px;white-space:nowrap;animation:tk 45s linear infinite}
@keyframes tk{to{transform:translateX(-50%)}}
.tc{font-family:var(--fm);font-size:9px}
.tc.cr{color:var(--r)}.tc.hi{color:var(--am)}.tc.inf{color:var(--td)}

/* PAGES */
.page{display:none;position:relative;z-index:1}
.page.active{display:block}

/* FILTERS */
.fbar{background:var(--bg2);border-bottom:1px solid var(--bd);padding:6px 16px;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.fl{font-family:var(--fm);font-size:8px;color:var(--td);letter-spacing:.1em}
select,input[type=text]{background:#0a1a0a;border:1px solid var(--bd);color:var(--tx);font-family:var(--fm);font-size:9px;padding:3px 7px;outline:none;border-radius:2px}
select:focus,input[type=text]:focus{border-color:var(--gd)}
option{background:#0a1a0a}

/* KPI */
.kpi-g{display:grid;grid-template-columns:repeat(6,1fr);gap:1px;background:var(--bd);padding:1px}
.kpi{background:var(--bg2);padding:12px 14px;position:relative;overflow:hidden;transition:background .2s}
.kpi:hover{background:var(--bg3)}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.kpi.g::before{background:var(--g);box-shadow:0 0 5px var(--g)}
.kpi.r::before{background:var(--r);box-shadow:0 0 5px var(--r)}
.kpi.a::before{background:var(--am);box-shadow:0 0 5px var(--am)}
.kpi.b::before{background:var(--b);box-shadow:0 0 5px var(--b)}
.kpi.p::before{background:var(--p);box-shadow:0 0 5px var(--p)}
.kl{font-family:var(--fm);font-size:7px;color:var(--td);letter-spacing:.12em;text-transform:uppercase;margin-bottom:3px}
.kv{font-family:var(--fd);font-size:24px;font-weight:900;line-height:1}
.kpi.g .kv{color:var(--g);text-shadow:0 0 10px var(--g)}
.kpi.r .kv{color:var(--r);text-shadow:0 0 10px var(--r)}
.kpi.a .kv{color:var(--am);text-shadow:0 0 10px var(--am)}
.kpi.b .kv{color:var(--b);text-shadow:0 0 10px var(--b)}
.kpi.p .kv{color:var(--p);text-shadow:0 0 10px var(--p)}
.ks{font-size:8px;color:var(--td);margin-top:2px;font-family:var(--fm)}

/* CHARTS */
.cr4{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--bd)}
.cc{background:var(--bg2);padding:12px}
.ct{font-family:var(--fm);font-size:8px;color:var(--td);letter-spacing:.12em;text-transform:uppercase;margin-bottom:8px}

/* PANELS */
.panels{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--bd)}
.panel{background:var(--bg2)}
.ph{padding:7px 13px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between}
.pt{font-family:var(--fm);font-size:8px;color:var(--g);letter-spacing:.12em;text-transform:uppercase}
.pc{font-family:var(--fm);font-size:8px;color:var(--td)}

/* TABLES */
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{font-family:var(--fm);font-size:7px;color:var(--td);padding:5px 9px;text-align:left;border-bottom:1px solid var(--bd);text-transform:uppercase;letter-spacing:.07em;white-space:nowrap}
td{padding:4px 9px;border-bottom:1px solid #0a1a0a;font-family:var(--fm);font-size:8px;color:var(--tx)}
tr:hover td{background:var(--bg3);color:var(--g)}
.sv{padding:1px 4px;border-radius:2px;font-size:7px;font-family:var(--fm);white-space:nowrap}
.CRITICAL{background:#1a0005;color:var(--r);border:1px solid #300}
.HIGH{background:#1a0e00;color:var(--am);border:1px solid #530}
.MEDIUM{background:#1a1500;color:#ffd700;border:1px solid #550}
.LOW{background:#001a00;color:var(--g);border:1px solid #030}
.UNKNOWN{background:#0a0a0a;color:var(--td);border:1px solid #1a1a1a}
.cb{padding:1px 4px;border-radius:2px;font-size:7px;font-family:var(--fm)}
.c0{background:#001a1a;color:var(--b);border:1px solid #053}
.c1{background:#0a001a;color:var(--p);border:1px solid #305}
.c2{background:#1a0e00;color:var(--am);border:1px solid #530}
.c3{background:#001a00;color:var(--g);border:1px solid #030}
.c4{background:#1a1500;color:#ffd700;border:1px solid #550}
.tr2{color:var(--r);font-size:7px;font-family:var(--fm)}
.ta{color:var(--am);font-size:7px;font-family:var(--fm)}
.tw2{color:var(--g);font-size:7px;font-family:var(--fm)}

/* TIMELINE */
.tl{padding:4px 0;max-height:260px;overflow-y:auto}
.tli{display:flex;align-items:flex-start;gap:7px;padding:4px 13px;border-left:2px solid transparent;transition:all .2s}
.tli:hover{background:var(--bg3);border-left-color:var(--g)}
.tli.cr{border-left-color:var(--r)!important}.tli.hi{border-left-color:var(--am)!important}
.tdot{width:5px;height:5px;border-radius:50%;margin-top:3px;flex-shrink:0}
.tdot.cr{background:var(--r);box-shadow:0 0 4px var(--r)}.tdot.hi{background:var(--am)}.tdot.lo{background:var(--td)}
.ttt{font-family:var(--fm);font-size:8px;color:var(--tx)}
.tmt{font-family:var(--fm);font-size:7px;color:var(--td);margin-top:1px}

/* RISK */
.rg{display:grid;grid-template-columns:repeat(3,1fr);gap:3px;padding:9px}
.rc{background:var(--bg3);border:1px solid var(--bd);border-radius:3px;padding:8px;text-align:center;transition:all .2s}
.rc:hover{transform:translateY(-2px);border-color:var(--td)}
.rn{font-size:7px;color:var(--td);font-family:var(--fm);margin-bottom:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rv{font-family:var(--fd);font-size:16px;font-weight:700}
.rc-c .rv{color:var(--r);text-shadow:0 0 7px var(--r)}.rc-h .rv{color:var(--am)}
.rc-m .rv{color:#ffd700}.rc-l .rv{color:var(--g)}
.rl{font-size:7px;font-family:var(--fm);margin-top:1px;color:var(--td)}

/* IOC */
.ir{display:flex;align-items:center;gap:7px;padding:4px 13px;border-bottom:1px solid #0a1a0a;font-family:var(--fm);font-size:8px}
.it{padding:1px 4px;border-radius:2px;font-size:7px;background:#001a1a;color:var(--b);border:1px solid #053;min-width:38px;text-align:center}
.iv{flex:1;color:var(--tx);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* MISP */
.mg{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1px;background:var(--bd)}
.mp{background:var(--bg2)}

/* NOTIF */
#nc{position:fixed;top:65px;right:12px;z-index:999;display:flex;flex-direction:column;gap:5px}
.notif{background:#0a0000;border:1px solid var(--r);border-left:3px solid var(--r);padding:7px 12px;min-width:240px;font-family:var(--fm);font-size:9px;color:var(--r);animation:si .3s ease,fo .5s 4.5s forwards}
.notif.am{border-color:var(--am);color:var(--am)}
.nt{font-weight:600;margin-bottom:1px}.nb2{font-size:8px;color:var(--td)}
@keyframes si{from{transform:translateX(280px);opacity:0}to{transform:translateX(0);opacity:1}}
@keyframes fo{to{opacity:0;transform:translateX(280px)}}

/* MODAL */
#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.9);z-index:500;align-items:center;justify-content:center}
#modal.open{display:flex}
.mb{background:var(--bg2);border:1px solid var(--gd);width:560px;max-width:95vw;max-height:82vh;overflow-y:auto;padding:18px;position:relative}
.mc{position:absolute;top:9px;right:12px;font-family:var(--fm);color:var(--td);cursor:pointer;font-size:13px}
.mc:hover{color:var(--r)}
.mttl{font-family:var(--fd);font-size:10px;color:var(--g);margin-bottom:10px;letter-spacing:.1em}
.mr{display:flex;gap:7px;margin-bottom:5px;font-family:var(--fm);font-size:8px}
.mk{color:var(--td);min-width:95px;flex-shrink:0}.mv{color:var(--tx);flex:1;word-break:break-all}
.mrow-sep{border-top:1px solid var(--bd);margin:8px 0}

/* PAGINATION */
.pag{display:flex;align-items:center;gap:4px;padding:6px 13px;border-top:1px solid var(--bd);font-family:var(--fm);font-size:8px;color:var(--td)}
.pb{background:none;border:1px solid var(--bd);color:var(--td);font-family:var(--fm);font-size:8px;padding:2px 7px;cursor:pointer;border-radius:2px}
.pb:hover{border-color:var(--gd);color:var(--g)}.pb.act{border-color:var(--g);color:var(--g)}

/* MISP ENRICHED */
.misp-corr{background:var(--bg3);border:1px solid var(--bd);border-radius:3px;padding:8px;margin:4px 0;font-family:var(--fm);font-size:8px}
.misp-tag{display:inline-block;padding:1px 5px;border-radius:2px;font-size:7px;margin:2px;font-family:var(--fm)}
.mt-mitre{background:#0a001a;color:var(--p);border:1px solid #305}
.mt-tlp-r{background:#1a0005;color:var(--r);border:1px solid #300}
.mt-tlp-a{background:#1a0e00;color:var(--am);border:1px solid #530}
.mt-cve{background:#001a1a;color:var(--b);border:1px solid #053}
.mt-other{background:#0a1a0a;color:var(--td);border:1px solid var(--bd)}

/* FOOTER */
footer{position:relative;z-index:1;background:var(--bg);border-top:1px solid var(--bd);padding:5px 16px;display:flex;align-items:center;gap:10px;font-family:var(--fm);font-size:7px;color:var(--td)}
.fs span{color:var(--g)}
::-webkit-scrollbar{width:3px;height:3px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--gk)}
.empty{padding:18px;text-align:center;color:var(--td);font-family:var(--fm);font-size:9px}
</style>
</head>
<body>
<div id="nc"></div>
<div id="modal"><div class="mb"><span class="mc" onclick="closeModal()">&#10005;</span><div id="mc2"></div></div></div>

<!-- TOPBAR -->
<div class="topbar">
  <div class="logo">CTI<span>/</span>CLOUD<span>//</span>THREAT INTEL <span>v4.0</span></div>
  <div class="sdot"></div>
  <div class="tbadge" id="tbadge">THREAT: HIGH</div>
  <div class="sw">
    <input type="text" id="si" placeholder="Rechercher CVE ID, repo, IP, hash..." autocomplete="off">
    <div id="sr"></div>
  </div>
  <div style="margin-left:auto;font-family:var(--fm);font-size:8px;color:var(--td)" id="clk">--:--:--</div>
</div>

<!-- NAVBAR -->
<nav>
  <button class="nb active" onclick="showPage('ov',this)">&#9670; OVERVIEW</button>
  <button class="nb" onclick="showPage('cve',this)">&#11041; CVE EXPLORER</button>
  <button class="nb" onclick="showPage('inc',this)">&#9889; INCIDENTS CI/CD</button>
  <button class="nb" onclick="showPage('ioc',this)">&#9901; IOC &amp; VIRUSTOTAL</button>
  <button class="nb" onclick="showPage('misp',this)">&#11042; MISP INTELLIGENCE</button>
  <div class="nr">
    <button class="btn bb" onclick="exportJSON()" title="Export JSON">&#9660; JSON</button>
    <button class="btn bj" onclick="exportCSV()" title="Export CSV">&#9660; CSV</button>
    <button class="btn bg" onclick="exportPDF()" title="Export PDF section">&#9660; PDF</button>
    <a href="/api/rapport/pdf" class="btn br" title="Rapport Top Management">&#9660; RAPPORT</a>
  </div>
</nav>

<!-- TICKER -->
<div class="ticker">
  <div class="ti" id="ticker">
    <span class="tc cr">&#9888; secret_exposed :: brahim6209/cti-test-pipeline :: T1552.001 :: TLP:RED</span>
    <span class="tc hi">&#9650; CVE-2026-31957 CVSS:10.0 :: Azure Entra ID :: Patch requis</span>
    <span class="tc inf">&#9679; 172 CVE cloud :: NVD API v2 :: MISP 85 events synchronises</span>
    <span class="tc hi">&#9650; IOC 185.220.101.45 :: 18/94 moteurs VT :: Tor exit node malveillant</span>
    <span class="tc cr">&#9888; secret_exposed :: brahim6209/cti-test-pipeline :: T1552.001 :: TLP:RED</span>
    <span class="tc hi">&#9650; CVE-2026-31957 CVSS:10.0 :: Azure Entra ID :: Patch requis</span>
    <span class="tc inf">&#9679; 172 CVE cloud :: NVD API v2 :: MISP 85 events synchronises</span>
    <span class="tc hi">&#9650; IOC 185.220.101.45 :: 18/94 moteurs VT :: Tor exit node malveillant</span>
  </div>
</div>

<!-- ═══ OVERVIEW ═══ -->
<div class="page active" id="page-ov">
  <div class="kpi-g">
    <div class="kpi b"><div class="kl">CVE Collectees</div><div class="kv" id="k-cve">-</div><div class="ks">NVD Cloud Feed</div></div>
    <div class="kpi r"><div class="kl">CVE Critiques</div><div class="kv" id="k-crit">-</div><div class="ks">CVSS &ge; 9.0</div></div>
    <div class="kpi a"><div class="kl">Incidents CI/CD</div><div class="kv" id="k-inc">-</div><div class="ks">GitHub Actions</div></div>
    <div class="kpi g"><div class="kl">IOC Suivis</div><div class="kv" id="k-ioc">-</div><div class="ks">Multi-sources</div></div>
    <div class="kpi r"><div class="kl">IOC Malveillants</div><div class="kv" id="k-mal">-</div><div class="ks">VirusTotal</div></div>
    <div class="kpi p"><div class="kl">MISP Events</div><div class="kv" id="k-misp">85</div><div class="ks">Synchro active</div></div>
  </div>
  <div class="cr4">
    <div class="cc"><div class="ct">Severite CVE</div><canvas id="ch-sev" height="140"></canvas></div>
    <div class="cc"><div class="ct">Incidents par Type</div><canvas id="ch-inc" height="140"></canvas></div>
    <div class="cc"><div class="ct">Clusters K-Means ML</div><canvas id="ch-cl" height="140"></canvas></div>
    <div class="cc"><div class="ct">Timeline 24h</div><canvas id="ch-tl" height="140"></canvas></div>
  </div>
  <div class="panels">
    <div class="panel">
      <div class="ph"><div class="pt">Incidents Recents</div><div class="pc" id="ov-ic">0</div></div>
      <div class="tl" id="ov-tl"></div>
    </div>
    <div class="panel">
      <div class="ph"><div class="pt">Risk Score par Asset</div><div class="pc">Top repos</div></div>
      <div class="rg" id="ov-rg"></div>
    </div>
  </div>
</div>

<!-- ═══ CVE EXPLORER ═══ -->
<div class="page" id="page-cve">
  <div class="fbar">
    <span class="fl">FILTRES :</span>
    <select id="f-sv" onchange="filterCVE()"><option value="">Severite</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
    <select id="f-tlp" onchange="filterCVE()"><option value="">TLP</option><option>TLP:RED</option><option>TLP:AMBER</option><option>TLP:WHITE</option></select>
    <select id="f-cl" onchange="filterCVE()">
      <option value="">Cluster ML</option>
      <option value="0">Injection &amp; RCE</option><option value="1">Credentials</option>
      <option value="2">Privilege Esc.</option><option value="3">Supply Chain</option><option value="4">Misconfig</option>
    </select>
    <input type="text" id="f-cq" placeholder="CVE ID ou mot-cle..." oninput="filterCVE()" style="width:175px">
    <button class="btn bb" onclick="clrCVE()">&#10005; Reset</button>
    <span style="margin-left:auto;font-family:var(--fm);font-size:8px;color:var(--td)" id="cve-cl">0 CVE</span>
  </div>
  <div class="tw" style="max-height:calc(100vh - 240px);overflow-y:auto">
    <table><thead><tr><th>CVE ID</th><th>CVSS</th><th>Severite</th><th>Cluster ML</th><th>TLP</th><th>Description</th><th></th></tr></thead>
    <tbody id="cve-tb"></tbody></table>
  </div>
  <div class="pag" id="cve-pg"></div>
</div>

<!-- ═══ INCIDENTS ═══ -->
<div class="page" id="page-inc">
  <div class="fbar">
    <span class="fl">FILTRES :</span>
    <select id="f-is" onchange="filterInc()"><option value="">Severite</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
    <select id="f-it" onchange="filterInc()"><option value="">Type</option><option>secret_exposed</option><option>job_failed_repeat</option><option>unknown</option></select>
    <input type="text" id="f-iq" placeholder="Repo, MITRE, acteur..." oninput="filterInc()" style="width:175px">
    <button class="btn bb" onclick="clrInc()">&#10005; Reset</button>
    <span style="margin-left:auto;font-family:var(--fm);font-size:8px;color:var(--td)" id="inc-cl">0 incidents</span>
  </div>
  <div class="tw" style="max-height:calc(100vh - 210px);overflow-y:auto">
    <table><thead><tr><th>Date</th><th>Repo</th><th>Type</th><th>Severite</th><th>ML</th><th>Anomaly</th><th>MITRE</th><th>TLP</th><th></th></tr></thead>
    <tbody id="inc-tb"></tbody></table>
  </div>
</div>

<!-- ═══ IOC ═══ -->
<div class="page" id="page-ioc">
  <div class="fbar">
    <span class="fl">FILTRES :</span>
    <select id="f-iot" onchange="filterIOC()"><option value="">Type</option><option>ip</option><option>domain</option><option>hash</option><option>url</option></select>
    <select id="f-ios" onchange="filterIOC()">
      <option value="">Score VT</option>
      <option value="70">Critique (&gt;70%)</option><option value="40">Malveillant (&gt;40%)</option><option value="0">Tous</option>
    </select>
    <input type="text" id="f-ioq" placeholder="IP, domaine, hash..." oninput="filterIOC()" style="width:175px">
    <button class="btn bb" onclick="clrIOC()">&#10005; Reset</button>
    <span style="margin-left:auto;font-family:var(--fm);font-size:8px;color:var(--td)" id="ioc-cl">0 IOC</span>
  </div>
  <div class="panels">
    <div class="panel">
      <div class="ph"><div class="pt">IOC Enrichis VirusTotal</div><div class="pc" id="ioc-ph">0</div></div>
      <div id="ioc-list" style="max-height:450px;overflow-y:auto"></div>
    </div>
    <div class="panel">
      <div class="ph"><div class="pt">Distribution par Type</div><div class="pc">VirusTotal</div></div>
      <div style="padding:12px"><canvas id="ch-ioc" height="170"></canvas></div>
    </div>
  </div>
</div>

<!-- ═══ MISP INTELLIGENCE ═══ -->
<div class="page" id="page-misp">
  <!-- Stats rapides MISP -->
  <div class="kpi-g" style="grid-template-columns:repeat(5,1fr)">
    <div class="kpi p"><div class="kl">Total Events</div><div class="kv" id="ms-tot">-</div><div class="ks">MISP Docker</div></div>
    <div class="kpi b"><div class="kl">CVE Events</div><div class="kv" id="ms-cve">-</div><div class="ks">Vulnerabilites</div></div>
    <div class="kpi r"><div class="kl">Incidents</div><div class="kv" id="ms-inc">-</div><div class="ks">CI/CD MITRE</div></div>
    <div class="kpi r"><div class="kl">TLP:RED</div><div class="kv" id="ms-red">-</div><div class="ks">Critique</div></div>
    <div class="kpi a"><div class="kl">TLP:AMBER</div><div class="kv" id="ms-amb">-</div><div class="ks">Interne</div></div>
  </div>
  <!-- 3 panels TLP + MITRE + incidents -->
  <div class="mg">
    <div class="mp">
      <div class="ph"><div class="pt">Distribution TLP</div><div class="pc" id="misp-tot">0</div></div>
      <div style="padding:12px" id="misp-tlp"></div>
    </div>
    <div class="mp">
      <div class="ph"><div class="pt">Top MITRE ATT&amp;CK</div><div class="pc">Techniques detectees</div></div>
      <div style="padding:12px" id="misp-mitre"></div>
    </div>
    <div class="mp">
      <div class="ph"><div class="pt">Incidents CI/CD MISP</div><div class="pc" id="misp-ic">0</div></div>
      <div style="padding:4px 0;max-height:200px;overflow-y:auto" id="misp-incs"></div>
    </div>
  </div>
  <!-- Enrichissement : Events MISP + Correlations -->
  <div class="panels" style="margin-top:1px">
    <div class="panel">
      <div class="ph"><div class="pt">CVE Events MISP (Enrichis)</div><div class="pc" id="misp-cc">0</div></div>
      <div style="max-height:280px;overflow-y:auto">
        <table><thead><tr><th>ID</th><th>CVE</th><th>Threat</th><th>Attributs</th><th>Tags</th><th>Date</th></tr></thead>
        <tbody id="misp-cve-tb"></tbody></table>
      </div>
    </div>
    <div class="panel">
      <div class="ph"><div class="pt">Correlations &amp; Galaxies ATT&amp;CK</div><div class="pc">MISP Enrichissement</div></div>
      <div style="padding:10px;max-height:280px;overflow-y:auto" id="misp-corr"></div>
    </div>
  </div>
  <!-- Statistiques globales -->
  <div class="panel" style="margin-top:1px">
    <div class="ph"><div class="pt">Statistiques Globales MISP</div><div class="pc">Synthese complete</div></div>
    <div style="padding:12px" id="misp-stats"></div>
  </div>
</div>

<footer>
  <div class="fs">NVD API <span>&#10003;</span></div>
  <div class="fs">VirusTotal <span>&#10003;</span></div>
  <div class="fs">MISP v2.5.35 <span>&#10003;</span></div>
  <div class="fs">GitHub Webhook <span>&#10003;</span></div>
  <div class="fs">ML Models <span>4 actifs</span></div>
  <div class="fs">STIX 2.1 <span>&#10003;</span></div>
  <div style="margin-left:auto">CTI CLOUD-NATIVE v4.0 // AUTO-REFRESH 30s</div>
</footer>

<script>
const G='#00ff41',R='#ff2d55',AM='#ffa500',B='#00d4ff',P='#bf5fff';
const CN={0:'Injection & RCE',1:'Credentials',2:'Privilege Esc.',3:'Supply Chain',4:'Misconfig'};
const CC=[B,P,AM,G,'#ffd700'];
let ch={},allCVE=[],allInc=[],allIOC=[],cvePg=0,cveN=30,prevInc=0,curPage='ov';

// ── UTILS ─────────────────────────────────────────────────────────
function tlpC(t){return t==='TLP:RED'?'tr2':t==='TLP:AMBER'?'ta':'tw2'}
function scCol(s){s=parseFloat(s||0);return s>70?R:s>40?AM:G}
function showN(t,b,l='cr'){
  const d=document.createElement('div');d.className='notif'+(l==='hi'?' am':'');
  d.innerHTML=`<div class="nt">&#9888; ${t}</div><div class="nb2">${b}</div>`;
  document.getElementById('nc').appendChild(d);setTimeout(()=>d.remove(),5000);
}
function openModal(h){document.getElementById('mc2').innerHTML=h;document.getElementById('modal').classList.add('open')}
function closeModal(){document.getElementById('modal').classList.remove('open')}
document.getElementById('modal').addEventListener('click',e=>{if(e.target.id==='modal')closeModal()});
setInterval(()=>document.getElementById('clk').textContent=new Date().toLocaleTimeString('fr-FR'),1000);

// ── NAVIGATION ────────────────────────────────────────────────────
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn)btn.classList.add('active');
  curPage=id;
  if(id==='cve')renderCVE();
  if(id==='inc')renderInc();
  if(id==='ioc')renderIOC();
  if(id==='misp')loadMISP();
}

// ── SEARCH ────────────────────────────────────────────────────────
const siEl=document.getElementById('si'),srEl=document.getElementById('sr');
siEl.addEventListener('input',()=>{
  const q=siEl.value.trim().toLowerCase();
  if(q.length<2){srEl.style.display='none';return}
  const res=[];
  allCVE.filter(c=>(c.id||'').toLowerCase().includes(q)||(c.description||'').toLowerCase().includes(q)).slice(0,5)
    .forEach(c=>res.push({type:'CVE',label:`${c.id} — CVSS:${c.cvss_score||'?'} ${c.severity||''}`,data:c}));
  allInc.filter(i=>(i.event_type||'').toLowerCase().includes(q)||(i.repo||'').toLowerCase().includes(q)||(i.mitre_id||'').toLowerCase().includes(q)).slice(0,4)
    .forEach(i=>res.push({type:'INC',label:`${i.event_type} — ${(i.repo||'').split('/')[1]||''} [${i.severity||''}]`,data:i}));
  allIOC.filter(o=>(o.value||'').toLowerCase().includes(q)).slice(0,3)
    .forEach(o=>res.push({type:'IOC',label:`${o.type}: ${o.value} — VT:${parseFloat(o.score||0).toFixed(0)}%`,data:o}));
  if(!res.length){srEl.innerHTML='<div class="sri" style="color:var(--td)">Aucun resultat</div>';srEl.style.display='block';return}
  srEl.innerHTML=res.map((r,i)=>`<div class="sri" data-i="${i}"><span class="sri-t">${r.type}</span>${r.label.slice(0,65)}</div>`).join('');
  srEl.style.display='block';
  srEl.querySelectorAll('.sri').forEach((el,i)=>el.addEventListener('click',()=>{
    const r=res[i];siEl.value='';srEl.style.display='none';
    if(r.type==='CVE'){showPage('cve',document.querySelectorAll('.nb')[1]);setTimeout(()=>showCVEDet(r.data),50)}
    else if(r.type==='INC'){showPage('inc',document.querySelectorAll('.nb')[2]);setTimeout(()=>showIncDet(r.data),50)}
    else if(r.type==='IOC'){showPage('ioc',document.querySelectorAll('.nb')[3]);setTimeout(()=>showIOCDet(r.data),50)}
  }));
});
document.addEventListener('click',e=>{if(!siEl.contains(e.target)&&!srEl.contains(e.target))srEl.style.display='none'});

// ── DETAIL MODALS ─────────────────────────────────────────────────
function showCVEDet(c){
  openModal(`<div class="mttl">&#9670; ${c.id}</div>
    <div class="mr"><div class="mk">CVSS Score</div><div class="mv" style="color:${c.cvss_score>=9?R:AM};font-size:14px;font-family:var(--fd)">${c.cvss_score||'N/A'}</div></div>
    <div class="mr"><div class="mk">Severite</div><div class="mv"><span class="sv ${c.severity||'UNKNOWN'}">${c.severity||'N/A'}</span></div></div>
    <div class="mr"><div class="mk">TLP</div><div class="mv"><span class="${tlpC(c.tlp)}">${c.tlp||'N/A'}</span></div></div>
    <div class="mr"><div class="mk">Cluster ML</div><div class="mv">${c.cluster_id!=null?`<span class="cb c${c.cluster_id}">${CN[c.cluster_id]}</span>`:'N/A'}</div></div>
    <div class="mrow-sep"></div>
    <div class="mr"><div class="mk">Description</div><div class="mv">${c.description||'N/A'}</div></div>
    <div class="mrow-sep"></div>
    <div class="mr"><div class="mk">NVD Link</div><div class="mv"><a href="https://nvd.nist.gov/vuln/detail/${c.id}" target="_blank" style="color:var(--b)">${c.id} &#8599;</a></div></div>
    <div class="mr"><div class="mk">MISP Check</div><div class="mv"><button class="btn bb" onclick="checkMISPCVE('${c.id}')" style="font-size:8px;padding:2px 7px">Verifier dans MISP &#8599;</button></div></div>`);
}
function showIncDet(i){
  openModal(`<div class="mttl">&#9889; Incident #${i.id}</div>
    <div class="mr"><div class="mk">Type</div><div class="mv">${i.event_type||'N/A'}</div></div>
    <div class="mr"><div class="mk">Repo</div><div class="mv" style="color:var(--b)">${i.repo||'N/A'}</div></div>
    <div class="mr"><div class="mk">Severite</div><div class="mv"><span class="sv ${i.severity||'UNKNOWN'}">${i.severity||'N/A'}</span></div></div>
    <div class="mr"><div class="mk">ML Predit</div><div class="mv">${i.ml_severity||'N/A'}</div></div>
    <div class="mr"><div class="mk">Anomaly Score</div><div class="mv" style="color:${parseFloat(i.anomaly_score||0)>60?R:AM}">${i.anomaly_score||'N/A'}</div></div>
    <div class="mrow-sep"></div>
    <div class="mr"><div class="mk">MITRE ATT&CK</div><div class="mv"><span style="color:var(--p);font-size:11px">${i.mitre_id||'N/A'}</span> — ${i.mitre_name||''}</div></div>
    <div class="mr"><div class="mk">TLP</div><div class="mv"><span class="${tlpC(i.tlp)}">${i.tlp||'N/A'}</span></div></div>
    <div class="mr"><div class="mk">Acteur</div><div class="mv">${i.actor||'N/A'}</div></div>
    <div class="mr"><div class="mk">Date</div><div class="mv">${(i.created_at||'').slice(0,16)}</div></div>
    <div class="mrow-sep"></div>
    <div class="mr"><div class="mk">Source</div><div class="mv">${i.source||'N/A'}</div></div>
    <div class="mr"><div class="mk">STIX ID</div><div class="mv" style="color:var(--td)">${i.stix_id||'N/A'}</div></div>`);
}
function showIOCDet(o){
  const sc=parseFloat(o.score||0);
  openModal(`<div class="mttl">&#9901; IOC — ${(o.type||'?').toUpperCase()}</div>
    <div class="mr"><div class="mk">Valeur</div><div class="mv" style="color:var(--b)">${o.value||'N/A'}</div></div>
    <div class="mr"><div class="mk">Type</div><div class="mv">${o.type||'N/A'}</div></div>
    <div class="mr"><div class="mk">Score VT</div><div class="mv" style="color:${scCol(sc)};font-size:14px;font-family:var(--fd)">${sc.toFixed(1)}%</div></div>
    <div class="mr"><div class="mk">Source</div><div class="mv">${o.source||'N/A'}</div></div>
    <div class="mr"><div class="mk">TLP</div><div class="mv"><span class="${tlpC(o.tlp)}">${o.tlp||'N/A'}</span></div></div>
    <div class="mrow-sep"></div>
    <div class="mr"><div class="mk">VT Link</div><div class="mv"><a href="https://www.virustotal.com/gui/search/${encodeURIComponent(o.value||'')}" target="_blank" style="color:var(--b)">VirusTotal &#8599;</a></div></div>`);
}
async function checkMISPCVE(cveId){
  const el=document.getElementById('mc2');
  el.innerHTML+='<div style="margin-top:10px;color:var(--td);font-family:var(--fm);font-size:9px">Recherche dans MISP...</div>';
  try{
    const d=await fetch(`/api/misp/cve/${cveId}`).then(r=>r.json());
    if(d.found){
      el.innerHTML+=`<div class="mrow-sep"></div>
        <div style="font-family:var(--fm);font-size:9px;color:var(--g);margin-bottom:6px">MISP Event #${d.misp_id} trouve</div>
        <div class="mr"><div class="mk">Threat Level</div><div class="mv">${d.threat_level}</div></div>
        <div class="mr"><div class="mk">Date</div><div class="mv">${d.date}</div></div>
        <div class="mr"><div class="mk">Tags MISP</div><div class="mv">${(d.tags||[]).map(t=>`<span class="misp-tag ${t.startsWith('mitre')?'mt-mitre':t.startsWith('tlp:red')?'mt-tlp-r':t.startsWith('tlp:amber')?'mt-tlp-a':'mt-other'}">${t}</span>`).join('')}</div></div>
        <div class="mr"><div class="mk">Attributs</div><div class="mv">${(d.attributes||[]).map(a=>`<div style="margin:1px 0"><span style="color:var(--td)">${a.type}:</span> ${a.value}</div>`).join('')}</div></div>`;
    }else{
      el.innerHTML+=`<div style="margin-top:8px;color:var(--td);font-family:var(--fm);font-size:9px">Non trouve dans MISP</div>`;
    }
  }catch(e){el.innerHTML+=`<div style="margin-top:8px;color:var(--r);font-family:var(--fm);font-size:9px">Erreur MISP: ${e}</div>`}
}

// ── CVE PAGE ──────────────────────────────────────────────────────
function filterCVE(){cvePg=0;renderCVE()}
function clrCVE(){['f-sv','f-tlp','f-cl'].forEach(id=>document.getElementById(id).value='');document.getElementById('f-cq').value='';filterCVE()}
function filteredCVE(){
  const sv=document.getElementById('f-sv').value,tlp=document.getElementById('f-tlp').value;
  const cl=document.getElementById('f-cl').value,q=(document.getElementById('f-cq').value||'').toLowerCase();
  return allCVE.filter(c=>(!sv||c.severity===sv)&&(!tlp||c.tlp===tlp)&&(cl===''||String(c.cluster_id)===cl)&&
    (!q||(c.id||'').toLowerCase().includes(q)||(c.description||'').toLowerCase().includes(q)));
}
function renderCVE(){
  const data=filteredCVE(),total=data.length,pages=Math.ceil(total/cveN);
  const slice=data.slice(cvePg*cveN,(cvePg+1)*cveN);
  document.getElementById('cve-cl').textContent=total+' CVE';
  document.getElementById('cve-tb').innerHTML=slice.map(c=>`<tr>
    <td><a href="https://nvd.nist.gov/vuln/detail/${c.id}" target="_blank" style="color:var(--b);text-decoration:none">${c.id}</a></td>
    <td style="color:${c.cvss_score>=9?R:AM}">${c.cvss_score||'—'}</td>
    <td><span class="sv ${c.severity||'UNKNOWN'}">${c.severity||'—'}</span></td>
    <td>${c.cluster_id!=null?`<span class="cb c${c.cluster_id}">${CN[c.cluster_id]||'C'+c.cluster_id}</span>`:'—'}</td>
    <td><span class="${tlpC(c.tlp)}">${c.tlp||'—'}</span></td>
    <td style="max-width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--td)">${(c.description||'').slice(0,75)}</td>
    <td><button class="btn bb" onclick='showCVEDet(${JSON.stringify(c).replace(/'/g,"\\'")})' style="padding:1px 5px;font-size:7px">DETAIL</button></td>
  </tr>`).join('')||`<tr><td colspan="7" class="empty">Aucun resultat</td></tr>`;
  let pg='';
  if(pages>1){
    pg+=`<span>Page ${cvePg+1}/${pages}</span>`;
    if(cvePg>0)pg+=`<button class="pb" onclick="cvePg--;renderCVE()">&#9664; Prec</button>`;
    const s2=Math.max(0,cvePg-2),e2=Math.min(pages,cvePg+3);
    for(let i=s2;i<e2;i++)pg+=`<button class="pb${i===cvePg?' act':''}" onclick="cvePg=${i};renderCVE()">${i+1}</button>`;
    if(cvePg<pages-1)pg+=`<button class="pb" onclick="cvePg++;renderCVE()">Suiv &#9654;</button>`;
  }
  document.getElementById('cve-pg').innerHTML=pg;
}

// ── INCIDENTS ─────────────────────────────────────────────────────
function filterInc(){renderInc()}
function clrInc(){['f-is','f-it'].forEach(id=>document.getElementById(id).value='');document.getElementById('f-iq').value='';renderInc()}
function renderInc(){
  const sv=document.getElementById('f-is').value,tp=document.getElementById('f-it').value;
  const q=(document.getElementById('f-iq').value||'').toLowerCase();
  const data=allInc.filter(i=>(!sv||i.severity===sv)&&(!tp||i.event_type===tp)&&
    (!q||(i.repo||'').toLowerCase().includes(q)||(i.mitre_id||'').toLowerCase().includes(q)||(i.actor||'').toLowerCase().includes(q)));
  document.getElementById('inc-cl').textContent=data.length+' incidents';
  document.getElementById('inc-tb').innerHTML=data.slice(0,100).map(i=>{
    const an=i.anomaly_score?parseFloat(i.anomaly_score).toFixed(1):null;
    return`<tr>
      <td style="white-space:nowrap">${(i.created_at||'').slice(0,16)}</td>
      <td style="color:var(--b)">${(i.repo||'').replace('brahim6209/','')}</td>
      <td>${i.event_type||'—'}</td>
      <td><span class="sv ${i.severity||'UNKNOWN'}">${i.severity||'—'}</span></td>
      <td>${i.ml_severity||'—'}</td>
      <td>${an?`<span style="color:${scCol(an)}">${an}</span>`:'—'}</td>
      <td style="color:var(--p)">${i.mitre_id||'—'}</td>
      <td><span class="${tlpC(i.tlp)}">${i.tlp||'—'}</span></td>
      <td><button class="btn bb" onclick='showIncDet(${JSON.stringify(i).replace(/'/g,"\\'")})' style="padding:1px 5px;font-size:7px">DETAIL</button></td>
    </tr>`;
  }).join('')||`<tr><td colspan="9" class="empty">Aucun incident</td></tr>`;
}

// ── IOC ───────────────────────────────────────────────────────────
function filterIOC(){renderIOC()}
function clrIOC(){['f-iot','f-ios'].forEach(id=>document.getElementById(id).value='');document.getElementById('f-ioq').value='';renderIOC()}
function renderIOC(){
  const tp=document.getElementById('f-iot').value,ms=parseFloat(document.getElementById('f-ios').value)||0;
  const q=(document.getElementById('f-ioq').value||'').toLowerCase();
  const data=allIOC.filter(o=>(!tp||o.type===tp)&&(!ms||parseFloat(o.score||0)>=ms)&&(!q||(o.value||'').toLowerCase().includes(q)));
  document.getElementById('ioc-cl').textContent=data.length+' IOC';
  document.getElementById('ioc-ph').textContent=data.length+' IOC';
  document.getElementById('ioc-list').innerHTML=data.map(o=>{
    const sc=parseFloat(o.score||0);
    return`<div class="ir" onclick='showIOCDet(${JSON.stringify(o).replace(/'/g,"\\'")})' style="cursor:pointer">
      <span class="it">${(o.type||'?').toUpperCase()}</span>
      <span class="iv" title="${o.value}">${(o.value||'').slice(0,42)}</span>
      ${sc?`<span style="font-weight:600;color:${scCol(sc)}">${sc.toFixed(0)}%</span>`:''}
      <span style="font-size:7px;color:var(--td)">${o.source||''}</span>
      <span style="font-size:7px;color:var(--td)">&#9654;</span>
    </div>`;
  }).join('')||'<div class="empty">Aucun IOC</div>';
  const tc2={};allIOC.forEach(o=>{tc2[o.type]=(tc2[o.type]||0)+1});
  if(ch.ioc)ch.ioc.destroy();
  ch.ioc=new Chart(document.getElementById('ch-ioc'),{type:'doughnut',data:{
    labels:Object.keys(tc2),datasets:[{data:Object.values(tc2),backgroundColor:[B,P,AM,G],borderColor:'#020c02',borderWidth:2}]
  },options:{plugins:{legend:{labels:{color:G,font:{size:8,family:'Share Tech Mono'}}}},cutout:'60%',
    onClick:(e,el)=>{if(el.length){const lbl=Object.keys(tc2)[el[0].index];document.getElementById('f-iot').value=lbl;filterIOC()}}}});
}

// ── EXPORTS ───────────────────────────────────────────────────────
function exportJSON(){
  let data,fname;
  const sv=document.getElementById('f-sv')||{value:''};
  if(curPage==='cve'||curPage==='ov'){data=filteredCVE();fname='CTI_CVE'}
  else if(curPage==='inc'){
    const is=document.getElementById('f-is').value,it=document.getElementById('f-it').value,iq=(document.getElementById('f-iq').value||'').toLowerCase();
    data=allInc.filter(i=>(!is||i.severity===is)&&(!it||i.event_type===it)&&(!iq||(i.repo||'').toLowerCase().includes(iq)||(i.mitre_id||'').toLowerCase().includes(iq)));
    fname='CTI_Incidents';
  }else if(curPage==='ioc'){
    const iot=document.getElementById('f-iot').value,ios=parseFloat(document.getElementById('f-ios').value)||0,ioq=(document.getElementById('f-ioq').value||'').toLowerCase();
    data=allIOC.filter(o=>(!iot||o.type===iot)&&(!ios||parseFloat(o.score||0)>=ios)&&(!ioq||(o.value||'').toLowerCase().includes(ioq)));
    fname='CTI_IOC';
  }else{data=[{info:'Aller sur CVE, Incidents ou IOC pour export JSON'}];fname='CTI_Export'}
  const export_obj={
    generated:new Date().toISOString(),platform:"CTI Cloud-Native v4.0",
    classification:"TLP:AMBER",count:data.length,data:data
  };
  const a=document.createElement('a');
  a.href='data:application/json;charset=utf-8,'+encodeURIComponent(JSON.stringify(export_obj,null,2));
  a.download=`${fname}_${new Date().toISOString().slice(0,10)}.json`;a.click();
  showN('Export JSON','Fichier '+fname+' exporte','hi');
}
function exportCSV(){
  let rows=[],headers=[];
  if(curPage==='cve'||curPage==='ov'){
    headers=['CVE ID','CVSS','Severite','TLP','Cluster','Description'];
    rows=filteredCVE().map(c=>[c.id,c.cvss_score,c.severity,c.tlp,CN[c.cluster_id]||'',(c.description||'').replace(/,/g,' ').slice(0,100)]);
  }else if(curPage==='inc'){
    headers=['Date','Repo','Type','Severite','ML','Anomaly','MITRE','TLP'];
    rows=allInc.map(i=>[(i.created_at||'').slice(0,16),i.repo,i.event_type,i.severity,i.ml_severity,i.anomaly_score,i.mitre_id,i.tlp]);
  }else if(curPage==='ioc'){
    headers=['Type','Valeur','Score VT','Source','TLP'];
    rows=allIOC.map(o=>[o.type,o.value,o.score,o.source,o.tlp]);
  }else{headers=['Info'];rows=[['Aller sur CVE, Incidents ou IOC']]}
  const csv=[headers,...rows].map(r=>r.map(v=>`"${(v||'')}"`).join(',')).join('\n');
  const a=document.createElement('a');a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download=`CTI_${curPage}_${new Date().toISOString().slice(0,10)}.csv`;a.click();
  showN('Export CSV','Fichier CSV exporte','hi');
}
async function exportPDF(){
  const sv=document.getElementById(curPage==='cve'?'f-sv':curPage==='inc'?'f-is':'f-iot')||{value:''};
  let url=`/api/export/pdf/${curPage}`;
  if(curPage==='cve'){
    const s=document.getElementById('f-sv').value,t=document.getElementById('f-tlp').value,c=document.getElementById('f-cl').value,q=document.getElementById('f-cq').value;
    url+=`?severity=${s}&tlp=${t}&cluster=${c}&q=${q}`;
  }else if(curPage==='inc'){
    const s=document.getElementById('f-is').value,t=document.getElementById('f-it').value,q=document.getElementById('f-iq').value;
    url+=`?severity=${s}&type=${t}&q=${q}`;
  }else if(curPage==='ioc'){
    const t=document.getElementById('f-iot').value,s=document.getElementById('f-ios').value,q=document.getElementById('f-ioq').value;
    url+=`?type=${t}&min_score=${s}&q=${q}`;
  }else{url='/api/rapport/pdf'}
  showN('Export PDF','Generation en cours...','hi');
  window.open(url,'_blank');
}

// ── MISP PAGE ─────────────────────────────────────────────────────
async function loadMISP(){
  try{
    const d=await fetch('/api/misp/feed').then(r=>r.json());
    const s=d.summary||{};
    // KPI
    document.getElementById('ms-tot').textContent=s.total_events||0;
    document.getElementById('ms-cve').textContent=s.cve_events||0;
    document.getElementById('ms-inc').textContent=s.incident_events||0;
    document.getElementById('ms-red').textContent=s.tlp_red_count||0;
    document.getElementById('ms-amb').textContent=s.tlp_amber_count||0;
    document.getElementById('misp-tot').textContent=(s.total_events||0)+' events';
    document.getElementById('misp-ic').textContent=(s.incident_events||0)+' events';
    document.getElementById('misp-cc').textContent=(s.cve_events||0)+' events';

    // TLP bars
    const tlp=d.tlp_distribution||{},tt=Object.values(tlp).reduce((a,b)=>a+b,0)||1;
    document.getElementById('misp-tlp').innerHTML=`
      <div style="font-family:var(--fm);font-size:8px;color:var(--td);margin-bottom:8px">${s.total_events||0} events synchronises dans MISP Docker v2.5.35</div>
      ${Object.entries(tlp).map(([tg,cnt])=>{
        const pct=Math.round(cnt/tt*100),col=tg==='tlp:red'?R:tg==='tlp:amber'?AM:G;
        return`<div style="margin-bottom:7px">
          <div style="display:flex;justify-content:space-between;font-family:var(--fm);font-size:8px;margin-bottom:2px">
            <span style="color:${col}">${tg.toUpperCase()}</span><span style="color:var(--td)">${cnt} events (${pct}%)</span></div>
          <div style="height:3px;background:#0a1a0a;border-radius:2px">
            <div style="height:100%;width:${pct}%;background:${col};border-radius:2px;box-shadow:0 0 4px ${col}"></div>
          </div></div>`}).join('')}`;

    // MITRE
    const mt=d.mitre_techniques||[];
    document.getElementById('misp-mitre').innerHTML=mt.length
      ?mt.map(m=>`<div style="display:flex;align-items:center;gap:7px;margin-bottom:7px;font-family:var(--fm)">
          <span class="misp-tag mt-mitre" style="min-width:64px">${m.technique}</span>
          <span style="font-size:8px;color:var(--tx);flex:1">${m.label}</span>
          <span style="color:var(--r);font-size:8px;font-weight:600">x${m.count}</span></div>`).join('')
      :'<div style="color:var(--td);font-family:var(--fm);font-size:8px">Aucune technique</div>';

    // Incidents
    const mi2=d.incident_events||[];
    document.getElementById('misp-incs').innerHTML=mi2.length
      ?mi2.map(e=>`<div style="padding:4px 12px;border-bottom:1px solid #0a1a0a;font-family:var(--fm)">
          <div style="font-size:8px;color:var(--r)">Event #${e.id} — ${e.info.slice(0,48)}</div>
          <div style="font-size:7px;color:var(--td);margin-top:1px">
            ${e.mitre?`<span class="misp-tag mt-mitre">${e.mitre}</span>`:''} 
            ${(e.tags||[]).map(t=>`<span class="misp-tag ${t.startsWith('tlp:red')?'mt-tlp-r':t.startsWith('tlp:amber')?'mt-tlp-a':t.startsWith('mitre')?'mt-mitre':'mt-other'}">${t}</span>`).join('')}
          </div></div>`).join('')
      :'<div class="empty">Aucun incident</div>';

    // CVE table enrichie
    const cv2=d.cve_events||[];
    document.getElementById('misp-cve-tb').innerHTML=cv2.slice(0,25).map(e=>{
      const tl=e.threat_level==='1'?`<span style="color:${R}">HIGH</span>`:e.threat_level==='2'?`<span style="color:${AM}">MEDIUM</span>`:`<span style="color:${G}">LOW</span>`;
      return`<tr>
        <td>#${e.id}</td>
        <td style="color:var(--b)">${e.cve_id||'—'}</td>
        <td>${tl}</td>
        <td>${e.attr_count||0} attrs</td>
        <td>${(e.tags||[]).map(t=>`<span class="misp-tag ${t.startsWith('tlp:red')?'mt-tlp-r':t.startsWith('tlp:amber')?'mt-tlp-a':t.startsWith('mitre')?'mt-mitre':t.startsWith('cve')?'mt-cve':'mt-other'}">${t}</span>`).join('')}</td>
        <td style="color:var(--td)">${e.date||'—'}</td></tr>`;
    }).join('')||'<tr><td colspan="6" class="empty">Aucun event</td></tr>';

    // Correlations & Galaxies
    const corrHTML=[];
    if(s.top_mitre){
      corrHTML.push(`<div class="misp-corr">
        <div style="font-family:var(--fm);font-size:8px;color:var(--g);margin-bottom:5px">&#9670; Technique dominante detectee</div>
        <span class="misp-tag mt-mitre" style="font-size:9px;padding:2px 8px">${s.top_mitre}</span>
        <span style="font-family:var(--fm);font-size:8px;color:var(--tx);margin-left:6px">x${mt.find(m=>m.technique===s.top_mitre)?.count||0} occurrences dans MISP</span>
        <div style="font-family:var(--fm);font-size:7px;color:var(--td);margin-top:4px">
          Impact : Credentials exposes dans les pipelines CI/CD — Rotation immediate requise
        </div></div>`);
    }
    corrHTML.push(`<div class="misp-corr">
      <div style="font-family:var(--fm);font-size:8px;color:var(--g);margin-bottom:5px">&#9670; Distribution des menaces MISP</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        <span class="misp-tag mt-tlp-r" style="font-size:8px">TLP:RED ${s.tlp_red_count||0}</span>
        <span class="misp-tag mt-tlp-a" style="font-size:8px">TLP:AMBER ${s.tlp_amber_count||0}</span>
        <span class="misp-tag mt-cve" style="font-size:8px">CVE ${s.cve_events||0}</span>
        <span class="misp-tag mt-other" style="font-size:8px">CI/CD ${s.incident_events||0}</span>
        <span class="misp-tag mt-other" style="font-size:8px">IOC ${s.ioc_events||0}</span>
      </div></div>`);
    corrHTML.push(`<div class="misp-corr">
      <div style="font-family:var(--fm);font-size:8px;color:var(--g);margin-bottom:5px">&#9670; Galaxy ATT&CK — Cloud Matrix</div>
      <div style="font-family:var(--fm);font-size:7px;color:var(--td)">
        Toutes nos CVE et incidents sont mappes sur la matrice ATT&CK Cloud.<br>
        Technique confirmee : <span class="misp-tag mt-mitre">T1552.001</span> Credentials In Files<br>
        Categorie : TA0006 — Credential Access<br>
        Plateforme : AWS, Azure, GCP, Kubernetes, Docker
      </div></div>`);
    document.getElementById('misp-corr').innerHTML=corrHTML.join('');

    // Stats globales
    document.getElementById('misp-stats').innerHTML=`<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px">
      ${[['Total Events',s.total_events||0,G],['CVE Events',s.cve_events||0,B],
         ['Incidents CI/CD',s.incident_events||0,R],['IOC Events',s.ioc_events||0,AM],
         ['TLP:RED',s.tlp_red_count||0,R],['TLP:AMBER',s.tlp_amber_count||0,AM],
         ['Top Technique',s.top_mitre||'N/A',P],['Critiques',s.critical_events||0,R]].map(([k,v,c])=>`
        <div style="background:var(--bg3);border:1px solid var(--bd);padding:7px;border-radius:2px;text-align:center">
          <div style="font-family:var(--fm);font-size:7px;color:var(--td);margin-bottom:2px">${k}</div>
          <div style="font-family:var(--fd);font-size:14px;color:${c}">${v}</div></div>`).join('')}</div>`;
  }catch(e){console.error('MISP:',e)}
}

// ── OVERVIEW ──────────────────────────────────────────────────────
async function refreshOV(){
  try{
    const s=await fetch('/api/stats').then(r=>r.json());
    document.getElementById('k-cve').textContent=s.total_cve??'-';
    document.getElementById('k-crit').textContent=s.critical_cve??'-';
    document.getElementById('k-inc').textContent=s.total_incidents??'-';
    document.getElementById('k-ioc').textContent=s.total_ioc??'-';
    document.getElementById('k-mal').textContent=s.malicious_ioc??'-';
    document.getElementById('k-misp').textContent=s.misp_events??'85';
    const crit=s.critical_cve||0,tb=document.getElementById('tbadge');
    if(crit>=20){tb.textContent='THREAT: CRITICAL';tb.style.color=R;tb.style.borderColor=R}
    else if(crit>=10){tb.textContent='THREAT: HIGH'}
    else{tb.textContent='THREAT: MEDIUM';tb.style.color='#ffd700';tb.style.borderColor='#ffd700'}
    if((s.total_incidents||0)>prevInc&&prevInc>0)showN('NOUVEL INCIDENT CI/CD',`${s.total_incidents-prevInc} nouveaux detectes`);
    prevInc=s.total_incidents||0;
  }catch(e){}
  try{
    const sv=await fetch('/api/cve/by_severity').then(r=>r.json());
    if(ch.sv)ch.sv.destroy();
    ch.sv=new Chart(document.getElementById('ch-sev'),{type:'doughnut',data:{
      labels:Object.keys(sv),datasets:[{data:Object.values(sv),backgroundColor:[R,AM,'#ffd700',G,'#2a3a2a'],borderColor:'#020c02',borderWidth:2}]
    },options:{plugins:{legend:{labels:{color:G,font:{size:7,family:'Share Tech Mono'}}}},cutout:'62%',
      onClick:(e,el)=>{if(el.length){const lbl=Object.keys(sv)[el[0].index];showPage('cve',document.querySelectorAll('.nb')[1]);document.getElementById('f-sv').value=lbl;filterCVE()}}}});
  }catch(e){}
  try{
    const it=await fetch('/api/incidents/by_type').then(r=>r.json());
    if(ch.it)ch.it.destroy();
    ch.it=new Chart(document.getElementById('ch-inc'),{type:'bar',data:{
      labels:Object.keys(it),datasets:[{data:Object.values(it),backgroundColor:Object.keys(it).map(k=>k==='secret_exposed'?R:k==='job_failed_repeat'?AM:G),borderRadius:0,borderWidth:0}]
    },options:{plugins:{legend:{display:false}},scales:{
      x:{ticks:{color:G,font:{size:7,family:'Share Tech Mono'}},grid:{color:'#0a1a0a'}},
      y:{ticks:{color:G,font:{size:7}},grid:{color:'#0a1a0a'}}},
      onClick:(e,el)=>{if(el.length){const lbl=Object.keys(it)[el[0].index];showPage('inc',document.querySelectorAll('.nb')[2]);document.getElementById('f-it').value=lbl;filterInc()}}}});
  }catch(e){}
  try{
    const cl=await fetch('/api/cve/clusters').then(r=>r.json());
    if(ch.cl)ch.cl.destroy();
    ch.cl=new Chart(document.getElementById('ch-cl'),{type:'polarArea',data:{
      labels:Object.keys(cl).map(k=>CN[k]||'C'+k),
      datasets:[{data:Object.values(cl),backgroundColor:CC.map(c=>c+'55'),borderColor:CC,borderWidth:1}]
    },options:{plugins:{legend:{labels:{color:G,font:{size:7,family:'Share Tech Mono'}}}},
      scales:{r:{ticks:{color:G,font:{size:7}},grid:{color:'#0a1a0a'}}}}});
  }catch(e){}
  try{
    const incs=await fetch('/api/incidents').then(r=>r.json());
    allInc=incs;
    const hours={};
    incs.forEach(i=>{if(i.created_at){const h=i.created_at.slice(11,13)+':00';hours[h]=(hours[h]||0)+1}});
    const lbs=Object.keys(hours).sort(),vs=lbs.map(l=>hours[l]);
    if(ch.tl)ch.tl.destroy();
    ch.tl=new Chart(document.getElementById('ch-tl'),{type:'line',data:{
      labels:lbs,datasets:[{data:vs,borderColor:G,backgroundColor:G+'11',borderWidth:1.5,pointRadius:2,pointBackgroundColor:G,fill:true,tension:.3}]
    },options:{plugins:{legend:{display:false}},scales:{
      x:{ticks:{color:G,font:{size:7,family:'Share Tech Mono'}},grid:{color:'#0a1a0a'}},
      y:{ticks:{color:G,font:{size:7}},grid:{color:'#0a1a0a'}}}}});
    document.getElementById('ov-ic').textContent=incs.length+' events';
    document.getElementById('ov-tl').innerHTML=incs.slice(0,15).map(i=>{
      const sv=(i.severity||'low').toLowerCase(),dc=sv==='critical'?'cr':sv==='high'?'hi':'lo';
      return`<div class="tli ${dc}"><div class="tdot ${dc}"></div>
        <div style="flex:1">
          <div class="ttt">${i.event_type||'unknown'} — <span style="color:var(--td)">${(i.repo||'').split('/')[1]||''}</span></div>
          <div class="tmt">${(i.created_at||'').slice(0,16)} // ${i.mitre_id||'—'} // ML:${i.ml_severity||'—'}</div>
        </div><span class="sv ${i.severity||'UNKNOWN'}" style="font-size:6px">${i.severity||'—'}</span></div>`;
    }).join('');
    const risk={};
    incs.forEach(i=>{const rp=(i.repo||'unknown').split('/')[1]||i.repo||'unknown';
      if(!risk[rp])risk[rp]={score:0,count:0};
      risk[rp].score+=i.severity==='CRITICAL'?40:i.severity==='HIGH'?20:i.severity==='MEDIUM'?10:5;risk[rp].count++});
    const sorted=Object.entries(risk).sort((a,b)=>b[1].score-a[1].score).slice(0,6);
    const mx=sorted[0]?.[1]?.score||1;
    document.getElementById('ov-rg').innerHTML=sorted.map(([rp,d])=>{
      const pct=Math.min(100,Math.round(d.score/mx*100));
      const cls=pct>=80?'rc-c':pct>=50?'rc-h':pct>=30?'rc-m':'rc-l';
      return`<div class="rc ${cls}"><div class="rn">${rp}</div><div class="rv">${pct}</div><div class="rl">${d.count} inc</div></div>`;
    }).join('')||'<div class="empty">Aucun asset</div>';
  }catch(e){}
}

async function loadAll(){
  try{allCVE=await fetch('/api/cve').then(r=>r.json())}catch(e){}
  try{allIOC=await fetch('/api/ioc').then(r=>r.json())}catch(e){}
  try{allInc=await fetch('/api/incidents').then(r=>r.json())}catch(e){}
}
async function init(){await loadAll();await refreshOV()}
init();
setInterval(async()=>{await loadAll();await refreshOV()},30000);
</script>
</body></html>"""

# ── ROUTES ───────────────────────────────────────────────────────────────────
@app.route("/")
def index(): return render_template_string(HTML)

@app.route("/api/stats")
def api_stats():
    s = get_stats(); s['misp_events'] = 85; return jsonify(s)

@app.route("/api/cve")
def api_cve():
    with get_conn() as c:
        rows = c.execute("SELECT id,description,cvss_score,severity,tlp FROM cve WHERE severity IN ('CRITICAL','HIGH') ORDER BY cvss_score DESC").fetchall()
    from ml_models import cluster_cve
    result = []
    for r in rows:
        d = dict(r)
        try: cl = cluster_cve(d.get("description","")); d["cluster_id"] = cl["cluster_id"]
        except: d["cluster_id"] = None
        result.append(d)
    return jsonify(result)

@app.route("/api/cve/by_severity")
def api_cve_sev():
    with get_conn() as c:
        rows = c.execute("SELECT severity,COUNT(*) as n FROM cve GROUP BY severity").fetchall()
    return jsonify({r["severity"]: r["n"] for r in rows})

@app.route("/api/cve/clusters")
def api_cve_clusters():
    from ml_models import cluster_cve
    from collections import Counter
    with get_conn() as c:
        rows = c.execute("SELECT description FROM cve WHERE description IS NOT NULL LIMIT 200").fetchall()
    cnt = Counter()
    for r in rows:
        try: cnt[cluster_cve(r["description"])["cluster_id"]] += 1
        except: pass
    return jsonify({str(k): v for k, v in sorted(cnt.items())})

@app.route("/api/incidents")
def api_incidents():
    with get_conn() as c:
        rows = c.execute("SELECT * FROM incident ORDER BY created_at DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/incidents/by_type")
def api_inc_type():
    with get_conn() as c:
        rows = c.execute("SELECT event_type,COUNT(*) as n FROM incident GROUP BY event_type ORDER BY n DESC").fetchall()
    return jsonify({r["event_type"]: r["n"] for r in rows})

@app.route("/api/ioc")
def api_ioc():
    with get_conn() as c:
        rows = c.execute("SELECT i.*,e.score,e.malicious_count,e.total_engines FROM ioc i LEFT JOIN enrichment e ON i.value=e.ioc_value ORDER BY e.score DESC NULLS LAST").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/misp/feed")
def api_misp_feed():
    try:
        from misp_feed import get_misp_intelligence
        return jsonify(get_misp_intelligence())
    except Exception as e: return jsonify({"error": str(e)})

@app.route("/api/misp/cve/<cve_id>")
def api_misp_cve(cve_id):
    try:
        from misp_feed import get_misp_cve_details
        return jsonify(get_misp_cve_details(cve_id))
    except Exception as e: return jsonify({"error": str(e)})

# ── EXPORT PDF PAR SECTION ────────────────────────────────────────────────────
@app.route("/api/export/pdf/cve")
def export_pdf_cve():
    try:
        buf = gen_pdf_cve(
            severity=request.args.get("severity",""),
            tlp=request.args.get("tlp",""),
            cluster=request.args.get("cluster",""),
            q=request.args.get("q","")
        )
        fname = f"CTI_CVE_{datetime.date.today().strftime('%Y%m%d')}.pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=fname)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/export/pdf/inc")
def export_pdf_inc():
    try:
        buf = gen_pdf_incidents(
            severity=request.args.get("severity",""),
            itype=request.args.get("type",""),
            q=request.args.get("q","")
        )
        fname = f"CTI_Incidents_{datetime.date.today().strftime('%Y%m%d')}.pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=fname)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/export/pdf/ioc")
def export_pdf_ioc():
    try:
        buf = gen_pdf_ioc(
            itype=request.args.get("type",""),
            min_score=float(request.args.get("min_score",0) or 0),
            q=request.args.get("q","")
        )
        fname = f"CTI_IOC_{datetime.date.today().strftime('%Y%m%d')}.pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=fname)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/export/pdf/ov")
@app.route("/api/rapport/pdf")
def api_rapport_pdf():
    try:
        buf = gen_pdf_management()
        fname = f"CTI_Rapport_Management_{datetime.date.today().strftime('%Y%m%d')}.pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=fname)
    except Exception as e: return jsonify({"error": str(e)}), 500

# ── EXPORT JSON ───────────────────────────────────────────────────────────────
@app.route("/api/export/json/<section>")
def export_json(section):
    data = []
    if section == "cve":
        with get_conn() as c:
            rows = c.execute("SELECT id,description,cvss_score,severity,tlp FROM cve ORDER BY cvss_score DESC").fetchall()
        data = [dict(r) for r in rows]
    elif section == "incidents":
        with get_conn() as c:
            rows = c.execute("SELECT * FROM incident ORDER BY created_at DESC").fetchall()
        data = [dict(r) for r in rows]
    elif section == "ioc":
        with get_conn() as c:
            rows = c.execute("SELECT i.*,e.score FROM ioc i LEFT JOIN enrichment e ON i.value=e.ioc_value").fetchall()
        data = [dict(r) for r in rows]
    elif section == "misp":
        try:
            from misp_feed import get_misp_intelligence
            data = get_misp_intelligence()
        except Exception as e:
            data = {"error": str(e)}
    export = {"generated": datetime.datetime.now().isoformat(), "platform": "CTI Cloud-Native v4.0",
              "classification": "TLP:AMBER", "section": section, "count": len(data) if isinstance(data, list) else 1, "data": data}
    resp = Response(json.dumps(export, indent=2, default=str), mimetype="application/json")
    resp.headers["Content-Disposition"] = f"attachment; filename=CTI_{section}_{datetime.date.today().strftime('%Y%m%d')}.json"
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
