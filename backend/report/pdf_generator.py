"""
PDF Report Generator - Exact Nessus Report format.
Matches: Title page, Table of Contents, Hosts Summary (Executive),
then per-host detail pages with severity/plugin/name table.
"""
import os
from datetime import datetime
from collections import defaultdict
from typing import List
from parsers.parser_engine import Finding
from utils.logger import get_logger

logger = get_logger("pdf_generator")

C = {
    "critical":  (0.75, 0.00, 0.00),
    "high":      (0.85, 0.25, 0.00),
    "medium":    (0.88, 0.58, 0.00),
    "low":       (0.15, 0.45, 0.75),
    "info":      (0.40, 0.40, 0.40),
    "navy":      (0.09, 0.18, 0.36),
    "navy2":     (0.14, 0.27, 0.50),
    "row_alt":   (0.95, 0.97, 1.00),
    "row_white": (1.00, 1.00, 1.00),
    "border":    (0.78, 0.80, 0.88),
    "label_bg":  (0.20, 0.35, 0.60),
    "field_bg":  (0.97, 0.97, 0.99),
    "green_bg":  (0.93, 0.98, 0.93),
    "code_bg":   (0.94, 0.96, 0.94),
    "white":     (1.00, 1.00, 1.00),
    "light_grey":(0.92, 0.92, 0.94),
    "dark_text": (0.10, 0.10, 0.15),
}

SCORE    = {"critical":"10.0","high":"9.3","medium":"6.5","low":"3.3"}
LABEL    = {"critical":"Critical","high":"High","medium":"Medium","low":"Low","info":"Info"}
PRIORITY = {"critical":"Immediate (24–72 h)","high":"Short-term (30 d)",
            "medium":"Medium-term (90 d)","low":"Scheduled"}


class PDFGenerator:
    def __init__(self, org_name="Target Organization"):
        self.org_name = org_name

    def generate(self, findings, executive_summary, context_note, output_path):
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm, mm
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, PageBreak,
                                         HRFlowable, KeepTogether)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY

        PW, PH = A4
        LM = RM = 1.8 * cm
        W = PW - LM - RM

        def clr(k):    return colors.Color(*C[k])
        def sclr(sev): return colors.Color(*C.get(sev, C["info"]))

        def ps(name, **kw):
            p = ParagraphStyle(name)
            p.fontName    = kw.get("fontName",    "Helvetica")
            p.fontSize    = kw.get("fontSize",    9)
            p.leading     = kw.get("leading",     p.fontSize * 1.4)
            p.textColor   = kw.get("textColor",   colors.Color(.1,.1,.15))
            p.alignment   = kw.get("alignment",   TA_LEFT)
            p.spaceBefore = kw.get("spaceBefore", 0)
            p.spaceAfter  = kw.get("spaceAfter",  0)
            p.wordWrap    = "LTR"
            return p

        WHITE = colors.white

        s_body   = ps("bd",   fontSize=9,  leading=13)
        s_bodyj  = ps("bdj",  fontSize=9,  leading=13, alignment=TA_JUSTIFY)
        s_bold   = ps("bld",  fontSize=9,  fontName="Helvetica-Bold", leading=13)
        s_small  = ps("sm",   fontSize=8,  leading=12)
        s_smallb = ps("smb",  fontSize=8,  fontName="Helvetica-Bold", leading=12)
        s_code   = ps("cod",  fontSize=7.5,leading=10.5, fontName="Courier",
                      textColor=colors.Color(.05,.20,.05))
        s_white  = ps("wh",   fontSize=9,  fontName="Helvetica-Bold", textColor=WHITE)
        s_title  = ps("ttl",  fontSize=26, fontName="Helvetica-Bold",
                      textColor=colors.Color(.1,.1,.15), leading=32)
        s_title2 = ps("ttl2", fontSize=13, textColor=colors.Color(.3,.3,.3), leading=18)
        s_h1     = ps("h1",   fontSize=14, fontName="Helvetica-Bold",
                      textColor=colors.Color(.1,.1,.15), leading=18)
        s_h2     = ps("h2",   fontSize=11, fontName="Helvetica-Bold",
                      textColor=colors.Color(.1,.1,.15), leading=15)
        s_toc    = ps("toc",  fontSize=10, leading=16,
                      textColor=colors.Color(.15,.25,.55))
        s_foot   = ps("ft",   fontSize=8,  textColor=colors.Color(.5,.5,.5),
                      alignment=TA_CENTER)
        s_ctr    = ps("ctr",  fontSize=9,  alignment=TA_CENTER)

        def tbl(data, cw, rh=None, style=None):
            kw = dict(colWidths=cw)
            if rh and all(v is not None for v in rh):
                kw["rowHeights"] = rh
            t = Table(data, **kw)
            if style:
                t.setStyle(TableStyle(style))
            return t

        # ── group findings by host ────────────────────────────────────
        host_findings = defaultdict(list)
        for f in findings:
            host_findings[f.host].append(f)
        # sort hosts
        def host_sort_key(h):
            try:
                return tuple(int(p) for p in h.split("."))
            except:
                return (999,999,999,999)
        sorted_hosts = sorted(host_findings.keys(), key=host_sort_key)

        nc_total = sum(1 for f in findings if f.severity=="critical")
        nh_total = sum(1 for f in findings if f.severity=="high")
        nm_total = sum(1 for f in findings if f.severity=="medium")
        nl_total = sum(1 for f in findings if f.severity=="low")

        doc = SimpleDocTemplate(output_path, pagesize=A4,
            leftMargin=LM, rightMargin=RM,
            topMargin=2*cm, bottomMargin=2*cm)
        story = []

        # ══════════════════════════════════════════════════════════════
        # PAGE 1 — COVER  (matches Nessus "Nessus Report / Report" page)
        # ══════════════════════════════════════════════════════════════
        story.append(Spacer(1, 3*cm))
        story.append(Paragraph("Nessus Format Report", s_title))
        story.append(Spacer(1, 0.4*cm))
        story.append(HRFlowable(width="100%", thickness=1.5,
                                color=colors.Color(.6,.6,.6)))
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("Vulnerability Assessment Report", s_title2))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            datetime.now().strftime("%d/%b/%Y:%H:%M:%S GMT"), s_title2))
        story.append(Spacer(1, 1*cm))
        story.append(Paragraph(f"Target: {self.org_name}", s_body))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(f"Generated by Synthetic Auditor (Offline AI — Mistral)", s_small))
        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════
        # PAGE 2 — TABLE OF CONTENTS
        # ══════════════════════════════════════════════════════════════
        story.append(Paragraph("Table Of Contents", s_h1))
        story.append(Spacer(1, 0.4*cm))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.Color(.7,.7,.7)))
        story.append(Spacer(1, 0.4*cm))

        # TOC entry: Hosts Summary (Executive)
        toc_data = [[
            Paragraph("Hosts Summary (Executive)", s_toc),
            Paragraph("3", ps("tpg",fontSize=10,alignment=TA_RIGHT,
                               textColor=colors.Color(.15,.25,.55)))
        ]]
        pg = 4
        for host in sorted_hosts:
            toc_data.append([
                Paragraph(f"  • {host}", ps("thi",fontSize=10,leading=16,
                    leftIndent=10, textColor=colors.Color(.15,.25,.55))),
                Paragraph(str(pg), ps(f"tpg{host}",fontSize=10,alignment=TA_RIGHT,
                    textColor=colors.Color(.15,.25,.55)))
            ])
            pg += 1

        toc_tbl = tbl(toc_data, cw=[W-1.5*cm, 1.5*cm],
            style=[("VALIGN",(0,0),(-1,-1),"TOP"),
                   ("TOPPADDING",(0,0),(-1,-1),2),
                   ("BOTTOMPADDING",(0,0),(-1,-1),2),
                   ("LINEBELOW",(0,0),(-1,-1),.3,colors.Color(.85,.85,.85))])
        story.append(toc_tbl)
        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════
        # PAGE 3 — HOSTS SUMMARY (EXECUTIVE)  — overview table
        # ══════════════════════════════════════════════════════════════
        story.append(Paragraph("Hosts Summary (Executive)", s_h1))
        story.append(Spacer(1, 0.5*cm))

        # Per-host summary table  (like the Nessus grey-bar table)
        sum_hdr = [
            Paragraph("<b>Host</b>",     ps("sh",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE)),
            Paragraph("<b>Critical</b>", ps("sc",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE,alignment=TA_CENTER)),
            Paragraph("<b>High</b>",     ps("sh2",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE,alignment=TA_CENTER)),
            Paragraph("<b>Medium</b>",   ps("sm2",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE,alignment=TA_CENTER)),
            Paragraph("<b>Low</b>",      ps("sl",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE,alignment=TA_CENTER)),
            Paragraph("<b>Info</b>",     ps("si",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE,alignment=TA_CENTER)),
            Paragraph("<b>Total</b>",    ps("st",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE,alignment=TA_CENTER)),
        ]
        sum_rows = [sum_hdr]
        sum_styles = [
            ("BACKGROUND",(0,0),(-1,0), clr("navy")),
            ("GRID",(0,0),(-1,-1),.3, clr("border")),
            ("FONTSIZE",(0,0),(-1,-1), 9),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("TOPPADDING",(0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",(0,0),(-1,-1), 7),
            ("RIGHTPADDING",(0,0),(-1,-1), 7),
            ("ALIGN",(1,0),(-1,-1),"CENTER"),
        ]

        for i, host in enumerate(sorted_hosts):
            hf = host_findings[host]
            nc = sum(1 for f in hf if f.severity=="critical")
            nh = sum(1 for f in hf if f.severity=="high")
            nm = sum(1 for f in hf if f.severity=="medium")
            nl = sum(1 for f in hf if f.severity=="low")
            ni = 0
            nt = len(hf)
            rbg = clr("row_alt") if i%2==0 else clr("row_white")
            sum_styles.append(("BACKGROUND",(0,i+1),(-1,i+1), rbg))
            sum_rows.append([
                Paragraph(host, s_body),
                Paragraph(str(nc), ps(f"nc{i}",fontSize=9,alignment=TA_CENTER,
                    fontName="Helvetica-Bold" if nc>0 else "Helvetica",
                    textColor=sclr("critical") if nc>0 else colors.Color(.5,.5,.5))),
                Paragraph(str(nh), ps(f"nh{i}",fontSize=9,alignment=TA_CENTER,
                    fontName="Helvetica-Bold" if nh>0 else "Helvetica",
                    textColor=sclr("high") if nh>0 else colors.Color(.5,.5,.5))),
                Paragraph(str(nm), ps(f"nm{i}",fontSize=9,alignment=TA_CENTER,
                    fontName="Helvetica-Bold" if nm>0 else "Helvetica",
                    textColor=sclr("medium") if nm>0 else colors.Color(.5,.5,.5))),
                Paragraph(str(nl), ps(f"nl{i}",fontSize=9,alignment=TA_CENTER,
                    fontName="Helvetica-Bold" if nl>0 else "Helvetica",
                    textColor=sclr("low") if nl>0 else colors.Color(.5,.5,.5))),
                Paragraph(str(ni), ps(f"ni{i}",fontSize=9,alignment=TA_CENTER,
                    textColor=colors.Color(.5,.5,.5))),
                Paragraph(str(nt), ps(f"nt{i}",fontSize=9,alignment=TA_CENTER,
                    fontName="Helvetica-Bold")),
            ])

        # Totals row
        sum_styles.append(("BACKGROUND",(0,len(sorted_hosts)+1),(-1,len(sorted_hosts)+1),
                            clr("light_grey")))
        sum_rows.append([
            Paragraph("<b>Total</b>", ps("tot",fontSize=9,fontName="Helvetica-Bold")),
            Paragraph(str(nc_total), ps("tnc",fontSize=9,fontName="Helvetica-Bold",
                alignment=TA_CENTER,textColor=sclr("critical"))),
            Paragraph(str(nh_total), ps("tnh",fontSize=9,fontName="Helvetica-Bold",
                alignment=TA_CENTER,textColor=sclr("high"))),
            Paragraph(str(nm_total), ps("tnm",fontSize=9,fontName="Helvetica-Bold",
                alignment=TA_CENTER,textColor=sclr("medium"))),
            Paragraph(str(nl_total), ps("tnl",fontSize=9,fontName="Helvetica-Bold",
                alignment=TA_CENTER,textColor=sclr("low"))),
            Paragraph("0", ps("tni",fontSize=9,alignment=TA_CENTER,
                textColor=colors.Color(.5,.5,.5))),
            Paragraph(str(len(findings)), ps("tnt",fontSize=9,
                fontName="Helvetica-Bold",alignment=TA_CENTER)),
        ])

        story.append(tbl(sum_rows,
            cw=[7.0*cm, 2.0*cm, 2.0*cm, 2.2*cm, 1.6*cm, 1.4*cm, 1.2*cm],
            style=sum_styles))
        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════
        # PER-HOST DETAIL PAGES  — one page per host
        # Matches exact Nessus layout:
        #   IP heading, Summary box (Critical/High/Medium/Low/Info/Total)
        #   "Details" section header
        #   Table: Severity | Plugin Id | Name
        # ══════════════════════════════════════════════════════════════
        for host in sorted_hosts:
            hf = sorted(host_findings[host],
                        key=lambda f: ["critical","high","medium","low","info"].index(
                            f.severity if f.severity in
                            ["critical","high","medium","low"] else "info"))

            nc = sum(1 for f in hf if f.severity=="critical")
            nh = sum(1 for f in hf if f.severity=="high")
            nm = sum(1 for f in hf if f.severity=="medium")
            nl = sum(1 for f in hf if f.severity=="low")
            nt = len(hf)

            # ── Host IP heading ───────────────────────────────────────
            story.append(Paragraph(host, s_h1))
            story.append(Spacer(1, 0.4*cm))

            # ── Summary box ───────────────────────────────────────────
            story.append(Paragraph("Summary", s_h2))
            story.append(Spacer(1, 0.2*cm))

            sum_box_hdr = [
                Paragraph("<b>Critical</b>", ps("bh_c",fontSize=9,fontName="Helvetica-Bold",
                    textColor=WHITE,alignment=TA_CENTER)),
                Paragraph("<b>High</b>",     ps("bh_h",fontSize=9,fontName="Helvetica-Bold",
                    textColor=WHITE,alignment=TA_CENTER)),
                Paragraph("<b>Medium</b>",   ps("bh_m",fontSize=9,fontName="Helvetica-Bold",
                    textColor=WHITE,alignment=TA_CENTER)),
                Paragraph("<b>Low</b>",      ps("bh_l",fontSize=9,fontName="Helvetica-Bold",
                    textColor=WHITE,alignment=TA_CENTER)),
                Paragraph("<b>Info</b>",     ps("bh_i",fontSize=9,fontName="Helvetica-Bold",
                    textColor=WHITE,alignment=TA_CENTER)),
                Paragraph("<b>Total</b>",    ps("bh_t",fontSize=9,fontName="Helvetica-Bold",
                    textColor=WHITE,alignment=TA_CENTER)),
            ]
            sum_box_vals = [
                Paragraph(str(nc), ps(f"bv_c{host}",fontSize=12,fontName="Helvetica-Bold",
                    alignment=TA_CENTER,
                    textColor=sclr("critical") if nc>0 else colors.Color(.5,.5,.5))),
                Paragraph(str(nh), ps(f"bv_h{host}",fontSize=12,fontName="Helvetica-Bold",
                    alignment=TA_CENTER,
                    textColor=sclr("high") if nh>0 else colors.Color(.5,.5,.5))),
                Paragraph(str(nm), ps(f"bv_m{host}",fontSize=12,fontName="Helvetica-Bold",
                    alignment=TA_CENTER,
                    textColor=sclr("medium") if nm>0 else colors.Color(.5,.5,.5))),
                Paragraph(str(nl), ps(f"bv_l{host}",fontSize=12,fontName="Helvetica-Bold",
                    alignment=TA_CENTER,
                    textColor=sclr("low") if nl>0 else colors.Color(.5,.5,.5))),
                Paragraph("0",    ps(f"bv_i{host}",fontSize=12,fontName="Helvetica-Bold",
                    alignment=TA_CENTER,textColor=colors.Color(.5,.5,.5))),
                Paragraph(str(nt),ps(f"bv_t{host}",fontSize=12,fontName="Helvetica-Bold",
                    alignment=TA_CENTER,textColor=colors.Color(.1,.1,.15))),
            ]

            box_cw = [W/6]*6
            summary_box = tbl(
                [sum_box_hdr, sum_box_vals],
                cw=box_cw,
                rh=[0.55*cm, 0.75*cm],
                style=[
                    ("BACKGROUND",(0,0),(-1,0), clr("navy")),
                    ("BACKGROUND",(0,1),(-1,1), clr("light_grey")),
                    ("GRID",(0,0),(-1,-1), .5,  colors.white),
                    ("ALIGN",(0,0),(-1,-1),      "CENTER"),
                    ("VALIGN",(0,0),(-1,-1),     "MIDDLE"),
                    ("TOPPADDING",(0,0),(-1,-1),    4),
                    ("BOTTOMPADDING",(0,0),(-1,-1), 4),
                ])
            story.append(summary_box)
            story.append(Spacer(1, 0.5*cm))

            # ── Details heading ───────────────────────────────────────
            story.append(Paragraph("Details", s_h2))
            story.append(Spacer(1, 0.2*cm))

            # ── Details table  (Severity | Plugin Id | Name) ──────────
            det_hdr = [
                Paragraph("<b>Severity</b>",  ps("dh_s",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE)),
                Paragraph("<b>Port (Source File)</b>", ps("dh_p",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE,alignment=TA_CENTER)),
                Paragraph("<b>Name</b>",       ps("dh_n",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE)),
            ]
            det_rows = [det_hdr]
            det_styles = [
                ("BACKGROUND",(0,0),(-1,0), clr("navy")),
                ("GRID",(0,0),(-1,-1), .3,  clr("border")),
                ("FONTSIZE",(0,0),(-1,-1),  9),
                ("VALIGN",(0,0),(-1,-1),    "MIDDLE"),
                ("TOPPADDING",(0,0),(-1,-1),    4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
                ("LEFTPADDING",(0,0),(-1,-1),   7),
                ("RIGHTPADDING",(0,0),(-1,-1),  7),
                ("ALIGN",(1,0),(1,-1), "CENTER"),
            ]

            for i, f in enumerate(hf):
                rbg = clr("row_alt") if i%2==0 else clr("row_white")
                det_styles.append(("BACKGROUND",(0,i+1),(-1,i+1), rbg))

                # Severity cell: "Critical (10.0)" / "High (9.3)" etc.
                sev_score = SCORE.get(f.severity, "")
                sev_text  = f"{LABEL.get(f.severity,f.severity.title())} ({sev_score})"

                # Plugin ID: port number
                plugin_id = f"{f.port}" if f.port else str(abs(hash(f.title)) % 90000 + 10000)

                # Source file (short name only)
                src_short = os.path.basename(f.source_file) if f.source_file else ""
                # Port + source file label
                port_label = f"{f.port}" if f.port else "—"
                if src_short:
                    port_with_src = f"{port_label}\n({src_short})"
                else:
                    port_with_src = port_label

                det_rows.append([
                    Paragraph(sev_text, ps(f"ds{i}",fontSize=9,
                        fontName="Helvetica-Bold",
                        textColor=sclr(f.severity))),
                    Paragraph(port_with_src.replace("\n","<br/>"),
                        ps(f"dp{i}",fontSize=8,alignment=TA_CENTER,
                           textColor=colors.Color(.2,.2,.2))),
                    Paragraph(f.title[:90], ps(f"dn{i}",fontSize=9)),
                ])

            det_cw = [3.8*cm, 4.2*cm, W - 3.8*cm - 4.2*cm]
            story.append(tbl(det_rows, cw=det_cw, style=det_styles))
            story.append(Spacer(1, 0.6*cm))

            # ── AI Analysis section (after the table, per host) ────────
            # Collect unique AI analyses for this host
            critical_high = [f for f in hf if f.severity in ("critical","high") and f.llm_analysis][:3]
            if critical_high or executive_summary:
                story.append(Paragraph("Analysis", s_h2))
                story.append(Spacer(1, 0.2*cm))

                if executive_summary and host == sorted_hosts[0]:
                    for line in executive_summary.split("\n"):
                        line = line.strip()
                        story.append(Paragraph(line, s_bodyj) if line else Spacer(1,.1*cm))
                    story.append(Spacer(1, 0.3*cm))

                for f in critical_high:
                    if f.llm_analysis:
                        story.append(Paragraph(f"<b>{f.title}</b>", s_smallb))
                        story.append(Paragraph(f.llm_analysis, ps(f"ai{f.host}",
                            fontSize=8.5,leading=12.5,alignment=TA_JUSTIFY)))
                        if f.recommendation:
                            story.append(Spacer(1,.1*cm))
                            story.append(Paragraph(f"<b>Solution:</b> {f.recommendation}",
                                ps(f"sol{f.host}",fontSize=8.5,leading=12.5,
                                   textColor=colors.Color(.05,.3,.05))))
                        story.append(Spacer(1,.2*cm))

            story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════
        # FINAL PAGE — Remediation Summary
        # ══════════════════════════════════════════════════════════════
        story.append(Paragraph("Remediation Summary", s_h1))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            "The following table summarises prioritised remediation actions "
            "across all hosts, sorted by severity.",
            s_body))
        story.append(Spacer(1, 0.3*cm))

        rem_hdr = [
            Paragraph("<b>Severity</b>",  ps("rh0",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE)),
            Paragraph("<b>Host</b>",       ps("rh1",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE)),
            Paragraph("<b>Vulnerability</b>",ps("rh2",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE)),
            Paragraph("<b>Priority</b>",   ps("rh3",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE)),
            Paragraph("<b>Action</b>",     ps("rh4",fontSize=9,fontName="Helvetica-Bold",textColor=WHITE)),
        ]
        rem_rows = [rem_hdr]
        rem_styles = [
            ("BACKGROUND",(0,0),(-1,0), clr("navy")),
            ("GRID",(0,0),(-1,-1), .3, clr("border")),
            ("FONTSIZE",(0,0),(-1,-1), 8),
            ("VALIGN",(0,0),(-1,-1), "TOP"),
            ("TOPPADDING",(0,0),(-1,-1),    5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",(0,0),(-1,-1),   6),
            ("RIGHTPADDING",(0,0),(-1,-1),  6),
        ]
        for i, f in enumerate(findings):
            rbg = clr("row_alt") if i%2==0 else clr("row_white")
            rem_styles.append(("BACKGROUND",(0,i+1),(-1,i+1), rbg))
            rem_rows.append([
                Paragraph(LABEL.get(f.severity,""),
                    ps(f"rs{i}",fontSize=8,fontName="Helvetica-Bold",
                       textColor=sclr(f.severity))),
                Paragraph(f.host,         ps(f"rho{i}",fontSize=8)),
                Paragraph(f.title[:55],   ps(f"rt{i}",fontSize=8)),
                Paragraph(PRIORITY.get(f.severity,"Scheduled"),
                           ps(f"rp{i}",fontSize=8)),
                Paragraph((f.recommendation or "See details")[:100],
                           ps(f"ra{i}",fontSize=8)),
            ])

        story.append(Table(rem_rows,
            colWidths=[2.2*cm, 2.8*cm, 4.8*cm, 2.6*cm, 5.0*cm],
            repeatRows=1, style=TableStyle(rem_styles)))

        # Footer
        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", thickness=.5,
                                color=colors.Color(.7,.7,.7)))
        story.append(Paragraph(
            f"Synthetic Auditor — Offline AI (Mistral via Ollama) | "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')} | CONFIDENTIAL",
            s_foot))

        doc.build(story)
        logger.info(f"✅ Nessus-format PDF saved: {output_path}")
