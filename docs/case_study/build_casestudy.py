"""Build the final case study PDF.

    python docs/case_study/build_casestudy.py            # -> docs/Case_Study_Grp39_Final.pdf

Figures live in docs/case_study/assets/ (fig_benchmark.png is drawn by
make_benchmark_fig.py from demo/benchmark/results-full.json).
"""
import json
from pathlib import Path

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, Frame, Image, KeepTogether, NextPageTemplate, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
A = HERE / "assets"
OUT = ROOT / "docs" / "Case_Study_Grp39_Final.pdf"

# ── fonts and colours ───────────────────────────────────────────────────────
for name, f in (("Serif", "liberation-serif-fonts/LiberationSerif-Regular.ttf"),
                ("Serif-B", "liberation-serif-fonts/LiberationSerif-Bold.ttf"),
                ("Serif-I", "liberation-serif-fonts/LiberationSerif-Italic.ttf"),
                ("Serif-BI", "liberation-serif-fonts/LiberationSerif-BoldItalic.ttf"),
                ("Sans", "liberation-sans-fonts/LiberationSans-Regular.ttf"),
                ("Sans-B", "liberation-sans-fonts/LiberationSans-Bold.ttf")):
    pdfmetrics.registerFont(TTFont(name, f"/usr/share/fonts/{f}"))
pdfmetrics.registerFontFamily("Serif", normal="Serif", bold="Serif-B", italic="Serif-I", boldItalic="Serif-BI")
pdfmetrics.registerFontFamily("Sans", normal="Sans", bold="Sans-B", italic="Sans", boldItalic="Sans-B")

NAVY = colors.HexColor("#1f3a5f")
INK = colors.HexColor("#1c2333")
MUTED = colors.HexColor("#5b6577")
RULE = colors.HexColor("#c9d1de")
ZEBRA = colors.HexColor("#f3f5f9")
HEAD_BG = colors.HexColor("#e4e9f2")
ML_BLUE = colors.HexColor("#2255cc")
GOOD = colors.HexColor("#1a7f37")
BAD = colors.HexColor("#b42318")

body = ParagraphStyle("body", fontName="Serif", fontSize=11, leading=15, alignment=TA_JUSTIFY,
                      textColor=INK, spaceAfter=6)
small = ParagraphStyle("small", parent=body, fontSize=9.5, leading=12.5, alignment=0, spaceAfter=0)
cell = ParagraphStyle("cell", parent=body, fontSize=9.3, leading=11.6, alignment=0, spaceAfter=0)
cellb = ParagraphStyle("cellb", parent=cell, fontName="Serif-B")
caption = ParagraphStyle("caption", parent=body, fontSize=9.5, leading=12, alignment=TA_CENTER,
                         textColor=MUTED, fontName="Serif-I", spaceBefore=3, spaceAfter=10)
h1 = ParagraphStyle("h1", fontName="Sans-B", fontSize=15, leading=19, textColor=NAVY, spaceBefore=14, spaceAfter=7)
h2 = ParagraphStyle("h2", fontName="Sans-B", fontSize=12, leading=15, textColor=NAVY, spaceBefore=10, spaceAfter=5)
bullet = ParagraphStyle("bullet", parent=body, leftIndent=14, bulletIndent=3, spaceAfter=3)
ref = ParagraphStyle("ref", parent=body, fontSize=9.6, leading=12.4, leftIndent=22, firstLineIndent=-22,
                     alignment=0, spaceAfter=3)

story = []
_counters = {"fig": 0, "tab": 0}


def p(text, style=body):
    story.append(Paragraph(text, style))


def H1(text):
    story.append(Paragraph(text, h1))


def H2(text):
    story.append(Paragraph(text, h2))


def bullets(items):
    for t in items:
        story.append(Paragraph(t, bullet, bulletText="•"))


def figure(path, width_cm, text, max_h_cm=None):
    _counters["fig"] += 1
    im = PILImage.open(path)
    w = width_cm * cm
    h = w * im.height / im.width
    if max_h_cm and h > max_h_cm * cm:
        h = max_h_cm * cm
        w = h * im.width / im.height
    story.append(KeepTogether([Image(str(path), width=w, height=h),
                               Paragraph(f"<b>Figure {_counters['fig']}.</b> {text}", caption)]))
    return _counters["fig"]


def figure_pair(left, right, width_cm, text):
    _counters["fig"] += 1
    ims = []
    for path in (left, right):
        im = PILImage.open(path)
        w = width_cm / 2 * cm
        ims.append(Image(str(path), width=w, height=w * im.height / im.width))
    t = Table([ims], colWidths=[width_cm / 2 * cm] * 2)
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 2),
                           ("RIGHTPADDING", (0, 0), (-1, -1), 2)]))
    story.append(KeepTogether([t, Paragraph(f"<b>Figure {_counters['fig']}.</b> {text}", caption)]))
    return _counters["fig"]


def equation(path, num, height_cm=0.95):
    im = PILImage.open(path)
    h = height_cm * cm
    w = h * im.width / im.height
    t = Table([[Image(str(path), width=w, height=h), Paragraph(f"({num})", body)]],
              colWidths=[15.2 * cm, 1.3 * cm])
    t.setStyle(TableStyle([("ALIGN", (0, 0), (0, 0), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("ALIGN", (1, 0), (1, 0), "RIGHT")]))
    story.append(t)


def table(rows, widths, text, header_rows=1, align_right_cols=(), bold_cols=(), keep=True):
    _counters["tab"] += 1
    data = []
    for r_i, row in enumerate(rows):
        out = []
        for c_i, v in enumerate(row):
            if isinstance(v, str):
                st = cellb if (r_i < header_rows or c_i in bold_cols) else cell
                if c_i in align_right_cols and r_i >= header_rows:
                    st = ParagraphStyle("r", parent=st, alignment=2)
                out.append(Paragraph(v, st))
            else:
                out.append(v)
        data.append(out)
    t = Table(data, colWidths=[w * cm for w in widths], repeatRows=header_rows)
    style = [("BACKGROUND", (0, 0), (-1, header_rows - 1), HEAD_BG),
             ("LINEABOVE", (0, 0), (-1, 0), 0.9, NAVY),
             ("LINEBELOW", (0, header_rows - 1), (-1, header_rows - 1), 0.6, NAVY),
             ("LINEBELOW", (0, -1), (-1, -1), 0.9, NAVY),
             ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 3.2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.2),
             ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5)]
    for i in range(header_rows, len(rows)):
        if (i - header_rows) % 2 == 1:
            style.append(("BACKGROUND", (0, i), (-1, i), ZEBRA))
    t.setStyle(TableStyle(style))
    cap = Paragraph(f"<b>Table {_counters['tab']}.</b> {text}", caption)
    story.append(KeepTogether([cap, t, Spacer(1, 8)]) if keep else cap)
    if not keep:
        story.append(t)
        story.append(Spacer(1, 8))
    return _counters["tab"]


def ok(v):
    return f'<font color="#1a7f37"><b>{v}</b></font>'


def bad(v):
    return f'<font color="#b42318"><b>{v}</b></font>'


def ml(v):
    return f'<font color="#2255cc"><b>{v}</b></font>'


# ── document template with TOC hooks ────────────────────────────────────────
class Doc(BaseDocTemplate):
    def afterFlowable(self, f):
        if isinstance(f, Paragraph) and f.style.name in ("h1", "h2", "abs"):
            text = f.getPlainText()
            level = 1 if f.style.name == "h2" else 0
            key = f"h{self.seq.nextf('h')}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=level, closed=level > 0)
            self.notify("TOCEntry", (level, text, self.page, key))


def on_title(canv, doc):
    canv.saveState()
    canv.setFillColor(NAVY)
    canv.rect(0, A4[1] - 1.1 * cm, A4[0], 1.1 * cm, stroke=0, fill=1)
    canv.rect(0, 0, A4[0], 0.5 * cm, stroke=0, fill=1)
    canv.restoreState()


def on_page(canv, doc):
    canv.saveState()
    canv.setFont("Sans-B", 8.5)
    canv.setFillColor(NAVY)
    canv.drawString(2 * cm, A4[1] - 1.3 * cm, "CASE STUDY — STAY AT THE HELM")
    canv.setFont("Sans", 8.5)
    canv.drawRightString(A4[0] - 2 * cm, A4[1] - 1.3 * cm, "IIIT Dharwad · Cloud Computing")
    canv.setStrokeColor(RULE)
    canv.setLineWidth(0.6)
    canv.line(2 * cm, A4[1] - 1.45 * cm, A4[0] - 2 * cm, A4[1] - 1.45 * cm)
    canv.line(2 * cm, 1.45 * cm, A4[0] - 2 * cm, 1.45 * cm)
    canv.setFillColor(MUTED)
    canv.drawString(2 * cm, 1.0 * cm, "Group 39 · Final version, November 2026")
    canv.drawRightString(A4[0] - 2 * cm, 1.0 * cm, f"Page {doc.page}")
    canv.restoreState()


doc = Doc(str(OUT), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm,
          title="Stay at the Helm — Case Study (Final Version)",
          author="Group 39: Ganesh Daware, Gagan Rathod, Venkatesh Dhangar, Advait Pathak",
          subject="Case study of Blaise and Rebecchi (IEEE CLOUD 2022) and its extension with learned edge weights")
frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")
doc.addPageTemplates([PageTemplate("title", [frame], onPage=on_title),
                      PageTemplate("body", [frame], onPage=on_page)])

bench = json.loads((ROOT / "demo/benchmark/results-full.json").read_text())
B = {i["id"]: i for i in bench["items"]}
BS = bench["summary"]

# ════════════════════════════════════════════════════════════════════════════
# Title page
# ════════════════════════════════════════════════════════════════════════════
c = lambda t, size, font="Sans", color=INK, lead=None, after=0: Paragraph(
    t, ParagraphStyle("t", fontName=font, fontSize=size, leading=lead or size * 1.3, alignment=TA_CENTER,
                      textColor=color, spaceAfter=after))
story += [Spacer(1, 1.2 * cm),
          c("INDIAN INSTITUTE OF INFORMATION TECHNOLOGY DHARWAD", 13.5, "Sans-B", NAVY, after=6),
          c("Department of Computer Science and Engineering · Cloud Computing", 10.5, color=MUTED, after=34),
          c("CASE STUDY ASSIGNMENT — FINAL VERSION", 11, "Sans-B", MUTED, after=26),
          c("Stay at the Helm", 30, "Serif-B", NAVY, after=6),
          c("Secure Kubernetes Deployments via Graph Generation<br/>and Attack Reconstruction", 16, "Serif", INK,
            lead=21, after=22),
          c("A study of Blaise and Rebecchi (IEEE CLOUD 2022), and its extension in KubeAttackViz:<br/>"
            "from predefined static coefficients to learned, evidence-based edge weights,<br/>"
            "checked against attack paths documented by public benchmarks", 11, "Serif-I", MUTED, lead=15,
            after=40),
          c("Submitted by (Group 39)", 11.5, "Sans-B", NAVY, after=8)]
team = Table([["Name", "Roll No."], ["Ganesh Daware", "23BCS038"], ["Gagan Rathod", "23BCS106"],
              ["Venkatesh Dhangar", "23BCS041"], ["Advait Pathak", "23BCS094"]], colWidths=[6.5 * cm, 3.5 * cm])
team.setStyle(TableStyle([("FONT", (0, 0), (-1, 0), "Sans-B", 10.5), ("FONT", (0, 1), (-1, -1), "Serif", 11),
                          ("TEXTCOLOR", (0, 0), (-1, -1), INK), ("LINEBELOW", (0, 0), (-1, 0), 0.8, NAVY),
                          ("ALIGN", (1, 0), (1, -1), "RIGHT"), ("TOPPADDING", (0, 0), (-1, -1), 4),
                          ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
story += [team, Spacer(1, 1.3 * cm),
          c("Submitted to", 10.5, color=MUTED, after=2),
          c("Dr. Malay Kumar", 13, "Serif-B", INK, after=2),
          c("Department of Computer Science and Engineering, IIIT Dharwad", 10.5, color=MUTED, after=22),
          c("November 2026", 11, "Sans", INK),
          NextPageTemplate("body"), PageBreak()]

# ── contents ────────────────────────────────────────────────────────────────
toc = TableOfContents()
toc.levelStyles = [ParagraphStyle("toc0", fontName="Sans-B", fontSize=10.5, leading=14, spaceBefore=5,
                                  textColor=NAVY),
                   ParagraphStyle("toc1", fontName="Serif", fontSize=10, leading=12.6, leftIndent=16,
                                  textColor=INK)]
toc.tableStyle = TableStyle([("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                             ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                             ("VALIGN", (0, 0), (-1, -1), "TOP")])
story += [Paragraph("Contents", ParagraphStyle("ct", parent=h1, spaceBefore=0)), toc, PageBreak()]

# ════════════════════════════════════════════════════════════════════════════
# Abstract
# ════════════════════════════════════════════════════════════════════════════
story.append(Paragraph("Abstract", ParagraphStyle("abs", parent=h1, spaceBefore=0)))
absb = ParagraphStyle("absb", parent=body, leftIndent=12, rightIndent=12, fontSize=10.6, leading=14.4)
p("This report studies “Stay at the Helm: secure Kubernetes deployments via graph generation and attack "
  "reconstruction” by Agathe Blaise and Filippo Rebecchi [1]. The paper proposes a four-step methodology for "
  "analysing Kubernetes Helm Charts: reconstruct a deployment graph, enrich it with six security analyses, assign "
  "node and edge weights with respect to the Kubernetes threat-matrix tactics, and reconstruct high-risk attack "
  "paths using Dijkstra’s algorithm after a log transformation. The evaluation covers 592 official Helm Charts "
  "from 14 public repositories, comprising 1,076 pods and 1,318 containers, and shows that connectivity, "
  "especially missing network policies and pod affinities, expands the set of containers reachable from an entry "
  "point by a factor of 2.35.", absb)
p("This is the final version of our case study. Like the paper, the first version of our implementation, "
  "KubeAttackViz [2], used predefined static coefficients. We keep the original case study and add an extension: "
  "every edge weight is derived from the probability that the attack step succeeds. Configuration-decidable steps "
  "are proven from live RBAC, NetworkPolicy and Pod Security state, and vulnerability steps use an exploitation "
  "model we trained on 361,825 NVD vulnerabilities labelled with the CISA Known Exploited Vulnerabilities "
  "catalogue. On a temporally held-out test set, the learned score raises ROC-AUC from 0.770 (CVSS score alone) to "
  "0.887 and precision in the top 100 from 5% to 54%.", absb)
p("We then test both weightings against an answer key we did not write: the attack paths documented by two "
  "public, deliberately vulnerable projects, Kubernetes Goat and Bad Pods, deployed unmodified on a live cluster. "
  f"Both weightings find all {BS['learned']['goat_total']} documented Kubernetes Goat attacks, but the learned "
  f"weights rank them at a mean position of {BS['learned']['goat_mean_rank']} instead of "
  f"{BS['static']['goat_mean_rank']} among {BS['learned']['paths_ranked']} paths, and agree with "
  f"{BS['learned']['goat_found'] + BS['learned']['badpods_correct']} of 15 documented answers instead of "
  f"{BS['static']['goat_found'] + BS['static']['badpods_correct']}. We also compare the weightings on three live "
  "clusters, validate the feasibility engine against 22,425 checks on a real cluster, report the sensitivity "
  "analysis the original paper did not include, and show that a misconfiguration introduced at runtime is detected "
  "within one monitoring interval and ranked first only by the learned weights.", absb)
p("<b>Keywords:</b> Kubernetes security, Helm, attack graphs, threat matrix, RBAC, Dijkstra, vulnerability "
  "exploitation prediction, machine learning, CISA KEV, Kubernetes Goat, Bad Pods.", absb)

# ════════════════════════════════════════════════════════════════════════════
# 1. Introduction
# ════════════════════════════════════════════════════════════════════════════
H1("1. Introduction")
p("Kubernetes provides security mechanisms such as network segmentation, process isolation and role-based access "
  "control (RBAC), but the paper notes that these controls are effective only when configured correctly. Helm adds "
  "another layer of complexity because Charts package deployment resources into YAML-based configuration and can "
  "become very large; the authors report Charts of more than 40,000 lines [1]. The central question of the paper "
  "is therefore not simply whether an individual Kubernetes setting passes a security check, but how configuration "
  "properties interact and form multi-step attack paths.")
p("The paper answers this question with a weighted graph. The weights, however, are predefined coefficients chosen "
  "by the authors (Table 2): for example, every high-severity vulnerability adds 1 to a container’s score and a "
  "missing network policy gives an edge probability of 0.8. Our first implementation followed the same design. When "
  "we presented it, the obvious follow-up questions were whether these numbers could be learned from real data "
  "instead of chosen by hand, and how we would know that the result is better and not only different. This final "
  "version answers both.")
H2("1.1 Contributions of this final version")
bullets([
    "<b>Case study (retained from the first submission).</b> A structured explanation of the paper’s threat model, "
    "method, scoring model, evaluation and limitations (Section 3).",
    "<b>Static-coefficient baseline.</b> Our first KubeAttackViz version and how its fixed coefficients relate to "
    "the paper’s (Section 5).",
    "<b>Learned edge weights.</b> A probabilistic edge model, w(e) = −ln P(e), identical in form to the paper’s "
    "log(1/z(e)) transformation, where P(e) is either decided exactly from cluster configuration or estimated by a "
    "model trained on public exploitation data (Section 6).",
    "<b>External benchmark.</b> Both weightings checked against attack paths documented by Kubernetes Goat and Bad "
    "Pods, two public projects whose manifests we deploy unmodified (Section 7.3).",
    "<b>Live comparison and validation.</b> Before/after comparison on three live clusters, validation of the "
    "feasibility engine against a real cluster, a sensitivity analysis of the one remaining assumed parameter, and a "
    "runtime drift experiment (Sections 7.2 and 7.4–7.6).",
    "<b>Demonstration tool.</b> A single-command presentation of all of the above on live clusters (Section 8).",
])
p("Section 2 introduces the background. Section 3 is the case study of the paper. Section 4 reviews related work. "
  "Section 5 presents KubeAttackViz with static coefficients, Section 6 the machine-learning extension and Section 7 "
  "compares the two. Section 8 describes the demonstration, Section 9 revisits the paper’s limitations and Section "
  "10 concludes.")

# ════════════════════════════════════════════════════════════════════════════
# 2. Background
# ════════════════════════════════════════════════════════════════════════════
H1("2. Background")
H2("2.1 The problem with checklists")
p("The paper groups Kubernetes configuration-auditing approaches into CIS-benchmark checks, custom best-practice "
  "checks and penetration-testing approaches. Examples discussed by the authors include kube-bench, kube-hunter, "
  "Checkov, kubeaudit and Polaris [1]. The limitation motivating the paper is that individual checks do not "
  "correlate findings into a single model of how weaknesses combine across components, and that results are not "
  "expressed in terms of attacker tactics and multi-stage paths.")
H2("2.2 The Kubernetes threat matrix")
p("MITRE ATT&amp;CK organises adversary behaviour into tactics and techniques [4]. Microsoft’s threat matrix for "
  "Kubernetes adapts this structure to container orchestration [3]. It provides the vocabulary for stages such as "
  "initial access, execution, privilege escalation, credential access, discovery, lateral movement and impact. The "
  "paper does not use the matrix only as background: it incorporates tactic-specific scores into the graph model.")
H2("2.3 Kubernetes security controls relevant to attack paths")
p("Three Kubernetes mechanisms determine most of the edges in an attack graph, both in the paper and in our "
  "implementation:")
bullets([
    "<b>RBAC.</b> Roles and ClusterRoles list allowed verbs on resources; RoleBindings and ClusterRoleBindings grant "
    "them to users, groups and ServiceAccounts. A pod inherits the permissions of its ServiceAccount through the "
    "mounted token [6].",
    "<b>NetworkPolicy.</b> Without any policy selecting a pod, all ingress and egress traffic is allowed. This default "
    "is the reason the paper treats a missing network policy as a high-probability edge.",
    "<b>Pod security.</b> Root execution, privileged mode, Linux capabilities and host namespaces control whether a "
    "compromised container can reach its node. The paper analyses these via Pod Security Policies (PSP); PSP was "
    "removed in Kubernetes v1.25 and replaced by Pod Security Standards (PSS) and the Pod Security Admission "
    "controller [7].",
])

# ════════════════════════════════════════════════════════════════════════════
# 3. The reference paper
# ════════════════════════════════════════════════════════════════════════════
H1("3. The reference paper: Stay at the Helm")
H2("3.1 Overview and contribution")
p("Blaise and Rebecchi, from Thales, presented the paper at the 2022 IEEE 15th International Conference on Cloud "
  "Computing (CLOUD), pages 59–69 [1]. The contribution is a methodology that converts a Helm Chart deployment into "
  "an enriched graph, evaluates its security properties against Kubernetes threat-matrix tactics, and reconstructs "
  "risky attack paths. The authors validate the approach on a dataset of public Helm Charts rather than only on a "
  "small hand-built example.")
H2("3.2 Threat model")
p("The attacker is assumed to obtain an initial foothold in a container, typically through a service exposed "
  "outside the cluster (NodePort, LoadBalancer or Ingress), and then to move laterally between pods or towards the "
  "host. Internal services are not directly reachable, but the paper introduces a parameter ω: a non-zero "
  "probability that an attacker can reach a pod even if its service is internal, which models entry mechanisms not "
  "visible from service exposure alone (for example a compromised dependency).")
H2("3.3 The method")
figure(A / "fig_method.png", 16, "The four-step methodology, redrawn from Figure 1 and Section IV of [1].")
p("<b>Step 1: graph extraction.</b> The Chart is parsed into a model containing 16 resource categories, including "
  "pods, containers, namespaces, services, service accounts, roles and bindings, pod security policies, network "
  "policies, secrets and volumes. The final topological graph has pods and containers as vertices. Each pod is "
  "connected to the containers it encapsulates, while pod-to-pod edges represent possible movement based on network "
  "policies, permissions to execute in other pods and pod co-location. Other Kubernetes resources are correlated to "
  "the pod they affect [1].")
p("<b>Step 2: enrichment with six security analyses.</b> The graph is enriched using six feature groups inspired by "
  "the Kubernetes CIS benchmark [5] (Table 1). For vulnerabilities, the paper records high- or critical-severity "
  "findings (CVSS &gt; 7) using scanners such as Trivy, Docker Scan and Snyk.")
table([["#", "Feature", "What it captures"],
       ["1", "Container vulnerabilities", "Count of high or critical CVEs per image, from open-source scanners"],
       ["2", "Pod accessibility", "Whether services expose a pod (ClusterIP, NodePort, LoadBalancer, Ingress)"],
       ["3", "Security policies and contexts", "Root or privileged execution, Linux capabilities, host network, PID "
        "and IPC, volume types"],
       ["4", "Access control (RBAC)", "Service-account permissions such as reading secrets or creating pods"],
       ["5", "Firewall rules", "Network policies governing which pods may talk to which"],
       ["6", "Pod affinities", "Whether pods must, or must not, share a machine"]],
      [0.8, 5.0, 11.2], "The six enrichment features, after Section IV-B of [1].")
p("<b>Step 3: scoring.</b> The paper defines two scoring systems. The single-weight system assigns one node weight "
  "and one edge weight; edge weights are probabilities in [0, 1] and multiply along a path. The multiple-weight "
  "system assigns each node a sub-score per threat-matrix tactic, while edges keep probability-style weights. The "
  "authors use nine tactics: Initial Access, Execution, Privilege Escalation, Defence Evasion, Credential Access, "
  "Discovery, Impact, Lateral Movement to Host and Lateral Movement to Pod. A node’s score is a weighted sum of its "
  "findings, and an edge’s probability combines the γ coefficients of the conditions that create it:")
equation(A / "eq1.png", 1)
equation(A / "eq2.png", 2)
p("The coefficients are configurable; the paper gives one concrete setting for its evaluation (Table 2).")
table([["Symbol", "Meaning", "Value"],
       ["α<sub>1</sub> / α<sub>2</sub>", "Vulnerabilities / extra Linux capabilities", "1 per vuln. / 5 per capability"],
       ["β<sub>1</sub>, β<sub>2</sub>", "Accessible service; ability to run as root", "100 each"],
       ["β<sub>3</sub>, β<sub>5</sub>", "Can escalate privilege; can exec into other pods", "100 each"],
       ["β<sub>4</sub>", "Permissions (evasion, credential access, discovery, impact)", "10 per tactic"],
       ["β<sub>6</sub>, β<sub>7</sub>", "Can reach host network; can reach host paths", "100 each"],
       ["β<sub>8</sub>", "Allowed host volume types", "10 per volume"],
       ["γ<sub>1</sub>, γ<sub>2</sub>, γ<sub>3</sub>", "No network policy; pod affinity; pod execution capacity",
        "0.8; 0.4; 1"]],
      [2.6, 9.4, 5.0], "Predefined coefficients chosen by the authors (Table VI of [1], condensed).")
p("<b>Step 4: attack-path reconstruction.</b> The objective is to find acyclic paths with the largest product of "
  "edge probabilities. The paper turns this maximisation into a shortest-path problem by taking log(1/z(e)) as the "
  "edge cost; since 0 &lt; z ≤ 1 every cost is non-negative and Dijkstra’s algorithm applies:")
equation(A / "eq3.png", 3, 1.05)
p("This transformation is the bridge to our extension: Section 6 keeps exactly this form and changes only where "
  "z(e) comes from.")
H2("3.4 An illustrative example")
p("The following example was constructed for this report to make the probability model intuitive; it is not an "
  "experiment reported by the authors. Consider a web pod exposed by a LoadBalancer, an internal API pod, and a "
  "database pod whose service account can read secrets. If no network policy separates the pods, each edge has "
  "probability γ<sub>1</sub> = 0.8. The two-edge path has probability 0.8 × 0.8 = 0.64 and transformed cost "
  "log(1/0.8) + log(1/0.8) ≈ 0.446. Individually moderate weaknesses combine into a multi-step route.")
figure(A / "fig_example.png", 15, "Illustrative example constructed for this report, using the paper’s edge "
       "probability for a missing network policy.")
H2("3.5 Evaluation")
p("<b>Dataset.</b> The evaluation scrapes Helm Charts from 14 open-source repositories: 592 official Charts, 1,076 "
  "pods and 1,318 containers. The largest Chart contains 43,628 lines; the average is 564 lines [1].")
p("<b>Compliance with the CIS benchmark.</b> Table IV of the paper reports that 32.2% of containers run as root, "
  "4.2% are privileged, 86.3% retain the default Linux capabilities and 88.8% allow NET_RAW; 9.8% may list secrets, "
  "13.9% list pods, 8.1% create pods, 1.0% mount host paths and 0.8% use the host network. The median image has "
  "roughly 100 high- or critical-severity vulnerabilities, with examples above 3,000, and some images are opaque to "
  "the scanners [1].")
figure(A / "fig_cis.png", 16.5, "CIS non-compliance and reachability from outside, prepared for this report from "
       "Tables IV and V of [1].")
p("Connectivity is the key reason for the graph model. Starting from 134 containers reachable through exposed "
  "services, adding pod-execution permissions raises the count to 135, adding missing network policies to 293, and "
  "adding pod affinities to 315, a 2.35× increase over the initially reachable set [1].")
table([["Tactic", "ω = 0", "ω = 0, with paths", "ω &gt; 0"],
       ["Initial access", "122", "122", "1,318"],
       ["Execution", "103", "252", "1,112"],
       ["Privilege escalation (capabilities)", "4", "13", "92"],
       ["Privilege escalation (run as root)", "112", "285", "1,194"],
       ["Permissions", "23", "43", "224"],
       ["Access to host network / paths / volumes", "0 / 0 / 0", "0 / 0 / 0", "72 / 13 / 10"]],
      [7.4, 2.6, 3.8, 3.2], "Containers vulnerable to each tactic under three settings (Table VII of [1], condensed).",
      align_right_cols=(1, 2, 3))
p("<b>Case studies.</b> Similar global scores can arise from different causes. The node-exporter pod in the Bitnami "
  "kube-prometheus Chart scores 470 and combines host-network, host-PID and host-volume access; the pachd pod in the "
  "Pachyderm Chart scores 411 and combines privileged execution with secret and pod permissions. In "
  "spring-cloud-data-flow, a path starts at a LoadBalancer, reaches an opaque container and a container with 20 high "
  "or critical vulnerabilities, then uses service-account permissions to read secrets and create pods. In "
  "pachyderm, a NodePort entry leads through missing network policies to a privileged pod; in metallb, security "
  "policies permit host-network access and host-volume mounting (Figure 4).")
figure(A / "fig_paper_paths.png", 15, "Attack-path examples from the paper’s evaluation: spring-cloud-data-flow, "
       "pachyderm and metallb (Fig. 6 of [1]).")
H2("3.6 The authors’ conclusions")
p("The authors conclude that the methodology can analyse hundreds of Helm Charts and expose security-sensitive "
  "configurations and attack paths. They identify three directions for future work: improving vulnerability "
  "analysis so that fewer images remain opaque, automated remediation and prioritisation of fixes based on "
  "reconstructed paths, and integration into a Kubernetes CI/CD security pipeline [1].")
H2("3.7 Critical assessment")
p("<b>Strengths.</b> The main contribution is the correlation of heterogeneous configuration data into one graph "
  "rather than treating each finding independently. The evaluation uses 592 public Charts, the connectivity "
  "experiment directly demonstrates how graph relationships expand the attack surface, and the threat-matrix "
  "mapping gives the output an attacker-oriented reading.")
p("<b>Limitations.</b> Table 4 lists the limitations we identified; the right-hand column states which of them this "
  "work addresses and where.")
table([["#", "Limitation of [1]", "Addressed in this work"],
       ["L1", "Coefficients are chosen by hand; one setting is evaluated, with no sensitivity analysis.",
        "Replaced by measured or learned probabilities (§6); sensitivity analysis of the remaining parameter (§7.5)."],
       ["L2", "Vulnerabilities are counted (α<sub>1</sub> = 1 each, CVSS &gt; 7), so 100 rarely-exploited CVEs outweigh "
        "one actively exploited CVE.", "Each CVE gets an exploitation probability learned from NVD + CISA KEV (§6.3)."],
       ["L3", "Static analysis of Charts; no validation of the predicted edges against a live cluster or an external "
        "answer key.", "Edges validated against the API server and live probes (§7.2); attack paths checked against "
        "Kubernetes Goat and Bad Pods (§7.3)."],
       ["L4", "Pod Security Policies are deprecated and removed (Kubernetes v1.25).",
        "Mapped to Pod Security Standards checks (§5.2)."],
       ["L5", "One-off analysis; no monitoring of configuration drift.",
        "Continuous multi-cluster monitoring with change alerts (§7.6)."]],
      [1.0, 7.6, 8.4], "Limitations of the reference paper and how this work addresses them.", bold_cols=(0,))

# ════════════════════════════════════════════════════════════════════════════
# 4. Related work
# ════════════════════════════════════════════════════════════════════════════
H1("4. Related work")
p("<b>Attack graphs.</b> Automated attack-graph generation goes back to Sheyner et al. [8], who used model "
  "checking, and MulVAL [9], which derives attack graphs from Datalog rules over vulnerability and configuration "
  "facts. Both assume known exploit preconditions; the paper of Blaise and Rebecchi brings the idea to Kubernetes "
  "configuration.")
p("<b>Kubernetes auditing tools.</b> kube-bench checks a cluster against the CIS benchmark, kube-hunter probes from "
  "an attacker’s point of view, and Checkov, kubeaudit and Polaris lint manifests [1]. They report individual "
  "findings rather than paths.")
p("<b>Vulnerability prioritisation.</b> CVSS [10] measures technical severity, not the likelihood of exploitation. "
  "The Exploit Prediction Scoring System (EPSS) [11] estimates the probability of exploitation in the next 30 days, "
  "and the CISA Known Exploited Vulnerabilities (KEV) catalogue [12] lists vulnerabilities with confirmed "
  "exploitation. We use KEV as ground truth to train our model and EPSS only as an external reference.")
p("<b>Vulnerable-by-design clusters.</b> Kubernetes Goat [15] is an intentionally vulnerable cluster for security "
  "training; each scenario documents an attack step by step. Bad Pods [16] is a set of eight pod manifests, each "
  "enabling one host-level setting, with documentation of whether that setting alone gives root on the node. "
  "Neither was built to evaluate attack-graph tools, which makes them a useful external answer key: their authors "
  "decided what the attacks are, not us (Section 7.3).")

# ════════════════════════════════════════════════════════════════════════════
# 5. KubeAttackViz static
# ════════════════════════════════════════════════════════════════════════════
H1("5. Our implementation: KubeAttackViz with static coefficients")
p("KubeAttackViz [2] is an open-source attack-path analysis and visualisation tool for Kubernetes. It reads cluster "
  "state through kubectl (or from a JSON dump), builds a directed NetworkX graph and applies graph algorithms: BFS "
  "blast radius, Dijkstra shortest attack paths, bounded Johnson cycle detection, critical-node analysis by graph "
  "surgery, RBAC auditing, temporal comparison of snapshots, remediation advice, natural-language explanations and a "
  "D3.js interactive viewer.")
figure(A / "fig_arch.png", 15.5, "KubeAttackViz architecture. The edge-weight stage is where the static coefficients "
       "(first version) are replaced by learned probabilities (this work).")
H2("5.1 Mapping to the paper’s four steps")
table([["Paper step [1]", "KubeAttackViz component"],
       ["1. Graph extraction from a Helm Chart", "Inventory read from a live cluster with kubectl (pods, ServiceAccounts, "
        "Roles, bindings, Secrets, Services, NetworkPolicies, nodes)"],
       ["2. Enrichment with six features", "Feasibility engine: RBAC evaluation, NetworkPolicy evaluation, pod security "
        "checks, Trivy image scanning [14]"],
       ["3. Scoring (α, β, γ coefficients)", "Edge weights: static coefficients (first version) → learned probabilities "
        "(this work)"],
       ["4. Dijkstra on log(1/z)", "Dijkstra on w = −ln P, plus BFS blast radius, cycles and critical nodes"]],
      [6.2, 10.8], "Correspondence between the paper’s methodology and KubeAttackViz.")
H2("5.2 The six features in a live cluster")
p("The feasibility engine computes each of the paper’s six features from the live API objects rather than from "
  "Chart templates:")
table([["Paper feature", "How KubeAttackViz computes it"],
       ["1 Container vulnerabilities", "Trivy scan of every running image; each CVE scored for exploitation "
        "probability (§6.3)"],
       ["2 Pod accessibility", "Services of type NodePort/LoadBalancer and Ingresses become edges from an internet "
        "source; RBAC users and labelled pods are also entry points"],
       ["3 Security contexts", "Pod Security Standards (baseline) checks: privileged, host namespaces, hostPath, "
        "capabilities, run-as-root; PSP is no longer used"],
       ["4 RBAC", "Full rule evaluation: scope, wildcards, resourceNames, ServiceAccount groups, token automount; e.g. "
        "read secrets, exec, create pods, bind, impersonate"],
       ["5 Network policies", "Ingress and egress evaluation with pod/namespace selectors (AND semantics) and ports"],
       ["6 Pod affinities", "Pods on the same node are linked to that node through host-access edges when they can "
        "escape the container"]],
      [4.6, 12.4], "The paper’s six features as implemented in the feasibility engine.")
H2("5.3 The first version: predefined static coefficients")
p("Like the paper, the first version of KubeAttackViz gave every relationship type a fixed, hand-chosen cost (an "
  "“effort” value; lower means easier) and every node type a fixed impact. Path risk divided the impact of the "
  "target by the accumulated effort:")
equation(A / "eq4.png", 4)
table([["Relationship", "Cost", "Relationship", "Cost", "Relationship", "Cost"],
       ["exposes", "2.5", "can_read (secret)", "3.0", "can_bind", "5.0"],
       ["runs_as", "2.0", "can_exec", "3.5", "can_proxy", "5.0"],
       ["bound_to", "3.0", "can_create_token", "3.0", "host_access", "6.0"],
       ["grants", "4.0", "can_impersonate", "3.0", "connects_to", "2.0"]],
      [3.4, 1.6, 3.8, 1.6, 3.4, 1.6], "Static edge coefficients of the first KubeAttackViz version (excerpt).",
      align_right_cols=(1, 3, 5))
p("Paths were labelled CRITICAL, HIGH, MEDIUM or LOW at risk thresholds 7, 5 and 3. This design shares the paper’s "
  "weakness L1: the numbers are plausible but not measured. A cost of 3.0 for reading a secret is the same in every "
  "cluster, whether the permission actually exists or not, and a pod with a remotely exploitable, actively exploited "
  "CVE receives the same coefficient as a pod with no known vulnerability.")

# ════════════════════════════════════════════════════════════════════════════
# 6. Extension
# ════════════════════════════════════════════════════════════════════════════
H1("6. Extension: learned, evidence-based edge weights")
H2("6.1 Design principle")
p("We keep the paper’s probabilistic edge model and change only where the probabilities come from. Every edge e is "
  "given the probability P(e) that the corresponding attack step succeeds, and its weight is")
equation(A / "eq5.png", 5)
p("which is exactly the paper’s log(1/z(e)) with z = P. Dijkstra’s shortest path is therefore the most likely attack "
  "path, and the path risk becomes impact times probability of success:")
equation(A / "eq6.png", 6, 0.75)
p("We deliberately did not train a model to imitate our own static coefficients: that would only reproduce our "
  "guesses. Instead, each edge is assigned to one of three evidence classes (Table 8).")
table([["Evidence class", "Used for", "Probability"],
       ["exact-config", "Steps that the configuration decides: RBAC grants, token mounts, NetworkPolicy reachability, "
        "privileged pod → node", "0.995 if allowed; the edge is absent if not allowed"],
       ["cve-model", "Exploiting a reachable workload through a vulnerability in its image",
        "1 − (1 − p<sub>u</sub>)(1 − p<sub>x</sub>), p<sub>x</sub> from the CVE model"],
       ["scenario-param", "Exploiting a workload with no known exploitable CVE; other host-level settings "
        "(hostPath, hostPID, hostNetwork, hostIPC)", "p<sub>u</sub> = 0.05 (assumed, varied in §7.5)"]],
      [3.0, 8.4, 5.6], "Evidence classes for edge probabilities.", bold_cols=(0,))
p("For exact-config edges, a value of 0.995 instead of 1 keeps every weight strictly positive. The scenario parameter "
  "p<sub>u</sub> plays the same role as the paper’s ω: a small, non-zero chance of an unknown way in. It is the only "
  "assumed number left in the model, which is why we measure its effect in Section 7.5.")
H2("6.2 Why vulnerability counts are a poor proxy")
p("The paper’s α<sub>1</sub> adds 1 per high- or critical-severity CVE. Real exploitation data shows that severity "
  "is a weak signal: of 49,425 CVEs with CVSS 9–10, only 1.28% appear in the CISA KEV catalogue (Figure 6, left). "
  "Inside that same critical band, our model separates the CVEs strongly: the top fifth by model score has a 5.5% "
  "exploitation rate and the bottom fifth 0.01% (Figure 6, right). A count-based coefficient cannot make this "
  "distinction.")
figure(A / "fig_cvss_vs_ml.png", 16, "Left: observed exploitation rate (CISA KEV) by CVSS band. Right: within CVSS "
       "9–10, exploitation rate by quintile of the learned score.")
H2("6.3 The CVE exploitation model")
p("<b>Data.</b> 361,825 CVEs from the National Vulnerability Database [13] (via the FKIE mirror), labelled positive "
  "if listed in the CISA KEV catalogue (1,743 positives, catalogue version 2026.11.09). No synthetic data is used.")
p("<b>Features.</b> CVSS base score and vector components (attack vector, complexity, privileges, user interaction, "
  "impacts), CWE class, publication year, reference types (vendor advisory, exploit, patch), vendor and product "
  "prevalence, and keywords from the description. Permutation importance ranks vendor advisory, base score, vendor "
  "CVE volume and CWE highest.")
p("<b>Model.</b> A histogram gradient-boosting classifier (scikit-learn), which we trained ourselves and compared with "
  "a logistic regression and with CVSS score alone. To avoid leakage the evaluation is temporal: train on CVEs "
  "published up to 2023 (179,970 CVEs, 1,174 positives) and test on later CVEs (181,855 CVEs, 569 positives). A "
  "container’s exploitation probability combines its CVEs:")
equation(A / "eq7.png", 7, 1.05)
table([["Model (temporal test set)", "ROC-AUC", "PR-AUC", "Precision@100"],
       ["CVSS score only (static baseline)", "0.770", "0.012", "5%"],
       ["Logistic regression", "0.877", "0.112", "48%"],
       [ml("Gradient boosting (deployed)"), ml("0.887"), ml("0.108"), ml("54%")],
       ["Gradient boosting without the “in the wild” keyword", "0.876", "0.097", "42%"],
       ["FIRST EPSS (external reference, uses later data)", "0.975", "0.428", "89%"]],
      [8.6, 2.6, 2.6, 3.2], "Exploitation prediction on CVEs published after 2023 (base rate 0.31%).",
      align_right_cols=(1, 2, 3))
p("The learned model lifts ROC-AUC from 0.770 to 0.887 and precision among the 100 highest-ranked CVEs from 5% to "
  "54%. Removing the keyword “in the wild” from the description changes the result only slightly (0.876), so the "
  "model is not simply reading the answer from the text. EPSS remains better; it is a production system that uses "
  "exploit and telemetry data observed after publication, so it is shown only as a reference and not as a fair "
  "competitor.")
figure(A / "fig_roc_pr.png", 16, "ROC and precision–recall curves on the temporal test set; the grey line is the "
       "static CVSS baseline.")

# ════════════════════════════════════════════════════════════════════════════
# 7. Evaluation
# ════════════════════════════════════════════════════════════════════════════
H1("7. Evaluation: static coefficients versus learned weights")
H2("7.1 Experimental setup")
table([["Item", "Value"],
       ["Clusters", "Three monitored clusters we built (kav-dev, kav-staging, kav-prod), one validation cluster "
        "(kav-lab) and one public-benchmark cluster (kav-bench), all created with kind v0.33.0 [17]"],
       ["Kubernetes", "Server v1.37.0, kubectl v1.37.2, CNI kindnet (kind default)"],
       ["Workloads", "kav-dev/staging/prod: microservices (frontend, api, payments, checkout, ledger, redis, CI runner) "
        "with deliberate misconfigurations of the kinds reported in [1]. kav-bench: unmodified Kubernetes Goat [15] "
        "and Bad Pods [16] manifests"],
       ["Image scanning", "Trivy v0.76.1 [14] on every running image"],
       ["Graph size", "15–20 nodes per monitored cluster after scoping to application namespaces; kav-bench 26 nodes "
        "(full benchmark) or 12 nodes (demonstration subset)"]],
      [3.2, 13.8], "Experimental environment.", bold_cols=(0,))
H2("7.2 Validation of the edges against a live cluster")
p("The paper’s edges are not checked against a running cluster (limitation L3). We validate ours by deploying 26 "
  "scenarios on the lab cluster and comparing every predicted edge with the cluster’s own answer: the API server’s "
  "SubjectAccessReview for RBAC permissions, the presence of a mounted token, and real HTTP probes between pods for "
  "network reachability.")
table([["Check", "Checks", "Precision", "Recall", "Accuracy"],
       ["RBAC permissions (SubjectAccessReview)", "21,019", "1.000", "1.000", "1.000"],
       ["ServiceAccount token availability", "190", "1.000", "1.000", "1.000"],
       ["Network reachability, ordinary pods", "1,050", "1.000", "1.000", "1.000"],
       ["Network reachability, hostNetwork pods", "166", "0.873", "0.605", "0.669"],
       ["<b>Overall</b>", "<b>22,425</b>", "<b>0.996</b>", "<b>0.982</b>", "<b>0.9975</b>"]],
      [7.4, 2.2, 2.4, 2.4, 2.6], "Predicted edges compared with ground truth from a live cluster.",
      align_right_cols=(1, 2, 3, 4))
p("All RBAC, token and ordinary network edges are exact. The 55 disagreements all involve pods using the host "
  "network, whose traffic Kubernetes NetworkPolicy semantics do not cover consistently across network plugins; we "
  "report this as a known limitation rather than tuning it away.")

# ── 7.3 benchmark ───────────────────────────────────────────────────────────
H2("7.3 Public benchmark: Kubernetes Goat and Bad Pods")
p("Section 7.2 checks single edges. To check whole attack paths we need an answer key, and on clusters we built "
  "ourselves we would also be writing that answer key. We therefore use two public projects whose authors already "
  "documented which attacks work: Kubernetes Goat [15] and Bad Pods [16]. Their manifests are deployed "
  "<b>unmodified</b> on the kav-bench cluster, with two mechanical exceptions: the one Goat component that upstream "
  "installs with Helm is rendered from its chart’s default values, and the Bad Pods, which have no namespace, are "
  "applied in a namespace of their own.")
p("<b>Answer key.</b> From Kubernetes Goat we take the seven scenarios whose attack follows from cluster configuration "
  "(2, 3, 4, 8, 11, 12, 16). The others concern image contents, CIS or runtime tools, denial of service or a "
  "deprecated Helm v2 component and are out of scope for a configuration graph. From Bad Pods we take all eight "
  "pods; the documentation of each states whether that pod’s specification alone gives root on its node (four yes, "
  "four no). Every entry of the answer key links to the page where it is documented (Table 15).")
p("<b>Procedure.</b> The tool scans the live cluster once and builds the graph under both weightings. For each "
  "documented attack it reports whether the path is in the graph and its rank among all attack paths of the cluster. "
  "Following Kubernetes Goat’s premise that any application may be compromised, entry points are the internet, users "
  f"and every pod, which gives {BS['learned']['paths_ranked']} entry-to-target paths. Risks are compared at the two "
  "decimals shown, so equal risks share a rank. For Bad Pods we ask whether each weighting claims an escape on the "
  "direct pod → node step: the static weights have no probability, so any modelled step counts as a claim, while the "
  "learned weights claim an escape when P ≥ 0.5.")

goat_rows = [["Goat scenario", "Documented attack", "Found", "Old rank", "ML rank", "ML P(path)"]]
for gid in ("goat-2", "goat-3", "goat-4", "goat-8", "goat-11", "goat-12", "goat-16"):
    it = B[gid]
    o, l = it["modes"]["static"], it["modes"]["learned"]
    rk = lambda m: (f"#{m['rank']}" if m["rank"] else "reachable") if m["found"] else "not found"
    goat_rows.append([f"#{gid.split('-')[1]} {it['title']}", it["documented"],
                      ok("yes") if l["found"] else bad("no"), rk(o), ml(rk(l)) if l["rank"] else rk(l),
                      f"{l['probability'] * 100:.1f}%" if l["probability"] is not None else "—"])
table(goat_rows, [3.7, 6.0, 1.3, 1.9, 1.9, 2.2],
      f"Kubernetes Goat: documented attacks found and their rank among {BS['learned']['paths_ranked']} paths (lower is "
      "more dangerous). “reachable”: the target is a workload, not a secret or node, so the path is checked but not "
      "ranked.", align_right_cols=(3, 4, 5))

bp_rows = [["Bad Pod", "Documented outcome", "Expected", "Old weights say", "ML weights say", "ML P"]]
for i in range(1, 9):
    it = B[f"badpod-{i}"]
    o, l = it["modes"]["static"], it["modes"]["learned"]
    exp = it["expect"] == "reachable"
    v = lambda m: (ok if m["claims_escape"] == exp else bad)("escape" if m["claims_escape"] else "no escape")
    bp_rows.append([it["title"], it["documented"], "escape" if exp else "no escape", v(o), v(l),
                    f"{(l['escape_score'] or 0) * 100:.1f}%"])
table(bp_rows, [3.5, 5.6, 1.9, 2.2, 2.2, 1.6],
      "Bad Pods: can the pod’s own specification reach its node? Green: agrees with the documentation; red: disagrees.",
      align_right_cols=(5,))
figure(A / "fig_benchmark.png", 16.5, "Left: rank of each ranked Kubernetes Goat attack under old and ML weights. "
       "Right: agreement with the 15 documented answers, and the share of (real escape, non-escape) Bad Pod pairs "
       "that each weighting orders correctly; the dashed line is chance (50%).")
table([["Measure", "Old weights (paper-style)", "ML weights"],
       ["Kubernetes Goat attacks found (recall)", f"{BS['static']['goat_found']}/7", ml(f"{BS['learned']['goat_found']}/7")],
       [f"Mean rank of documented Goat attacks (of {BS['learned']['paths_ranked']})", f"{BS['static']['goat_mean_rank']}",
        ml(f"{BS['learned']['goat_mean_rank']}")],
       ["Bad Pods verdicts that match the documentation", f"{BS['static']['badpods_correct']}/8",
        ml(f"{BS['learned']['badpods_correct']}/8")],
       ["Real escapes ranked above non-escapes", f"{BS['static']['badpods_pairwise'] * 100:.0f}%",
        ml(f"{BS['learned']['badpods_pairwise'] * 100:.0f}%")],
       ["<b>All documented answers matched</b>", f"<b>{BS['static']['goat_found'] + BS['static']['badpods_correct']}/15</b>",
        ml(f"{BS['learned']['goat_found'] + BS['learned']['badpods_correct']}/15")]],
      [8.6, 4.4, 4.0], "Benchmark summary (full benchmark, Trivy image scanning on).", align_right_cols=(1, 2))
p("<b>Reading the results.</b> Both weightings find every documented Kubernetes Goat attack. This is expected: "
  "weights change the order of paths, not which edges exist, so recall is a property of the feasibility engine. The "
  "difference is the ranking. The learned weights put three of the four ranked attacks first and the fourth (reading "
  "secrets through the hunger-check ServiceAccount) seventh; the static weights place them 1st, 20th, 20th and 29th. "
  "The seventh place is itself informative: the Goat images contain CVEs listed in the CISA KEV catalogue, so the "
  "learned model also ranks many “compromise system-monitor through a known-exploited CVE” paths near the top with "
  "almost the same probability.")
p("On Bad Pods the static weights cannot tell host settings apart: every pod with any host-level setting gets the "
  "same pod → node edge, so hostPID, hostNetwork and hostIPC are all reported as escapes, against the documentation. "
  "The learned weights treat privileged pods as configuration-decided (P = 0.995) and the other settings as "
  "uncertain (P = 0.05), which matches Bad Pods for seven of eight pods. The one disagreement is <b>hostPath</b>: Bad "
  "Pods documents that mounting the host’s root directory gives read/write access to the node, but our model treats "
  "every hostPath mount as uncertain, because many hostPath mounts are read-only or harmless directories. Treating "
  "writable mounts of sensitive host paths as configuration-decided is the obvious fix; we report the miss rather "
  "than adjusting the model after seeing the answer key.")
p("<b>Demonstration subset.</b> For the live demonstration (Section 8) kav-bench runs a 12-node subset: three Goat "
  "applications and two Bad Pods (privileged, hostPID). On it the learned weights match 6 of 6 documented answers "
  "and the static weights 5 of 6, but the subset contains no hostPath pod, so the numbers reported in this section "
  "are those of the full benchmark.")
src_rows = [["Entry", "Documented at"]]
for gid in ("goat-2", "goat-3", "goat-4", "goat-8", "goat-11", "goat-12", "goat-16"):
    src_rows.append([f"Goat #{gid.split('-')[1]}", f'<font size="8.3">{B[gid]["doc"]}</font>'])
for i in range(1, 9):
    src_rows.append([f"Bad Pod #{i}", f'<font size="8.3">{B[f"badpod-{i}"]["doc"]}</font>'])
table(src_rows, [2.4, 14.6], "Sources of the answer key; each page states the attack used as the expected answer.")

# ── 7.4 live clusters ───────────────────────────────────────────────────────
H2("7.4 Before and after on three live clusters")
p("Both weightings were run on the same graphs of our three monitored clusters. Table 16 compares the paths found "
  "and their ordering; Figure 9 shows the severity labels assigned under each model.")
table([["Cluster", "Nodes / edges", "Paths", "Severity, static (before)", "Severity, learned (after)", "Rank corr. ρ"],
       ["kav-dev", "20 / 51", "16", "13 high, 3 medium", "16 critical", "0.71"],
       ["kav-staging", "19 / 38", "11", "8 high, 3 medium", "8 critical, 3 medium", "0.84"],
       ["kav-prod", "19 / 28", "19", "5 high, 14 medium", "4 critical, 8 medium, 7 low", "0.57"]],
      [2.3, 2.4, 1.3, 3.7, 4.6, 2.7], "Static versus learned weighting on the live clusters (ρ = Spearman rank "
      "correlation of path risks, measured on 12 November 2026 with Trivy image scanning).", align_right_cols=(2, 5))
figure(A / "fig_sev.png", 15, "Severity of the attack paths before (static coefficients) and after (learned "
       "weights). “mock” is the sample cluster shipped with the tool.")
p("The orderings differ where it matters; the rank correlation between the two models is lowest in kav-prod (0.57). "
  "Table 17 lists the two top-ranked paths of each cluster. With static coefficients, the short path ci-runner → "
  "registry-token is first everywhere because it has only one edge. With learned weights, the first path in kav-dev "
  "is dev-bob → platform-admins → cluster-admin: every step is a verified RBAC grant, so the path succeeds with "
  "probability 0.99 and leads to full cluster control. In kav-prod, the learned model promotes the break-glass role "
  "of sre-carol, which reaches ledger and payment credentials with probability 0.985, while the static model ranks "
  "the network chain ci-runner → frontend → api → session-key second even though its pod-to-pod exploitation steps "
  "have a low measured probability.")
table([["Cluster", "Top paths — static (risk)", "Top paths — learned (P of success)"],
       ["kav-dev", "ci-runner → registry-token (6.67)<br/>dev-bob → platform-admins → cluster-admin (5.88)",
        "dev-bob → platform-admins → cluster-admin (0.990)<br/>ci-runner → ci-runner → platform-admins → "
        "cluster-admin (0.985)"],
       ["kav-staging", "ci-runner → registry-token (6.67)<br/>ci-runner → api → session-key (5.81)",
        "ci-runner → registry-token (0.995)<br/>qa-alice → qa-alice-edit → session-key (0.990)"],
       ["kav-prod", "ci-runner → registry-token (6.67)<br/>ci-runner → frontend → api → session-key (5.14)",
        "ci-runner → registry-token (0.995)<br/>sre-carol → sre-carol-breakglass → ledger → ledger-creds (0.985)"]],
      [2.4, 6.8, 7.8], "Two highest-ranked paths per cluster under each weighting.", bold_cols=(0,))
p("<b>Severity becomes interpretable.</b> Under static coefficients, risk is a ratio of hand-chosen numbers and the "
  "HIGH/MEDIUM labels have no external meaning. Under learned weights, a CRITICAL path is one that reaches a "
  "high-impact target with a high, evidence-backed probability of success. In kav-prod, which has network policies "
  "and hardened pods, the learned model labels seven paths LOW because they depend on exploiting workloads whose "
  "images have a low measured exploitation probability; the static model could not distinguish these from "
  "configuration-guaranteed paths.")
p("<b>The same graph, two orderings.</b> Figure 10 draws the 41-node sample cluster shipped with the tool under both "
  "weightings with one layout, highlighting each weighting’s four highest-ranked paths. The static weights favour a "
  "chain through sa-worker → pod-exec → worker-node-1; under learned weights that chain drops out of the top four "
  "(the former first path falls to 15th, P = 0.7%) and the credential chain from cicd-bot to production-db, "
  "previously fourth, becomes first with P = 52.4%.")
figure_pair(A / "sample_static.png", A / "sample_learned.png", 17,
            "The sample cluster under (a) static coefficients and (b) learned weights, drawn with one layout; each "
            "panel highlights its four highest-ranked paths (#1 red, #2 orange, #3 purple, #4 green).")
figure(A / "fig_devgraph.png", 14.5, "Live kav-dev attack graph (20 nodes). The highlighted path is the most likely "
       "one under learned weights (P = 0.99).", max_h_cm=10)

# ── 7.5 sensitivity ─────────────────────────────────────────────────────────
H2("7.5 Sensitivity analysis")
p("The paper evaluates one coefficient setting (limitation L1). Our model has one assumed parameter, p<sub>u</sub>. "
  "We varied it from 0.01 to 0.5 and measured the Kendall rank correlation τ of the path ordering against the default "
  "(p<sub>u</sub> = 0.05).")
table([["p<sub>u</sub>", "kav-dev τ", "kav-staging τ", "kav-prod τ", "Top path unchanged"],
       ["0.01", "1.000", "1.000", "1.000", "yes"], ["0.02", "1.000", "1.000", "1.000", "yes"],
       ["0.05 (default)", "1.000", "1.000", "1.000", "yes"], ["0.10", "1.000", "1.000", "1.000", "yes"],
       ["0.20", "1.000", "1.000", "1.000", "yes"], ["0.30", "1.000", "1.000", "1.000", "yes"],
       ["0.50", "0.962", "0.990", "1.000", "yes"]],
      [3.4, 3.0, 3.0, 3.0, 4.6], "Kendall τ of path rankings against the default p<sub>u</sub> = 0.05.",
      align_right_cols=(1, 2, 3))
p("The ranking is identical (τ = 1) for every p<sub>u</sub> up to 0.3, and the most dangerous path never changes. "
  "Only at p<sub>u</sub> = 0.5, which assumes that half of all unpatched-looking services are exploitable, do a few "
  "lower-ranked paths swap. The conclusions therefore rest on measured evidence rather than on the assumed parameter.")

# ── 7.6 drift ───────────────────────────────────────────────────────────────
H2("7.6 Real-time detection of a misconfiguration")
p("The paper analyses Charts once, before deployment (limitation L5). KubeAttackViz rescans each monitored cluster "
  "every 15 seconds, recomputes the graph with both weightings and compares it with the previous snapshot. To test "
  "this end to end we introduced a realistic misconfiguration into the hardened kav-prod cluster while it was being "
  "monitored: a ClusterRoleBinding giving the ServiceAccount of the shop/frontend pod the cluster-admin role. We then "
  "removed it again.")
table([["Step", "Observation"],
       ["Binding created", "Detected after 16 s (one 15 s scan interval). The graph grew from 19 to 21 attack paths and "
        "the monitor raised CRITICAL alerts such as “New attack path: ci-runner → … → cluster-admin”."],
       ["New path, static weights", "ci-runner → ci-runner-deploys-shop → frontend → kav-drift-frontend-admin → "
        "cluster-admin ranked " + bad("#17, MEDIUM") + " (risk 3.85)."],
       ["New path, learned weights", "The same path ranked " + ok("#1, CRITICAL") + " (P = 0.975): every step is a "
        "verified RBAC grant or token mount."],
       ["Binding removed", "Detected after 12 s; the graph returned to its previous 19 paths."]],
      [4.2, 12.8], "Runtime drift experiment on kav-prod.", bold_cols=(0,))
p("Granting cluster-admin to a workload identity is among the most serious Kubernetes misconfigurations, yet the "
  "static weights rank the resulting path in the lower half of the list because it is long. The learned weights rank "
  "it first because each of its steps is decided by the configuration. This addresses the paper’s CI/CD future-work "
  "direction from the runtime side.")

# ════════════════════════════════════════════════════════════════════════════
# 8. Demonstration
# ════════════════════════════════════════════════════════════════════════════
H1("8. Demonstration")
p("All experiments in Section 7 can be repeated live from one command, ./demo/present.sh. It shows one menu: the "
  "clusters with their posture at the top (switched with s and a–d), and five actions below. All of them only read "
  "from the clusters.")
table([["Action", "What it shows"],
       ["1 Show pods", "The workloads, their status, ServiceAccount and image"],
       ["2 Show RBAC &amp; NetworkPolicies", "Who can do what, and whether pods are isolated on the network"],
       ["3 Live monitor + dashboard", "Continuous scanning with alerts, and the interactive graph in the browser"],
       ["4 Old vs ML weights", "Four dashboard views — the sample cluster and the selected live cluster, each under "
        "static and learned weights — with one layout per cluster, the four highest-ranked paths in colour and each "
        "path tagged with its rank under the other weighting"],
       ["5 Benchmark", "The comparison of Section 7.3 against Kubernetes Goat and Bad Pods, with the link to every "
        "documented answer"]],
      [4.6, 12.4], "The demonstration menu.", bold_cols=(0,))
figure(A / "screen_bench_ml.png", 16.5, "Dashboard view 4 (live kav-bench cluster, learned weights). Each path card "
       "and the panel at the bottom state the rank the path had under static weights. Only edges that lie on attack "
       "paths, plus the closest others, are drawn for readability; the analysis uses every edge, and a switch on the "
       "left shows them all.")

# ════════════════════════════════════════════════════════════════════════════
# 9. Discussion
# ════════════════════════════════════════════════════════════════════════════
H1("9. Discussion")
H2("9.1 Relationship to the paper")
p("The research contribution, the graph formulation and the log-probability path search come from Blaise and "
  "Rebecchi [1]. Our work keeps that formulation and changes the source of the numbers. Configuration-decidable steps "
  "are proven from the live cluster rather than scored, and the vulnerability step uses a probability learned from "
  "public exploitation data rather than a count of severe CVEs. Table 21 summarises the comparison.")
table([["Aspect", "Stay at the Helm [1]", "KubeAttackViz, static (v1)", "KubeAttackViz, learned (this work)"],
       ["Input", "Helm Charts", "Live cluster / JSON", "Live clusters, monitored continuously"],
       ["Edge weights", "Predefined γ coefficients", "Predefined costs per relation", "−ln P(e), proven or learned"],
       ["Vulnerabilities", "Count of CVSS &gt; 7 CVEs (α<sub>1</sub>)", "Not used",
        "Exploitation probability from NVD + CISA KEV"],
       ["Pod security", "Pod Security Policies", "Pod flags", "Pod Security Standards (baseline)"],
       ["Path search", "Dijkstra on log(1/z)", "Dijkstra on effort", "Dijkstra on −ln P"],
       ["Edge validation", "Statistics over 592 Charts", "Sample data", "22,425 checks on a live cluster"],
       ["External answer key", "None", "12/15 documented answers", "14/15 documented answers"],
       ["Sensitivity analysis", "None", "None", "p<sub>u</sub> from 0.01 to 0.5"],
       ["Scale of evaluation", "1,318 containers", "Demo clusters", "Three clusters of 15–20 nodes + public benchmark"]],
      [3.3, 4.2, 4.2, 5.3], "Comparison of the reference paper with both versions of our implementation.",
      bold_cols=(0,))
H2("9.2 Threats to validity")
bullets([
    "<b>Scale.</b> The paper evaluates 592 Charts; our live comparison uses three small clusters that we built and a "
    "public benchmark of 15 documented cases. The results show how the weighting changes rankings and that it agrees "
    "better with an external answer key, not how frequent each misconfiguration is in practice.",
    "<b>Answer key.</b> Kubernetes Goat and Bad Pods document the attacks they were designed for. Paths our tool finds "
    "beyond those are not necessarily wrong, so we report recall and rank rather than precision. Ranking the "
    "documented attacks highly is a reasonable but not a neutral criterion: it assumes the documented attacks are "
    "among the most dangerous in their cluster.",
    "<b>hostPath.</b> The learned model rates every hostPath mount as uncertain (P = 0.05), which disagrees with Bad Pods "
    "for a writable mount of the host root (Section 7.3).",
    "<b>Label noise.</b> CISA KEV lists confirmed exploitation only; many exploited CVEs are never listed, so absolute "
    "probabilities are conservative. Ranking metrics are less affected than calibration.",
    "<b>Independence.</b> Multiplying edge probabilities assumes independent steps, as in the paper. Correlated steps "
    "(for example, the same stolen token used twice) are approximated.",
    "<b>Host networking.</b> Reachability for hostNetwork pods is not modelled exactly (Section 7.2).",
])

# ════════════════════════════════════════════════════════════════════════════
# 10. Conclusion
# ════════════════════════════════════════════════════════════════════════════
H1("10. Conclusion and future work")
p("Blaise and Rebecchi show that Kubernetes configuration security is better understood as a connected graph of "
  "resources, permissions and movement opportunities than as a list of isolated checks, and that paths can be found "
  "with Dijkstra after a log transformation of edge probabilities [1]. Their probabilities, like the weights in our "
  "first implementation, are predefined coefficients.")
p("This work keeps the paper’s formulation and replaces those coefficients with evidence. Steps decided by the "
  "configuration are verified against the live cluster (all 21,019 RBAC checks correct), and the vulnerability step "
  "uses a model trained on 361,825 real CVEs that improves on CVSS alone from 0.770 to 0.887 ROC-AUC and from 5% to "
  "54% precision in the top 100. On attack paths documented by Kubernetes Goat and Bad Pods, which we did not write, "
  f"the learned weights match {BS['learned']['goat_found'] + BS['learned']['badpods_correct']} of 15 documented "
  f"answers against {BS['static']['goat_found'] + BS['static']['badpods_correct']} and rank the documented Goat "
  f"attacks at a mean position of {BS['learned']['goat_mean_rank']} instead of {BS['static']['goat_mean_rank']}. On "
  "three live clusters they reorder the attack paths (rank correlation 0.57–0.84 with the static model), promote "
  "configuration-guaranteed paths to cluster-admin and production secrets, and demote paths that rely on unlikely "
  "exploits; a cluster-admin misconfiguration introduced at runtime is detected within one scan interval and ranked "
  "first only by the learned weights. The only remaining assumed parameter does not change the rankings for any "
  "value up to 0.3.")
p("<b>Future work.</b> (i) Treat writable hostPath mounts of sensitive host directories as configuration-decided, "
  "the one disagreement with the benchmark; (ii) parse Helm Charts directly (through helm template) so that the "
  "paper’s 592-Chart dataset can be re-evaluated with learned weights; (iii) model the paper’s per-tactic sub-scores "
  "with tactic-specific probabilities; (iv) handle hostNetwork reachability per network plugin; (v) integrate the "
  "analysis as an admission or CI/CD gate, as proposed in [1].")

# ════════════════════════════════════════════════════════════════════════════
# References
# ════════════════════════════════════════════════════════════════════════════
H1("References")
refs = [
    "A. Blaise and F. Rebecchi, “Stay at the Helm: secure Kubernetes deployments via graph generation and attack "
    "reconstruction,” in <i>Proc. 2022 IEEE 15th Int. Conf. on Cloud Computing (CLOUD)</i>, Barcelona, Spain, 2022, "
    "pp. 59–69, doi: 10.1109/CLOUD55607.2022.00022.",
    "BugBuster18, “Kuber_h2f: KubeAttackViz — Kubernetes attack path visualizer,” GitHub repository, 2026. "
    "https://github.com/BugBuster18/Kuber_h2f",
    "Microsoft, “Threat matrix for Kubernetes,” Microsoft Security Blog, Apr. 2020. "
    "https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/",
    "The MITRE Corporation, “MITRE ATT&amp;CK.” https://attack.mitre.org/",
    "Center for Internet Security, “CIS Kubernetes Benchmark.” https://www.cisecurity.org/benchmark/kubernetes",
    "The Kubernetes Authors, “Using RBAC authorization,” Kubernetes documentation. "
    "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
    "The Kubernetes Authors, “Pod Security Standards,” Kubernetes documentation. "
    "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
    "O. Sheyner, J. Haines, S. Jha, R. Lippmann and J. M. Wing, “Automated generation and analysis of attack graphs,” "
    "in <i>Proc. IEEE Symp. on Security and Privacy</i>, 2002, pp. 273–284.",
    "X. Ou, S. Govindavajhala and A. W. Appel, “MulVAL: a logic-based network security analyzer,” in <i>Proc. 14th "
    "USENIX Security Symp.</i>, 2005.",
    "FIRST, “Common Vulnerability Scoring System v3.1: specification document.” https://www.first.org/cvss/",
    "J. Jacobs, S. Romanosky, B. Edwards, I. Adjerid and M. Roytman, “Exploit Prediction Scoring System (EPSS),” "
    "<i>Digital Threats: Research and Practice</i>, vol. 2, no. 3, 2021.",
    "Cybersecurity and Infrastructure Security Agency, “Known Exploited Vulnerabilities catalog.” "
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "NIST, “National Vulnerability Database.” https://nvd.nist.gov/",
    "Aqua Security, “Trivy: vulnerability scanner for containers.” https://github.com/aquasecurity/trivy",
    "M. Akula, “Kubernetes Goat: interactive Kubernetes security learning playground,” GitHub repository (MIT "
    "licence), commit 723a0db, 2026. https://github.com/madhuakula/kubernetes-goat",
    "Bishop Fox, “Bad Pods: Kubernetes pod privilege escalation,” GitHub repository (MIT licence), commit 107e5d8, "
    "2025. https://github.com/BishopFox/badPods",
    "The Kubernetes Authors, “kind: Kubernetes IN Docker.” https://kind.sigs.k8s.io/",
]
for i, r in enumerate(refs, 1):
    story.append(Paragraph(f"[{i}]&nbsp;&nbsp;{r}", ref))

doc.multiBuild(story)
print("wrote", OUT)
