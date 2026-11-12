"""Presentation / live-demo plan for KubeAttackViz (Group 39).

    python docs/demo_plan/build_demo_plan.py   ->  docs/Demo_Plan_Grp39.pdf
"""
import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "docs/case_study/assets"
OUT = ROOT / "docs/Demo_Plan_Grp39.pdf"
RES = json.loads((ROOT / "demo/benchmark/results-full.json").read_text())["summary"]

for name, f in (("Serif", "liberation-serif-fonts/LiberationSerif-Regular.ttf"),
                ("Serif-B", "liberation-serif-fonts/LiberationSerif-Bold.ttf"),
                ("Serif-I", "liberation-serif-fonts/LiberationSerif-Italic.ttf"),
                ("Sans", "liberation-sans-fonts/LiberationSans-Regular.ttf"),
                ("Sans-B", "liberation-sans-fonts/LiberationSans-Bold.ttf"),
                ("Mono", "liberation-mono-fonts/LiberationMono-Regular.ttf"),
                ("Mono-B", "liberation-mono-fonts/LiberationMono-Bold.ttf"),
                ("Sym", "dejavu-sans-fonts/DejaVuSans.ttf")):
    pdfmetrics.registerFont(TTFont(name, f"/usr/share/fonts/{f}"))
pdfmetrics.registerFontFamily("Serif", normal="Serif", bold="Serif-B", italic="Serif-I", boldItalic="Serif-B")
pdfmetrics.registerFontFamily("Sans", normal="Sans", bold="Sans-B", italic="Sans", boldItalic="Sans-B")
pdfmetrics.registerFontFamily("Mono", normal="Mono", bold="Mono-B", italic="Mono", boldItalic="Mono-B")

INK, MUTED, ACC, ML, OLD = (colors.HexColor(c) for c in ("#1c2333", "#5b6577", "#7048E8", "#2255cc", "#8e99ab"))
LINE, SHADE, SAY_BG, CMD_BG = (colors.HexColor(c) for c in ("#d5dae3", "#f2f4f8", "#f3effe", "#eef1f6"))

body = ParagraphStyle("body", fontName="Serif", fontSize=10.5, leading=14.2, textColor=INK, spaceAfter=5)
small = ParagraphStyle("small", parent=body, fontSize=9, leading=11.6, spaceAfter=0)
cell = ParagraphStyle("cell", parent=body, fontName="Sans", fontSize=8.6, leading=11, spaceAfter=0)
cellb = ParagraphStyle("cellb", parent=cell, fontName="Sans-B")
h1 = ParagraphStyle("h1", fontName="Sans-B", fontSize=14.5, leading=18, textColor=INK, spaceBefore=10, spaceAfter=6, keepWithNext=1)
h2 = ParagraphStyle("h2", fontName="Sans-B", fontSize=11.5, leading=14.5, textColor=ACC, spaceBefore=8, spaceAfter=4, keepWithNext=1)
cmd = ParagraphStyle("cmd", fontName="Mono", fontSize=8.8, leading=11.6, textColor=INK, spaceAfter=0)
say = ParagraphStyle("say", parent=body, fontName="Serif-I", fontSize=10.2, leading=13.6, spaceAfter=0)
cap = ParagraphStyle("cap", parent=small, fontName="Sans", textColor=MUTED, alignment=TA_CENTER, spaceBefore=3,
                     spaceAfter=8)
title = ParagraphStyle("title", fontName="Sans-B", fontSize=22, leading=27, textColor=INK, alignment=TA_CENTER)
sub = ParagraphStyle("sub", parent=body, fontName="Sans", alignment=TA_CENTER, textColor=MUTED, fontSize=11)

S = []
P = lambda t, st=body: S.append(Paragraph(t, st))


def box(flow, bg, border):
    t = Table([[flow]], colWidths=[16.4 * cm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("LINEBEFORE", (0, 0), (0, -1), 3, border),
                           ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return t


def code(*lines):
    S.append(box(Paragraph("<br/>".join(l.replace(" ", "&nbsp;") for l in lines), cmd), CMD_BG, MUTED))
    S.append(Spacer(1, 6))


def speak(text):
    S.append(box(Paragraph("<b>Say:</b> " + text, say), SAY_BG, ACC))
    S.append(Spacer(1, 6))


def table(rows, widths, head=True, zebra=True):
    data = [[Paragraph(str(c), cellb if (head and r == 0) else cell) for c in row] for r, row in enumerate(rows)]
    t = Table(data, colWidths=[w * cm for w in widths], repeatRows=1 if head else 0)
    st = [("GRID", (0, 0), (-1, -1), 0.5, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
          ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5)]
    if head:
        st.append(("BACKGROUND", (0, 0), (-1, 0), SHADE))
    if zebra:
        st += [("BACKGROUND", (0, r), (-1, r), colors.HexColor("#fafbfd")) for r in range(2, len(rows), 2)]
    t.setStyle(TableStyle(st))
    S.append(t)
    S.append(Spacer(1, 8))


def figure(name, width_cm, text):
    from reportlab.lib.utils import ImageReader
    w, h = ImageReader(str(ASSETS / name)).getSize()
    S.append(KeepTogether([Image(str(ASSETS / name), width=width_cm * cm, height=width_cm * cm * h / w),
                           Paragraph(text, cap)]))


def step(num, mins, heading):
    S.append(Paragraph(f'<font color="#7048E8">Step {num}</font> · {heading} '
                       f'<font name="Sans" size="9.5" color="#5b6577">({mins})</font>', h2))


st, lr = RES["static"], RES["learned"]
n_total = st["goat_total"] + st["badpods_total"]
match_old, match_ml = st["goat_found"] + st["badpods_correct"], lr["goat_found"] + lr["badpods_correct"]

# ---------------------------------------------------------------- title
S += [Spacer(1, 3.2 * cm), Paragraph("KubeAttackViz", title), Spacer(1, 4),
      Paragraph("Presentation &amp; Live-Demonstration Plan", ParagraphStyle("t2", parent=title, fontSize=15,
                                                                             leading=20, textColor=ACC)),
      Spacer(1, 18),
      Paragraph("Kubernetes attack paths with ML-learned edge weights, validated against "
                "Kubernetes Goat and Bad Pods", sub), Spacer(1, 1.6 * cm)]
team = [["Team (Group 39)", "Roll no."], ["Ganesh Daware", "23BCS038"], ["Gagan Rathod", "23BCS106"],
        ["Venkatesh Dhangar", "23BCS041"], ["Advait Pathak", "23BCS094"]]
tt = Table([[Paragraph(c, cellb if r == 0 else cell) for c in row] for r, row in enumerate(team)],
           colWidths=[6 * cm, 3.5 * cm], hAlign="CENTER")
tt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, LINE), ("BACKGROUND", (0, 0), (-1, 0), SHADE),
                        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
S += [tt, Spacer(1, 1.2 * cm), Paragraph("Course instructor: Dr. Malay Kumar · IIIT Dharwad", sub),
      Spacer(1, 2.2 * cm),
      box(Paragraph("<b>One command runs the whole demo:</b> <font name='Mono'>./demo/present.sh</font>. "
                    "One menu, five options, <font name='Mono'>s</font> then <font name='Mono'>a–d</font> "
                    "switches cluster. Planned length about 15 minutes plus questions.", small), SAY_BG, ACC),
      PageBreak()]

# ---------------------------------------------------------------- 1. story
P("1. The story in one minute", h1)
P("The base paper (<i>Stay at the Helm</i>) builds a Kubernetes attack graph and ranks attack paths using "
  "<b>hand-set edge costs</b>. Those costs are assumptions: every privileged-looking edge costs roughly the "
  "same, whatever the evidence behind it. Our project keeps the paper's graph and replaces the costs with "
  "<b>learned success probabilities</b>:")
table([["", "Before (paper-style, “old weights”)", "After (our work, “ML weights”)"],
       ["Edge weight", "hand-set cost C", "w = −ln P(success)"],
       ["Path score", "risk = impact / (1 + C/10)", "risk = impact × P(path),  P(path) = exp(−Σw)"],
       ["Where P comes from", "—", "exact config (0.995) · CVE model · scenario parameter (0.05)"],
       ["CVE model", "—", "gradient boosting on 361,825 NVD CVEs, CISA KEV labels; ROC-AUC 0.887 vs CVSS 0.770"]],
      [3.2, 5.6, 7.6])
P("Then we check the result against an answer key we did not write: the attacks that <b>Kubernetes Goat</b> "
  "and <b>Bad Pods</b> document for their own unmodified manifests. Finally we show it working in "
  "<b>real time</b>: a misconfiguration made in a running cluster is found and ranked within seconds.")
P("Headline numbers to remember", h2)
table([["Result", "Old weights", "ML weights"],
       [f"Documented answers matched ({n_total} cases, full benchmark)", f"{match_old}/{n_total}",
        f"<b>{match_ml}/{n_total}</b>"],
       ["Mean rank of the 4 ranked Goat attacks (of 80 paths)", f"#{st['goat_mean_rank']}",
        f"<b>#{lr['goat_mean_rank']}</b>"],
       ["Bad Pods verdict correct", f"{st['badpods_correct']}/8", f"<b>{lr['badpods_correct']}/8</b>"],
       ["Real escapes ranked above non-escapes", f"{st['badpods_pairwise'] * 100:.0f}%",
        f"<b>{lr['badpods_pairwise'] * 100:.0f}%</b>"],
       ["Drift test (prod): new cluster-admin path", "#17, MEDIUM", "<b>#1, CRITICAL (P = 0.975)</b>"],
       ["Time to detect the drift / the revert", "16 s / 12 s", "16 s / 12 s"]],
      [9.4, 3.3, 3.7])

# ---------------------------------------------------------------- 2. timeline
P("2. Timeline and who speaks", h1)
P("Suggested split; swap names as you like. Each speaker drives the keyboard for their own part.", small)
S.append(Spacer(1, 4))
table([["Time", "Part", "Screen", "Speaker"],
       ["0:00–1:30", "Problem and base paper: assumed weights", "slide / case study Fig. 1", "Ganesh"],
       ["1:30–3:00", "What we changed: w = −ln P, CVE model", "case study §4", "Gagan"],
       ["3:00–4:30", "Step 1–2: the benchmark cluster, pods and RBAC", "terminal: present.sh 1, 2", "Venkatesh"],
       ["4:30–8:00", "Step 3: four dashboard views, old vs ML", "terminal + browser: option 4", "Gagan"],
       ["8:00–10:00", "Step 4: benchmark against Goat / Bad Pods", "terminal: option 5", "Advait"],
       ["10:00–13:30", "Step 5: real-time drift on prod", "two terminals + browser", "Venkatesh"],
       ["13:30–15:00", "Limitations, conclusion", "paper Tables V–VI", "Advait"],
       ["15:00–", "Questions (see §5)", "—", "all"]],
      [2.2, 6.4, 4.8, 3.0])

# ---------------------------------------------------------------- 3. before class
P("3. Before the professor arrives (30 minutes earlier)", h1)
P("Do these on the laptop that will be presented. Everything is local (kind clusters in Docker); "
  "no internet is needed during the demo except to open the Goat / Bad Pods links.")
code("cd ~/Desktop/7sem/cloud/Kuber_h2f",
     "export PATH=\"$HOME/.local/bin:$PATH\"  # kind lives here",
     "docker ps                     # Docker must be running",
     "kind get clusters             # expect kav-bench, kav-dev, kav-prod, kav-staging",
     "./demo/setup.sh bench         # only if kav-bench is missing (1-2 min)",
     "./demo/setup.sh prod          # only if kav-prod is missing",
     "./demo/stop.sh                # stop any old dashboard server",
     "python main.py run-tests      # optional: 31 tests should pass")
table([["Check", "Why"],
       ["Close other Chrome windows; zoom browser to 100%", "the dashboard opens in a new window"],
       ["Terminal font large (Ctrl + = a few times), window at least 120 columns", "benchmark tables are wide"],
       ["Open a second terminal tab in the same folder", "used only for the drift command in Step 5"],
       ["Revert any old drift: <font name='Mono'>./demo/drift.sh prod admin-sa revert</font>",
        "prod must start clean, or the drift has nothing to show"],
       ["Have docs/Case_Study_Grp39_Final.pdf and the IEEE paper open", "backup if anything fails"]],
      [8.6, 7.8])

# ---------------------------------------------------------------- 4. run sheet
P("4. Run sheet: exactly what to press", h1)
P("Start once; everything below happens inside this one menu.")
code("./demo/present.sh")
P("The menu shows the cluster table on top (<font name='Sym'>▶</font> marks the current one) and five actions. "
  "Clusters: <b>a</b> = kav-bench, <b>b</b> = kav-dev, <b>c</b> = kav-staging, <b>d</b> = kav-prod. "
  "The menu starts on <b>a (bench)</b>.")

step(1, "about 1 min", "Show the benchmark cluster: press <font name='Mono'>1</font>")
P("Lists the pods. They come from Kubernetes Goat (system-monitor, hunger-check, internal-proxy) and "
  "Bad Pods (priv, hostpid), applied <b>unmodified</b> from the upstream repositories.")
speak("This cluster is not ours. These are public, intentionally vulnerable workloads whose authors "
      "already documented the attacks. That gives us an answer key we cannot tune.")

step(2, "about 1 min", "Who can do what: press <font name='Mono'>2</font>")
P("RoleBindings per namespace and the NetworkPolicies (none here, so every pod can reach every pod). "
  "Point at one binding that later appears in an attack path.")

step(3, "about 3.5 min", "Old vs ML weights, four views: press <font name='Mono'>4</font>")
P("Starts the dashboard and opens Chrome. A small second menu appears in the terminal; each key changes "
  "the browser within a second. Old and ML views of the same cluster keep every node in the same place, "
  "so only the ranking changes.")
table([["Key", "View", "What to point at"],
       ["1", "sample cluster · old weights", "the top-4 paths (red, orange, purple, green) in the caption"],
       ["2", "sample cluster · ML weights", "the <font name='Sym'>▲</font> “was #k with old weights” tags: the order changes"],
       ["3", "live kav-bench · old weights", "documented Goat paths sit low in the list"],
       ["4", "live kav-bench · ML weights", "the same paths move to the top; Bad Pods priv reaches the node"],
       ["q", "back to the main menu", "server keeps running"]],
      [1.3, 5.2, 9.9])
figure("sample_static.png", 12.2, "View 1: sample cluster with old weights.")
figure("sample_learned.png", 12.2, "View 2: same layout, ML weights; the ranked paths and their tags change.")
speak("Same graph, same nodes, same edges. Only the weights changed, from assumed costs to learned "
      "probabilities, and the paths an attacker would really take rise to the top.")
P("If someone asks why some edges are missing: the drawing hides a few edges that are on no attack path, "
  "to keep the picture readable. The <b>All edges</b> button on the left rail shows every edge; the "
  "analysis always uses all of them.", small)

step(4, "about 2 min", "Benchmark: press <font name='Mono'>5</font>")
P("Runs the benchmark on the live kav-bench cluster and prints a Goat table (found, old rank, ML rank, "
  "ML probability), a Bad Pods table, a summary and a <b>Sources</b> section with <font name='Sym'>✔</font>/<font name='Sym'>✘</font> per item and the "
  "link to the page where Goat or Bad Pods documents that attack. Click one link to show it is real.")
P("Then it prints a <b>See it live</b> link; press <font name='Mono'>Enter</font>. The browser opens on "
  "kav-bench (view 4, ML weights) with the <b>Benchmark: Goat + Bad Pods</b> tab: the same table, each row "
  "with its <i>source</i> link. Click a row and that documented path lights up in the graph. Press "
  "<font name='Mono'>3</font> / <font name='Mono'>4</font> in the terminal to compare old and ML weights on "
  "the same table (5/6 vs 6/6 match; Bad Pod #5 flips to correct).")
table([["Live demo set (12 nodes, 24 paths)", "Old weights", "ML weights"],
       ["Mean rank of the deployed Goat attacks", "#5.3", "<b>#2.0</b>"],
       ["Bad Pods verdict correct (priv, hostpid)", "1/2", "<b>2/2</b>"]], [9.4, 3.3, 3.7])
P("Then say the full-benchmark result (all of Goat + all 8 Bad Pods, run once with "
  "<font name='Mono'>BENCH_FULL=1</font>; it takes longer, so it is not run live):", small)
figure("fig_benchmark.png", 15.5,
       f"Full benchmark: documented attacks rank #{lr['goat_mean_rank']} on average with ML weights, "
       f"#{st['goat_mean_rank']} with old weights; {match_ml}/{n_total} vs {match_old}/{n_total} matches.")
speak(f"Both weightings find all seven Goat attacks, so the graph was already right. The weights decide "
      f"the order, and with ML weights the documented attacks are where a defender looks first.")

step(5, "about 3.5 min", "Real time: a misconfiguration appears in prod")
P("In the main menu press <font name='Mono'>s</font> then <font name='Mono'>d</font> (kav-prod, the "
  "hardened cluster), then <font name='Mono'>4</font>. Show view <font name='Mono'>4</font> (live prod, "
  "ML weights). In the <b>second terminal</b>:")
code("./demo/drift.sh prod admin-sa         # bind shop/frontend SA to cluster-admin")
P("Wait about 15 seconds. The live views rescan; an alert toast appears and a new path from the frontend "
  "to cluster-admin takes <b>#1, CRITICAL (P = 0.975)</b> in view 4. Press <font name='Mono'>3</font>: "
  "with old weights the same path is only <b>#17, MEDIUM</b>. Then undo it:")
code("./demo/drift.sh prod admin-sa revert  # undo; seen in ~12 s, paths 21 -> 19")
speak("Nothing was exploited; we only changed configuration, as a careless admin might. The tool noticed "
      "in 16 seconds, and only the learned weights put it at the top where it belongs.")
P("Close: press <font name='Mono'>q</font> in the views menu, then <font name='Mono'>q</font> in the main "
  "menu.", small)

# ---------------------------------------------------------------- 5. Q&A
P("5. Questions to expect", h1)
qa = [
    ("Why w = −ln P?", "Multiplying probabilities along a path becomes adding weights, so ordinary "
     "shortest-path search (Dijkstra) finds the most likely path. P(path) = exp(−Σw)."),
    ("What does the ML model learn?", "Whether a CVE gets exploited in the wild. Trained on 361,825 NVD "
     "CVEs, labelled by the CISA Known Exploited Vulnerabilities list (1,743 positives), split by time so "
     "it is tested on later CVEs. ROC-AUC 0.887 vs 0.770 for CVSS; in its top 100, 54% are exploited vs 5% "
     "for CVSS. Logistic regression reaches 0.877."),
    ("Is every edge from the model?", "No. Edges fixed by configuration (a privileged pod reaches its "
     "node, an RBAC rule allows a read) are near-certain, 0.995. CVE edges use the model. Edges that depend "
     "on unknown conditions use a stated scenario parameter, 0.05."),
    ("Did you write the answer key?", "We wrote it down, but its content is what Goat and Bad Pods "
     "document; every item links to their page (all 17 links checked). The manifests are unmodified, "
     "pinned to a commit."),
    ("Where does ML get it wrong?", "Bad Pods hostPath: mounting the host filesystem can lead to "
     "the node, but only under conditions we cannot see in the spec, so it gets 0.05 and is not called an "
     "escape. Treating it as 0.05 is a deliberate, stated choice, not a tuned one."),
    ("Is the difference between old and ML too large?", "The two rankings still agree on a lot: "
     "Spearman ρ = 0.71 / 0.84 / 0.57 on dev / staging / prod. They differ where the evidence differs, "
     "which is the point. The top path does not change when the scenario parameter goes up to 0.5."),
    ("Is this safe to run?", "Everything is in local kind clusters. The drift script refuses any context "
     "that is not kind-kav-*. Delete the benchmark cluster after the demo."),
    ("Why only 12 nodes live?", "So the graph is readable on a projector. The full benchmark (all "
     "Goat + all Bad Pods, 80 paths) gives the numbers in the paper."),
]
table([["Question", "Short answer"]] + [[f"<b>{q}</b>", a] for q, a in qa], [4.4, 12.0])

# ---------------------------------------------------------------- 6. fallback
P("6. If something goes wrong", h1)
table([["Problem", "Fix"],
       ["<font name='Mono'>kind: command not found</font>",
        "<font name='Mono'>export PATH=\"$HOME/.local/bin:$PATH\"</font>; do <b>not</b> let dnf install kind "
        "(it wants to remove docker-ce)"],
       ["A cluster shows <i>stopped</i>", "choose it and press 1; present.sh starts it (about 30 s)"],
       ["Browser does not open", "open http://localhost:8765 by hand"],
       ["Views 3–4 say “scanning…”", "the first live scan takes 15–40 s with image scanning; talk over it"],
       ["Dashboard shows the wrong cluster", "<font name='Mono'>./demo/stop.sh</font>, then option 4 again"],
       ["Drift toast does not appear", "wait one more scan (15 s); check the second terminal printed no error"],
       ["Nothing works", "show the case study §7–8 and the paper Tables V–VI; screenshots are in there"]],
      [5.2, 11.2])

P("7. After the demo", h1)
code("./demo/drift.sh prod admin-sa revert     # if not reverted yet",
     "./demo/stop.sh                           # stop the dashboard server",
     "kind delete cluster --name kav-bench     # it runs deliberately vulnerable workloads")


def on_page(canv, doc):
    if doc.page == 1:
        return
    canv.saveState()
    canv.setFont("Sans", 8)
    canv.setFillColor(MUTED)
    canv.drawString(2.2 * cm, 1.2 * cm, "KubeAttackViz · Demo plan · Group 39")
    canv.drawRightString(A4[0] - 2.2 * cm, 1.2 * cm, str(doc.page))
    canv.setStrokeColor(LINE)
    canv.line(2.2 * cm, A4[1] - 1.5 * cm, A4[0] - 2.2 * cm, A4[1] - 1.5 * cm)
    canv.restoreState()


doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=2.2 * cm, rightMargin=2.2 * cm, topMargin=2.0 * cm,
                        bottomMargin=2.0 * cm, title="KubeAttackViz Demo Plan",
                        author="Group 39, IIIT Dharwad")
doc.build(S, onFirstPage=on_page, onLaterPages=on_page)
print("saved", OUT)
