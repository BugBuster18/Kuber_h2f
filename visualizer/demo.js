/**
 * KubeAttackViz — presentation views.
 *
 * Active when the server runs with `serve --demo-sample <graph.json>`.
 * Four views: {sample, live} cluster x {old (static), ML (learned)} weights.
 * The presenter switches them from the terminal (demo/views.sh) or with the
 * buttons drawn here; every open dashboard follows within a second.
 *
 * Each view colours its four highest-ranked paths (#1 red, #2 orange,
 * #3 purple, #4 green) and tags every path card with its rank under the
 * other weighting, so the before/after change is visible on screen.
 * Old/ML views of the same cluster keep the same node positions.
 *
 * Live view of the benchmark cluster (kav-bench): a second caption tab lists
 * the attacks documented by Kubernetes Goat / Bad Pods (from the last
 * `main.py benchmark` run), whether we match each one, its rank, and a link to
 * the documentation. Clicking a row highlights that path in the graph.
 */

const DEMO_POLL_MS = 1000;

async function tryStartDemo() {
    try {
        const resp = await fetch('/api/demo', { cache: 'no-store' });
        if (!resp.ok) return false;
        const state = await resp.json();
        if (!state.enabled) return false;
        window.DEMO = { state, shown: null, seq: null, version: null, source: null, alertSeq: 0, busy: false,
                         bench: null, benchRows: null, tab: 'top', benchSel: null };
        try { if (new URLSearchParams(location.search).get('tab') === 'bench') window.DEMO.tab = 'bench'; } catch (_) {}
        buildDemoBar(state);
        ensureLivePill();
        const sel = document.getElementById('topbar-cluster-select');
        if (sel) sel.style.display = 'none';      // the four views replace the file picker
        await pollDemo();
        setInterval(pollDemo, DEMO_POLL_MS);
        return true;
    } catch (_) {
        return false;                               // static hosting, no API
    }
}

function buildDemoBar(state) {
    const bar = document.createElement('div');
    bar.id = 'demo-bar';
    bar.className = 'demo-bar';
    const buttons = document.createElement('div');
    buttons.className = 'demo-buttons';
    state.views.forEach(v => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = `demo-btn demo-${v.weights}`;
        b.dataset.view = v.id;
        b.innerHTML = `<span class="demo-num">${v.id}</span><span class="demo-txt">` +
            `<b>${v.cluster_label}</b><small>${v.weights === 'learned' ? 'ML weights' : 'Old weights'}</small></span>`;
        b.addEventListener('click', () => fetch(`/api/demo/view?view=${v.id}`, { method: 'POST' }).then(pollDemo));
        buttons.appendChild(b);
    });
    const caption = document.createElement('div');
    caption.id = 'demo-caption';
    caption.className = 'demo-caption';
    bar.append(buttons, caption);
    document.getElementById('graph-container').appendChild(bar);
}

async function pollDemo() {
    const D = window.DEMO;
    if (!D || D.busy) return;
    D.busy = true;
    try {
        const state = await (await fetch('/api/demo', { cache: 'no-store' })).json();
        D.state = state;
        const view = state.views.find(v => v.id === state.view);
        document.querySelectorAll('.demo-btn').forEach(b => {
            const v = state.views.find(x => x.id === +b.dataset.view);
            b.classList.toggle('active', v.id === state.view);
            b.classList.toggle('waiting', !v.ready);
            b.title = v.ready ? `${v.cluster_label} (${v.cluster_name}) · ${v.weights_label} · ${v.paths} paths`
                              : 'first scan of the live cluster still running…';
        });
        updateDemoPill(state, view);
        // redraw on a switch, or when the live cluster changed (new scan version)
        if (state.seq !== D.seq || (view.ready && view.version !== D.version)) {
            if (view.ready) {
                await showDemoView(view);
                D.seq = state.seq;
            } else {
                setDemoCaption(view, null, 'Scanning the live cluster… the view appears when the first scan finishes.');
                D.seq = state.seq;
                D.version = null;
            }
        }
        if (view.source === 'live') {
            const alerts = await (await fetch(`/api/alerts?since=${D.alertSeq}`, { cache: 'no-store' })).json();
            alerts.forEach(a => { D.alertSeq = Math.max(D.alertSeq, a.seq); showAlertToast(a); });
        }
    } catch (err) {
        updateLivePill(null, 'server unreachable');
    } finally {
        D.busy = false;
    }
}

function counterpartId(view) {
    return view.id % 2 === 1 ? view.id + 1 : view.id - 1;     // 1<->2, 3<->4
}

async function showDemoView(view) {
    const D = window.DEMO;
    const data = await (await fetch(`/api/demo/graph?view=${view.id}`, { cache: 'no-store' })).json();
    let other = null;
    const otherView = D.state.views.find(v => v.id === counterpartId(view));
    if (otherView && otherView.ready) {
        const r = await fetch(`/api/demo/graph?view=${otherView.id}`, { cache: 'no-store' });
        if (r.ok) other = await r.json();
    }
    annotateRankChanges(data, other, view);
    await loadBenchmark(view, data);

    // Same cluster as the view on screen (old <-> ML, or a live re-scan): keep every node where it is
    const sameCluster = D.source === view.source && D.shown !== null;
    if (sameCluster) {
        const pos = new Map();
        d3.selectAll('.node-circle').each(d => { if (d && d.x !== undefined) pos.set(d.id, { x: d.x, y: d.y }); });
        if (pos.size) lastPositions = pos;
    } else {
        lastPositions = new Map();
    }
    window.__keepLayout = sameCluster;
    window.__sparseOther = other;     // draw the same edges in the old and ML views
    try { loadGraphData(data); } finally { window.__keepLayout = false; }
    D.shown = view.id;
    D.source = view.source;
    D.version = view.version;
    setDemoCaption(view, data, null);
    if (D.benchSel !== null) highlightBench(D.benchSel, true);
}

// ─── Benchmark answer key (live kav-bench views) ─────────────────────────────

async function loadBenchmark(view, data) {
    const D = window.DEMO;
    D.benchRows = null;
    window.__benchPaths = [];
    if (view.source !== 'live') return;
    try {
        const r = await fetch('/api/benchmark', { cache: 'no-store' });
        if (!r.ok) return;
        D.bench = await r.json();
    } catch (_) { return; }
    if (!D.bench || D.bench.context !== D.state.live.context) return;    // result is for another cluster
    const mode = view.weights === 'learned' ? 'learned' : 'static';
    D.benchRows = (D.bench.items || []).map(it => {
        const m = it.modes[mode] || {};
        const ok = it.group === 'bad_pods' ? m.claims_escape === (it.expect === 'reachable') : !!m.found;
        const ids = resolveNamedPath(data, m.path || []);
        if (ids) window.__benchPaths.push({ path_nodes: ids });
        return { it, m, ok, ids, mode };
    });
}

// Benchmark paths are stored by resource name; map them to graph node ids,
// choosing at each step a node that has an edge from the previous one.
function resolveNamedPath(data, names) {
    if (!names.length) return null;
    const byName = new Map();
    (data.nodes || []).forEach(n => {
        if (!byName.has(n.name)) byName.set(n.name, []);
        byName.get(n.name).push(n.id);
    });
    const edges = new Set((data.edges || []).map(e => `${e.source.id || e.source}|${e.target.id || e.target}`));
    let paths = (byName.get(names[0]) || []).map(id => [id]);
    for (const name of names.slice(1)) {
        const next = [];
        for (const p of paths) {
            for (const id of byName.get(name) || []) {
                if (edges.has(`${p[p.length - 1]}|${id}`)) next.push([...p, id]);
            }
        }
        paths = next;
    }
    return paths.length ? paths[0] : null;
}

function benchLabel(it) {
    const [g, n] = it.id.split('-');
    return g === 'goat' ? `Goat #${n}` : `Bad Pod #${n}`;
}

function benchTable(view) {
    const D = window.DEMO;
    const learned = view.weights === 'learned';
    const rows = D.benchRows.map((r, i) => {
        const { it, m, ok } = r;
        const verdict = it.group === 'bad_pods'
            ? (m.claims_escape ? 'escape' : 'no escape')
            : (m.found ? 'found' : 'not found');
        const rank = m.rank ? `#${m.rank}` : (m.found ? 'reach.' : '—');
        // Bad Pods: the verdict uses the direct pod→node step, so show that P, not the best path's
        const pv = it.group === 'bad_pods' ? m.escape_score : m.probability;
        const score = learned && typeof pv === 'number'
            ? ` · ${it.group === 'bad_pods' ? 'P(escape)' : 'P'} ${(pv * 100).toFixed(1)}%` : '';
        const doc = it.group === 'bad_pods' ? (it.expect === 'reachable' ? 'escape' : 'no escape') : 'reachable';
        return `<tr class="bench-row${D.benchSel === i ? ' sel' : ''}${r.ids ? '' : ' nopath'}" data-i="${i}">` +
            `<td><b>${benchLabel(it)}</b><small>${it.title}</small></td>` +
            `<td>${doc}</td><td>${verdict}${score}</td><td>${rank}</td>` +
            `<td class="${ok ? 'bench-ok' : 'bench-bad'}">${ok ? '✔' : '✘'}</td>` +
            `<td><a href="${it.doc}" target="_blank" rel="noopener" title="${it.doc}">source ↗</a></td></tr>`;
    }).join('');
    const nOk = D.benchRows.filter(r => r.ok).length;
    const ranks = D.benchRows.filter(r => r.it.group !== 'bad_pods' && r.m.rank).map(r => r.m.rank);
    const mean = ranks.length ? (ranks.reduce((a, b) => a + b, 0) / ranks.length).toFixed(1) : '—';
    return `<div class="bench-sum">Documented by <a href="https://github.com/madhuakula/kubernetes-goat" target="_blank" rel="noopener">Kubernetes Goat</a>` +
        ` and <a href="https://github.com/BishopFox/badPods" target="_blank" rel="noopener">Bad Pods</a> · ` +
        `<b>${nOk}/${D.benchRows.length}</b> match with ${learned ? 'ML' : 'old'} weights · mean Goat rank <b>#${mean}</b> ` +
        `of ${D.bench.paths_ranked[r0mode(view)]} paths · click a row to show it</div>` +
        '<table class="bench-table"><thead><tr><th>Documented attack</th><th>They say</th><th>We say</th>' +
        '<th>Rank</th><th>Match</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>';
}

const r0mode = view => (view.weights === 'learned' ? 'learned' : 'static');

function highlightBench(i, keep) {
    const D = window.DEMO;
    const r = D.benchRows && D.benchRows[i];
    if (!r || !r.ids || (!keep && D.benchSel === i)) {
        D.benchSel = null;
        clearHighlight();
    } else {
        D.benchSel = i;
        const ns = new Set(r.ids), es = new Set();
        for (let k = 0; k < r.ids.length - 1; k++) es.add(`${r.ids[k]}|${r.ids[k + 1]}`);
        d3.selectAll('.node-circle').classed('dimmed', d => !ns.has(d.id));
        d3.selectAll('.node-label').classed('dimmed', d => !ns.has(d.id));
        d3.selectAll('.link-line').classed('dimmed', d => !es.has(`${d.source.id || d.source}|${d.target.id || d.target}`));
    }
    document.querySelectorAll('.bench-row').forEach(tr => tr.classList.toggle('sel', +tr.dataset.i === D.benchSel));
}

const pathKey = p => (p.path_nodes || []).join('>');
const pairKey = p => {
    const n = p.path_nodes || [];
    return `${n[0]}>${n[n.length - 1]}`;
};

// Tag each path with where it ranked under the other weighting.
function annotateRankChanges(data, other, view) {
    const paths = data.attack_paths || [];
    if (!other) { paths.forEach(p => { delete p._compare; }); return; }
    const otherName = view.weights === 'learned' ? 'old weights' : 'ML weights';
    const exact = new Map(), pair = new Map();
    (other.attack_paths || []).forEach((p, i) => {
        if (!exact.has(pathKey(p))) exact.set(pathKey(p), i + 1);
        if (!pair.has(pairKey(p))) pair.set(pairKey(p), i + 1);
    });
    paths.forEach((p, i) => {
        const me = i + 1;
        let was = exact.get(pathKey(p)), route = 'same route';
        if (was === undefined) { was = pair.get(pairKey(p)); route = 'other route'; }
        if (was === undefined) {
            p._compare = { cls: 'cmp-new', text: `not found with ${otherName}` };
        } else if (was === me) {
            p._compare = { cls: 'cmp-same', text: `= #${was} with ${otherName}` + (route === 'other route' ? ' (different route)' : '') };
        } else {
            const up = was > me;
            p._compare = { cls: up ? 'cmp-up' : 'cmp-down',
                           text: `${up ? '▲' : '▼'} was #${was} with ${otherName}` + (route === 'other route' ? ' (different route)' : '') };
        }
        p._was = was;
    });
}

function fmtScore(p, learned) {
    return learned && typeof p.success_probability === 'number'
        ? `P = ${(p.success_probability * 100).toFixed(1)}%` : `risk ${(p.total_risk || 0).toFixed(2)}`;
}

function setDemoCaption(view, data, message) {
    const el = document.getElementById('demo-caption');
    if (!el) return;
    const learned = view.weights === 'learned';
    const where = view.source === 'live' ? `live cluster <b>${view.cluster_name}</b>` : `sample cluster <b>${view.cluster_name}</b>`;
    const how = learned
        ? 'edge weight = −ln P(success) · ranked by impact × P'
        : 'hand-set edge costs (paper-style coefficients) · ranked by impact / (1 + cost/10)';
    let html = `<div class="demo-title"><span class="demo-chip demo-chip-${view.weights}">View ${view.id}/4</span> ${where} · ${how}</div>`;
    const D = window.DEMO;
    const bench = !message && D.benchRows && D.benchRows.length;
    if (bench) {
        html += `<div class="demo-tabs"><button type="button" data-tab="top" class="${D.tab === 'top' ? 'on' : ''}">Top paths</button>` +
            `<button type="button" data-tab="bench" class="${D.tab === 'bench' ? 'on' : ''}">Benchmark: Goat + Bad Pods</button></div>`;
    }
    if (message) {
        html += `<div class="demo-msg">${message}</div>`;
    } else if (bench && D.tab === 'bench') {
        html += benchTable(view);
    } else if (data) {
        const top = (data.attack_paths || []).slice(0, 4);
        html += '<ol class="demo-top">' + top.map((p, i) =>
            `<li style="--rank-color:${RANK_COLORS[i]}"><span class="demo-route">${(p.path_nodes || []).map((id, k) => shortName({ id, name: p.path_names[k], type: id.split(':')[0] })).join(' → ')}</span>` +
            `<span class="demo-score">${fmtScore(p, learned)} · ${p.severity}` +
            (p._compare ? ` · <span class="${p._compare.cls}">${p._compare.text}</span>` : '') + '</span></li>').join('') + '</ol>';
        if (!top.length) html += '<div class="demo-msg">No attack paths in this cluster.</div>';
    }
    el.innerHTML = html;
    el.querySelectorAll('.demo-tabs button').forEach(b => b.addEventListener('click', () => {
        D.tab = b.dataset.tab;
        if (D.tab !== 'bench' && D.benchSel !== null) { D.benchSel = null; clearHighlight(); }
        setDemoCaption(view, data, null);
        if (typeof zoomToFit === 'function') zoomToFit();
    }));
    el.querySelectorAll('.bench-row').forEach(tr => tr.addEventListener('click', e => {
        if (e.target.closest('a')) return;              // the link opens the documentation
        highlightBench(+tr.dataset.i, false);
    }));
}

function updateDemoPill(state, view) {
    const pill = document.getElementById('live-pill');
    if (!pill) return;
    if (view.source !== 'live') {
        pill.className = 'live-pill live-off';
        pill.textContent = `○ sample · ${view.weights === 'learned' ? 'ML' : 'old'} weights`;
        return;
    }
    const L = state.live;
    const ago = L.last_scan_at ? Math.max(0, Math.round((Date.now() - Date.parse(L.last_scan_at)) / 1000)) : null;
    pill.className = `live-pill ${L.status === 'ok' ? 'live-on' : (L.status === 'error' ? 'live-err' : 'live-off')}`;
    pill.textContent = L.scans
        ? `● LIVE ${L.context.replace('kind-', '')} · scan #${L.scans}` + (ago !== null ? ` · ${ago}s ago` : '') +
          ` · ${view.weights === 'learned' ? 'ML' : 'old'} weights`
        : `● ${L.context.replace('kind-', '')} · first scan running…`;
}
