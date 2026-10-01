/**
 * KubeAttackViz — Dashboard & Timeline Controller
 *
 * Manages the Dashboard (View 2) and Timeline (View 3) views.
 * The Graph view (View 1) continues to be driven by script.js.
 */

// ─── View Switching ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(btn => {
        btn.addEventListener('click', () => {
            const view = btn.dataset.view;
            tabs.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
            document.getElementById(`view-${view}`).classList.add('active');
        });
    });

    // Timeline file drop
    const tlDrop = document.getElementById('timeline-drop-zone');
    const tlInput = document.getElementById('timeline-file-input');
    if (tlDrop) {
        tlDrop.addEventListener('click', () => tlInput.click());
        tlDrop.addEventListener('dragover', e => { e.preventDefault(); tlDrop.classList.add('dragover'); });
        tlDrop.addEventListener('dragleave', () => tlDrop.classList.remove('dragover'));
        tlDrop.addEventListener('drop', e => {
            e.preventDefault(); tlDrop.classList.remove('dragover');
            handleTimelineFiles(e.dataTransfer.files);
        });
        tlInput.addEventListener('change', e => handleTimelineFiles(e.target.files));
    }

    // Load timeline button (try to load from default path)
    document.getElementById('btn-load-timeline')?.addEventListener('click', async () => {
        try {
            const resp = await fetch('../.temporal_snapshots/snapshot_index.json');
            if (!resp.ok) throw new Error('No snapshot index found');
            const index = await resp.json();
            if (index.snapshots && index.snapshots.length > 0) {
                const snapshots = [];
                for (const entry of index.snapshots) {
                    try {
                        const r = await fetch(`../.temporal_snapshots/${entry.snapshot_id}.json`);
                        if (r.ok) snapshots.push(await r.json());
                    } catch (_) {}
                }
                if (snapshots.length > 0) {
                    renderTimeline(snapshots);
                    return;
                }
            }
            alert('No snapshots found in .temporal_snapshots/.\nRun: python main.py temporal-snapshot -i cluster-graph.json');
        } catch (err) {
            alert('Could not load timeline data.\nDrag snapshot JSON files directly, or run:\n  python main.py temporal-snapshot -i cluster-graph.json\n\nError: ' + err.message);
        }
    });

    // Close diff panel
    document.getElementById('btn-close-diff')?.addEventListener('click', () => {
        document.getElementById('diff-panel').style.display = 'none';
    });
});


// ─── Dashboard Population ────────────────────────────────────────────────────

/**
 * Called from script.js after graph data is loaded.
 * Populates dashboard cards with analysis data.
 */
function populateDashboard(data) {
    if (!data) return;

    // ── Posture Score ────────────────────────────────────────────
    const paths = data.attack_paths || [];
    const critCount = paths.filter(p => p.severity === 'CRITICAL').length;
    const highCount = paths.filter(p => p.severity === 'HIGH').length;
    const medCount  = paths.filter(p => p.severity === 'MEDIUM').length;
    const lowCount  = paths.filter(p => p.severity === 'LOW').length;

    // Score: 100 = no paths, each CRITICAL = -20, HIGH = -12, MED = -5, LOW = -2
    let score = 100 - critCount * 20 - highCount * 12 - medCount * 5 - lowCount * 2;
    score = Math.max(0, Math.min(100, score));

    const ring = document.getElementById('ring-fg');
    const circumference = 2 * Math.PI * 52; // r=52
    ring.style.strokeDasharray = circumference;
    ring.style.strokeDashoffset = circumference - (score / 100) * circumference;
    ring.style.stroke = score >= 70 ? 'var(--green)' : score >= 40 ? 'var(--orange)' : 'var(--red)';
    document.getElementById('posture-score').textContent = score;
    const label = score >= 80 ? 'Acceptable' : score >= 50 ? 'Needs Attention' : 'Critical Risk';
    document.getElementById('posture-label').textContent = label;

    // ── Path stats ──────────────────────────────────────────────
    document.getElementById('stat-total-paths').textContent = paths.length;
    const pills = document.getElementById('severity-pills');
    pills.innerHTML = '';
    if (critCount > 0) pills.innerHTML += `<span class="sev sev-CRITICAL">${critCount} CRIT</span>`;
    if (highCount > 0) pills.innerHTML += `<span class="sev sev-HIGH">${highCount} HIGH</span>`;
    if (medCount > 0)  pills.innerHTML += `<span class="sev sev-MEDIUM">${medCount} MED</span>`;
    if (lowCount > 0)  pills.innerHTML += `<span class="sev sev-LOW">${lowCount} LOW</span>`;

    // ── Critical Node ───────────────────────────────────────────
    const cn = data.critical_node;
    if (cn && cn.top_nodes && cn.top_nodes.length > 0) {
        const top = cn.top_nodes[0];
        document.getElementById('stat-critical-node-name').textContent = top.name;
        const pct = cn.baseline_paths > 0 ? Math.round(top.paths_eliminated / cn.baseline_paths * 100) : 0;
        document.getElementById('stat-critical-node-impact').textContent =
            `Removing eliminates ${top.paths_eliminated}/${cn.baseline_paths} paths (${pct}%)`;
    }

    // ── CVE Stats ───────────────────────────────────────────────
    const allCves = new Set();
    let maxCvss = 0;
    const cveNodeMap = {};
    (data.nodes || []).forEach(n => {
        (n.cves || []).forEach(c => {
            allCves.add(c);
            if (!cveNodeMap[c]) cveNodeMap[c] = [];
            cveNodeMap[c].push(n.name);
        });
    });
    (data.edges || []).forEach(e => {
        if (e.cve) allCves.add(e.cve);
        if (e.cvss && e.cvss > maxCvss) maxCvss = e.cvss;
    });
    document.getElementById('stat-total-cves').textContent = allCves.size;
    document.getElementById('stat-max-cvss').textContent = maxCvss > 0
        ? `Max CVSS: ${maxCvss.toFixed(1)}`
        : 'No CVSS data';

    // ── Blast Radius ────────────────────────────────────────────
    const blastBody = document.getElementById('blast-body');
    const blastData = data.blast_radius || [];
    if (blastData.length === 0) {
        blastBody.innerHTML = '<p class="empty-state">No source nodes for blast radius.</p>';
    } else {
        const maxAffected = Math.max(...blastData.map(b => b.total_affected), 1);
        blastBody.innerHTML = blastData.map(b => {
            const pct = (b.total_affected / maxAffected) * 100;
            return `
                <div class="blast-item">
                    <div class="blast-label">
                        <span>${b.source_name}</span>
                        <span>${b.total_affected} affected</span>
                    </div>
                    <div class="blast-bar"><div class="blast-bar-fill" style="width:${pct}%"></div></div>
                </div>`;
        }).join('');
    }

    // ── Critical Nodes ──────────────────────────────────────────
    const critBody = document.getElementById('critical-body');
    if (cn && cn.top_nodes && cn.top_nodes.length > 0) {
        critBody.innerHTML = cn.top_nodes.map((n, i) => `
            <div class="crit-item">
                <span class="crit-name">${i + 1}. ${n.name}</span>
                <span class="crit-badge">${n.paths_eliminated} paths</span>
            </div>`).join('');
    } else {
        critBody.innerHTML = '<p class="empty-state">No critical nodes found.</p>';
    }

    // ── Attack Path Table ───────────────────────────────────────
    const pathBody = document.getElementById('pathdetail-body');
    if (paths.length === 0) {
        pathBody.innerHTML = '<p class="empty-state">No attack paths detected.</p>';
    } else {
        let rows = paths.map((p, i) => {
            const route = (p.path_names || []).join(' → ');
            const cats = (p.categories || []).join(', ') || '—';
            const cves = (p.cves || []).filter(Boolean);
            const cveStr = cves.length > 0 ? cves.join(', ') : '—';
            return `<tr>
                <td>${i + 1}</td>
                <td><span class="sev sev-${p.severity}">${p.severity}</span></td>
                <td class="td-path">${route}</td>
                <td class="td-mono">${p.hop_count}</td>
                <td class="td-mono">${p.total_risk.toFixed(2)}</td>
                <td class="td-mono">${p.advanced_score ?? '—'}</td>
                <td>${cats}</td>
                <td class="td-mono" style="font-size:.68rem">${cveStr}</td>
                <td>
                    <button type="button" class="btn-explain-nlp btn-table-explain" data-idx="${i}" title="Explain this attack path in plain English">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                        Explain
                    </button>
                </td>
            </tr>`;
        }).join('');

        pathBody.innerHTML = `
            <table class="data-table">
                <thead><tr>
                    <th>#</th><th>Severity</th><th>Path</th><th>Hops</th>
                    <th>Risk</th><th>Score</th><th>Category</th><th>CVEs</th><th>Action</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>`;

        // Wire up table explain buttons
        pathBody.querySelectorAll('.btn-table-explain').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const idx = parseInt(btn.dataset.idx, 10);
                const pathObj = paths[idx];
                if (pathObj && typeof explainAttackPathNLP === 'function') {
                    const explanation = explainAttackPathNLP(pathObj, data);
                    if (typeof openNlpExplanationModal === 'function') {
                        openNlpExplanationModal({
                            type: 'attack_path',
                            data: explanation,
                            highlightPath: pathObj
                        });
                    }
                }
            });
        });
    }

    // ── CVE Intelligence Grid ───────────────────────────────────
    const cveBody = document.getElementById('cve-body');
    if (allCves.size === 0) {
        cveBody.innerHTML = '<p class="empty-state">No CVEs detected in this cluster.</p>';
    } else {
        // Build CVE -> CVSS map from edges
        const cvssMap = {};
        (data.edges || []).forEach(e => {
            if (e.cve && e.cvss) cvssMap[e.cve] = e.cvss;
        });
        const sorted = [...allCves].sort((a, b) => (cvssMap[b] || 0) - (cvssMap[a] || 0));
        cveBody.innerHTML = '<div class="cve-grid">' + sorted.map(cve => {
            const score = cvssMap[cve];
            const nodes = cveNodeMap[cve] || [];
            const scoreColor = score ? (score >= 9 ? 'var(--red)' : score >= 7 ? 'var(--orange)' : 'var(--blue)') : 'var(--text-3)';
            return `<div class="cve-card">
                <div class="cve-id">${cve}${score ? `<span class="cve-score" style="color:${scoreColor}">${score.toFixed(1)}</span>` : ''}</div>
                <div class="cve-meta">Affects: ${nodes.length > 0 ? nodes.join(', ') : 'edge-level'}</div>
            </div>`;
        }).join('') + '</div>';
    }
}


// ─── Timeline ────────────────────────────────────────────────────────────────

let loadedSnapshots = [];

function handleTimelineFiles(files) {
    const readers = [];
    for (const file of files) {
        readers.push(new Promise((resolve, reject) => {
            const r = new FileReader();
            r.onload = e => { try { resolve(JSON.parse(e.target.result)); } catch(err) { reject(err); } };
            r.readAsText(file);
        }));
    }
    Promise.all(readers).then(data => {
        // Could be individual snapshots or a diff history array
        if (Array.isArray(data[0])) {
            // Diff history JSON
            renderDiffHistory(data[0]);
        } else {
            renderTimeline(data);
        }
    }).catch(err => alert('Failed to parse files: ' + err.message));
}

function renderTimeline(snapshots) {
    loadedSnapshots = snapshots.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const track = document.getElementById('timeline-track');

    if (snapshots.length === 0) {
        track.innerHTML = '<div class="tl-empty-state"><p>No snapshots to display.</p></div>';
        return;
    }

    let html = '';
    for (let i = 0; i < snapshots.length; i++) {
        const snap = snapshots[i];
        const ts = new Date(snap.timestamp).toLocaleString();
        const isFirst = i === 0;
        const nodeCount = snap.cluster_data?.nodes?.length || '?';
        const edgeCount = snap.cluster_data?.edges?.length || '?';
        const entryClass = isFirst ? 'tl-ok' : 'tl-change';

        html += `
            <div class="tl-entry ${entryClass}" data-index="${i}">
                <div class="tl-dot"></div>
                <div class="tl-card" onclick="showSnapshotDiff(${i})">
                    <div class="tl-card-head">
                        <span class="tl-card-title">${isFirst ? 'Baseline Snapshot' : `Scan #${i + 1}`}</span>
                        <span class="tl-time">${ts}</span>
                    </div>
                    <div class="tl-card-stats">
                        <div class="tl-stat"><span class="tl-stat-dot" style="background:var(--blue)"></span>${nodeCount} nodes</div>
                        <div class="tl-stat"><span class="tl-stat-dot" style="background:var(--purple)"></span>${edgeCount} edges</div>
                        <div class="tl-stat"><span class="tl-stat-dot" style="background:var(--text-3)"></span>${snap.graph_hash?.substring(0, 8) || '—'}</div>
                        <div class="tl-stat" style="color:var(--text-3);font-size:.68rem">${snap.source || 'unknown'}</div>
                    </div>
                </div>
            </div>`;
    }

    track.innerHTML = html;
}

function renderDiffHistory(diffs) {
    const track = document.getElementById('timeline-track');
    if (diffs.length === 0) {
        track.innerHTML = '<div class="tl-empty-state"><p>No diffs in this history.</p></div>';
        return;
    }

    let html = '';
    diffs.forEach((diff, i) => {
        const ts = diff.timestamp ? new Date(diff.timestamp).toLocaleString() : `Diff #${i + 1}`;
        const hasChanges = diff.has_changes;
        const alertCount = diff.alerts?.length || 0;
        const hasCritical = (diff.alerts || []).some(a => a.severity === 'CRITICAL');
        const entryClass = hasCritical ? 'tl-alert' : hasChanges ? 'tl-change' : 'tl-ok';

        const summary = diff.summary || {};
        html += `
            <div class="tl-entry ${entryClass}" data-diff-index="${i}">
                <div class="tl-dot"></div>
                <div class="tl-card" onclick="showDiffDetail(${i})">
                    <div class="tl-card-head">
                        <span class="tl-card-title">${hasChanges ? '⚡ Changes Detected' : '✓ No Changes'}</span>
                        <span class="tl-time">${ts}</span>
                    </div>
                    <div class="tl-card-stats">
                        <div class="tl-stat"><span class="tl-stat-dot" style="background:var(--green)"></span>+${summary.new_nodes_count || 0} nodes</div>
                        <div class="tl-stat"><span class="tl-stat-dot" style="background:var(--red)"></span>-${summary.removed_nodes_count || 0} nodes</div>
                        <div class="tl-stat"><span class="tl-stat-dot" style="background:var(--orange)"></span>${summary.new_attack_paths_count || 0} new paths</div>
                        ${alertCount > 0 ? `<div class="tl-stat" style="color:var(--red)">🚨 ${alertCount} alert${alertCount>1?'s':''}</div>` : ''}
                    </div>
                </div>
            </div>`;
    });

    track.innerHTML = html;
    // Store for detail views
    window._diffHistory = diffs;
}

function showSnapshotDiff(index) {
    if (index === 0 || loadedSnapshots.length < 2) {
        // Show snapshot info
        const snap = loadedSnapshots[index];
        const panel = document.getElementById('diff-panel');
        const body = document.getElementById('diff-panel-body');
        panel.style.display = 'block';
        const ts = new Date(snap.timestamp).toLocaleString();
        const nodeCount = snap.cluster_data?.nodes?.length || 0;
        const edgeCount = snap.cluster_data?.edges?.length || 0;
        body.innerHTML = `
            <div class="diff-section">
                <div class="diff-section-title">Snapshot Info</div>
                <div class="detail-row"><span class="detail-row-key">ID</span><span class="detail-row-value td-mono">${snap.snapshot_id}</span></div>
                <div class="detail-row"><span class="detail-row-key">Timestamp</span><span class="detail-row-value">${ts}</span></div>
                <div class="detail-row"><span class="detail-row-key">Hash</span><span class="detail-row-value td-mono">${snap.graph_hash}</span></div>
                <div class="detail-row"><span class="detail-row-key">Source</span><span class="detail-row-value">${snap.source}</span></div>
                <div class="detail-row"><span class="detail-row-key">Nodes</span><span class="detail-row-value">${nodeCount}</span></div>
                <div class="detail-row"><span class="detail-row-key">Edges</span><span class="detail-row-value">${edgeCount}</span></div>
            </div>
            <p class="empty-state">${index === 0 ? 'This is the baseline snapshot. Select a later snapshot to see the diff.' : 'Client-side diff not available. Use CLI to compute diffs.'}</p>`;
        return;
    }
    // For non-baseline, show basic comparison
    const oldSnap = loadedSnapshots[index - 1];
    const newSnap = loadedSnapshots[index];
    showClientDiff(oldSnap, newSnap);
}

function showClientDiff(oldSnap, newSnap) {
    const panel = document.getElementById('diff-panel');
    const body = document.getElementById('diff-panel-body');
    panel.style.display = 'block';

    const oldNodes = new Set((oldSnap.cluster_data?.nodes || []).map(n => n.id));
    const newNodes = new Set((newSnap.cluster_data?.nodes || []).map(n => n.id));
    const addedNodes = [...newNodes].filter(id => !oldNodes.has(id));
    const removedNodes = [...oldNodes].filter(id => !newNodes.has(id));

    const edgeKey = e => `${e.source}|${e.target}|${e.relationship}`;
    const oldEdges = new Set((oldSnap.cluster_data?.edges || []).map(edgeKey));
    const newEdges = new Set((newSnap.cluster_data?.edges || []).map(edgeKey));
    const addedEdges = [...newEdges].filter(k => !oldEdges.has(k));
    const removedEdges = [...oldEdges].filter(k => !newEdges.has(k));

    const nodeNameMap = {};
    (newSnap.cluster_data?.nodes || []).forEach(n => nodeNameMap[n.id] = n.name);
    (oldSnap.cluster_data?.nodes || []).forEach(n => { if (!nodeNameMap[n.id]) nodeNameMap[n.id] = n.name; });

    body.innerHTML = `
        <div class="diff-section">
            <div class="diff-section-title">Nodes (+${addedNodes.length} / -${removedNodes.length})</div>
            ${addedNodes.map(id => `<div class="diff-item added">+ ${nodeNameMap[id] || id}</div>`).join('')}
            ${removedNodes.map(id => `<div class="diff-item removed">- ${nodeNameMap[id] || id}</div>`).join('')}
            ${addedNodes.length === 0 && removedNodes.length === 0 ? '<div class="diff-item">No node changes.</div>' : ''}
        </div>
        <div class="diff-section">
            <div class="diff-section-title">Edges (+${addedEdges.length} / -${removedEdges.length})</div>
            ${addedEdges.slice(0, 10).map(k => `<div class="diff-item added">+ ${k.replace(/\|/g, ' → ')}</div>`).join('')}
            ${removedEdges.slice(0, 10).map(k => `<div class="diff-item removed">- ${k.replace(/\|/g, ' → ')}</div>`).join('')}
            ${addedEdges.length === 0 && removedEdges.length === 0 ? '<div class="diff-item">No edge changes.</div>' : ''}
            ${addedEdges.length > 10 ? `<div class="diff-item" style="color:var(--text-3)">...and ${addedEdges.length - 10} more</div>` : ''}
        </div>
        <div class="diff-section">
            <div class="diff-section-title">Summary</div>
            <div class="detail-row"><span class="detail-row-key">Hash (old)</span><span class="detail-row-value td-mono">${oldSnap.graph_hash}</span></div>
            <div class="detail-row"><span class="detail-row-key">Hash (new)</span><span class="detail-row-value td-mono">${newSnap.graph_hash}</span></div>
            <div class="detail-row"><span class="detail-row-key">Same?</span><span class="detail-row-value">${oldSnap.graph_hash === newSnap.graph_hash ? '✓ Yes' : '✗ Changed'}</span></div>
        </div>`;
}

function showDiffDetail(index) {
    const diffs = window._diffHistory;
    if (!diffs || !diffs[index]) return;
    const diff = diffs[index];

    const panel = document.getElementById('diff-panel');
    const body = document.getElementById('diff-panel-body');
    panel.style.display = 'block';

    let alertsHtml = '';
    if (diff.alerts && diff.alerts.length > 0) {
        alertsHtml = diff.alerts.map(a => {
            const cls = a.severity === 'CRITICAL' || a.severity === 'HIGH' ? ''
                      : a.severity === 'INFO' ? 'alert-info' : 'alert-high';
            const icon = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', INFO: 'ℹ️' }[a.severity] || '❓';
            return `<div class="diff-alert ${cls}">
                <span class="diff-alert-icon">${icon}</span>
                <div class="diff-alert-text">
                    <div class="diff-alert-title">[${a.severity}] ${a.title}</div>
                    <div class="diff-alert-desc">${a.description || ''}</div>
                </div>
            </div>`;
        }).join('');
    }

    const nn = diff.new_nodes || [];
    const rn = diff.removed_nodes || [];
    const ne = diff.new_edges || [];
    const re = diff.removed_edges || [];
    const np = diff.new_attack_paths || [];
    const rp = diff.removed_attack_paths || [];

    body.innerHTML = `
        ${alertsHtml ? `<div class="diff-section"><div class="diff-section-title">Alerts (${diff.alerts.length})</div>${alertsHtml}</div>` : ''}
        <div class="diff-section">
            <div class="diff-section-title">New Attack Paths (${np.length})</div>
            ${np.map(p => `<div class="diff-item added">⚡ ${(p.path_names || []).join(' → ')} — <span class="sev sev-${p.severity}">${p.severity}</span> risk: ${(p.total_risk || 0).toFixed(2)}</div>`).join('')}
            ${np.length === 0 ? '<div class="diff-item">None.</div>' : ''}
        </div>
        <div class="diff-section">
            <div class="diff-section-title">Eliminated Paths (${rp.length})</div>
            ${rp.map(p => `<div class="diff-item removed">✓ ${(p.path_names || []).join(' → ')}</div>`).join('')}
            ${rp.length === 0 ? '<div class="diff-item">None.</div>' : ''}
        </div>
        <div class="diff-section">
            <div class="diff-section-title">Node Changes (+${nn.length} / -${rn.length})</div>
            ${nn.map(n => `<div class="diff-item added">+ ${n.name || n.id} [${n.type}]</div>`).join('')}
            ${rn.map(n => `<div class="diff-item removed">- ${n.name || n.id} [${n.type}]</div>`).join('')}
            ${nn.length === 0 && rn.length === 0 ? '<div class="diff-item">No changes.</div>' : ''}
        </div>
        <div class="diff-section">
            <div class="diff-section-title">Edge Changes (+${ne.length} / -${re.length})</div>
            ${ne.slice(0, 8).map(e => `<div class="diff-item added">+ ${e.source} →[${e.relationship}]→ ${e.target}</div>`).join('')}
            ${re.slice(0, 8).map(e => `<div class="diff-item removed">- ${e.source} →[${e.relationship}]→ ${e.target}</div>`).join('')}
            ${ne.length === 0 && re.length === 0 ? '<div class="diff-item">No changes.</div>' : ''}
        </div>`;
}
