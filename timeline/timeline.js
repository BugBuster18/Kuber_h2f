/**
 * KubeAttackViz Timeline Visualizer
 * 
 * Interactive D3.js timeline with snapshot navigation, diff overlays,
 * auto-playback, and animated graph transitions.
 */

// ─── Configuration ─────────────────────────────────────────────────────────

const NODE_COLORS = {
    pod:              '#4A90D9',
    service:          '#2ECC71',
    serviceaccount:   '#E8833A',
    role:             '#9B59B6',
    clusterrole:      '#8E44AD',
    rolebinding:      '#F39C12',
    clusterrolebinding:'#E67E22',
    secret:           '#E74C3C',
    configmap:        '#F1C40F',
    database:         '#C0392B',
    namespace:        '#F39C12',
    node:             '#1ABC9C',
    deployment:       '#3498DB',
    ingress:          '#16A085',
};

const NODE_RADIUS = {
    pod: 8,
    service: 7,
    serviceaccount: 7,
    role: 6,
    clusterrole: 8,
    secret: 7,
    configmap: 5,
    database: 9,
    namespace: 6,
    node: 9,
    deployment: 7,
    ingress: 6,
};

// ─── State ─────────────────────────────────────────────────────────────────

let timelineData = null;
let currentSnapshotIndex = 0;
let isPlaying = false;
let playbackTimer = null;
let simulation = null;
let svg, g, width, height;
let nodeElements, edgeElements, labelElements;
let showLabels = true;
let showDiffOverlay = true;
let animateTransitions = true;

// ─── Initialization ────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initSVG();
    initEventListeners();
    tryAutoLoad();
});

function initSVG() {
    const container = document.getElementById('graph-container');
    svg = d3.select('#graph-svg');
    width = container.clientWidth;
    height = container.clientHeight;

    svg.attr('viewBox', [0, 0, width, height]);

    // Defs for markers and filters
    const defs = svg.append('defs');

    // Arrow marker
    defs.append('marker')
        .attr('id', 'arrowhead')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', 'rgba(255,255,255,0.3)');

    // Glow filter for added nodes
    const glowGreen = defs.append('filter').attr('id', 'glow-green');
    glowGreen.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'blur');
    glowGreen.append('feFlood').attr('flood-color', '#10b981').attr('flood-opacity', '0.6');
    glowGreen.append('feComposite').attr('in2', 'blur').attr('operator', 'in');
    glowGreen.append('feMerge')
        .selectAll('feMergeNode')
        .data(['', 'SourceGraphic'])
        .join('feMergeNode')
        .attr('in', d => d || null);

    // Glow filter for removed nodes
    const glowRed = defs.append('filter').attr('id', 'glow-red');
    glowRed.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'blur');
    glowRed.append('feFlood').attr('flood-color', '#ef4444').attr('flood-opacity', '0.6');
    glowRed.append('feComposite').attr('in2', 'blur').attr('operator', 'in');
    glowRed.append('feMerge')
        .selectAll('feMergeNode')
        .data(['', 'SourceGraphic'])
        .join('feMergeNode')
        .attr('in', d => d || null);

    // Zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.2, 5])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        });

    svg.call(zoom);
    g = svg.append('g');

    // Handle resize
    window.addEventListener('resize', () => {
        width = container.clientWidth;
        height = container.clientHeight;
        svg.attr('viewBox', [0, 0, width, height]);
        if (simulation) {
            simulation.force('center', d3.forceCenter(width / 2, height / 2));
            simulation.alpha(0.1).restart();
        }
    });
}

function initEventListeners() {
    // File drop zone
    const dropZone = document.getElementById('file-drop-zone');
    const fileInput = document.getElementById('file-input');

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) loadFile(file);
    });
    fileInput.addEventListener('change', (e) => {
        if (e.target.files[0]) loadFile(e.target.files[0]);
    });

    // Load demo button
    document.getElementById('btn-load-demo').addEventListener('click', () => {
        fetch('timeline-data.json')
            .then(r => r.json())
            .then(data => {
                timelineData = data;
                onDataLoaded();
            })
            .catch(err => {
                console.error('Failed to load timeline-data.json:', err);
                alert('Could not load timeline-data.json. Make sure it exists in this directory.');
            });
    });

    // Playback controls
    document.getElementById('btn-prev').addEventListener('click', prevSnapshot);
    document.getElementById('btn-next').addEventListener('click', nextSnapshot);
    document.getElementById('btn-play').addEventListener('click', togglePlayback);

    // Speed control
    const speedSlider = document.getElementById('playback-speed');
    const speedLabel = document.getElementById('speed-label');
    speedSlider.addEventListener('input', () => {
        speedLabel.textContent = (speedSlider.value / 1000).toFixed(1) + 's';
        if (isPlaying) {
            stopPlayback();
            startPlayback();
        }
    });

    // Display toggles
    document.getElementById('toggle-labels').addEventListener('change', (e) => {
        showLabels = e.target.checked;
        if (labelElements) {
            labelElements.style('display', showLabels ? 'block' : 'none');
        }
    });

    document.getElementById('toggle-diff-overlay').addEventListener('change', (e) => {
        showDiffOverlay = e.target.checked;
        renderSnapshot(currentSnapshotIndex);
    });

    document.getElementById('toggle-animate').addEventListener('change', (e) => {
        animateTransitions = e.target.checked;
    });

    // Close detail panel
    document.getElementById('btn-close-detail').addEventListener('click', () => {
        document.getElementById('detail-panel').classList.add('hidden');
    });
}

function tryAutoLoad() {
    fetch('timeline-data.json')
        .then(r => {
            if (!r.ok) throw new Error('Not found');
            return r.json();
        })
        .then(data => {
            timelineData = data;
            onDataLoaded();
        })
        .catch(() => {
            // No auto-load — user must load manually
        });
}

// ─── Data Loading ──────────────────────────────────────────────────────────

function loadFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            timelineData = JSON.parse(e.target.result);
            onDataLoaded();
        } catch (err) {
            alert('Invalid JSON file: ' + err.message);
        }
    };
    reader.readAsText(file);
}

function onDataLoaded() {
    if (!timelineData || !timelineData.snapshots || timelineData.snapshots.length === 0) {
        alert('No snapshots found in the timeline data.');
        return;
    }

    // Update header stats
    document.getElementById('snapshot-count').textContent = timelineData.snapshots.length;

    let totalChanges = 0;
    (timelineData.diffs || []).forEach(d => {
        totalChanges += (d.summary ? d.summary.total_changes : 0);
    });
    document.getElementById('total-changes').textContent = totalChanges;

    // Build timeline markers
    buildTimeline();

    // Build change cards
    buildChangeCards();

    // Render first snapshot
    currentSnapshotIndex = 0;
    renderSnapshot(0);
}

// ─── Timeline Builder ──────────────────────────────────────────────────────

function buildTimeline() {
    const markers = document.getElementById('timeline-markers');
    const labels = document.getElementById('timeline-labels');
    markers.innerHTML = '';
    labels.innerHTML = '';

    const snaps = timelineData.snapshots;
    if (snaps.length === 0) return;

    snaps.forEach((snap, i) => {
        const pct = snaps.length === 1 ? 50 : (i / (snaps.length - 1)) * 100;

        // Marker
        const marker = document.createElement('div');
        marker.className = 'timeline-marker';
        marker.style.left = pct + '%';
        marker.dataset.index = i;

        if (i === 0) marker.classList.add('active');

        // Check if this snapshot has changes from previous
        if (i > 0 && timelineData.diffs && timelineData.diffs[i - 1]) {
            const diff = timelineData.diffs[i - 1];
            if (diff.summary && diff.summary.total_changes > 0) {
                marker.classList.add('has-changes');
            }
        }

        const dot = document.createElement('div');
        dot.className = 'timeline-marker-dot';
        marker.appendChild(dot);

        // Tooltip
        const tooltip = document.createElement('div');
        tooltip.className = 'timeline-marker-tooltip';
        const time = formatTimestamp(snap.timestamp);
        const label = snap.label || `Snapshot ${i + 1}`;
        tooltip.innerHTML = `<strong>${label}</strong><br>${time}<br>${snap.metadata?.node_count || 0} nodes`;
        marker.appendChild(tooltip);

        marker.addEventListener('click', () => {
            currentSnapshotIndex = i;
            renderSnapshot(i);
            updateTimelineUI();
        });

        markers.appendChild(marker);
    });

    // Labels
    if (snaps.length >= 2) {
        const firstLabel = document.createElement('span');
        firstLabel.textContent = formatTimestamp(snaps[0].timestamp);
        labels.appendChild(firstLabel);

        const lastLabel = document.createElement('span');
        lastLabel.textContent = formatTimestamp(snaps[snaps.length - 1].timestamp);
        labels.appendChild(lastLabel);
    } else {
        const onlyLabel = document.createElement('span');
        onlyLabel.textContent = formatTimestamp(snaps[0].timestamp);
        labels.appendChild(onlyLabel);
    }
}

function updateTimelineUI() {
    const markers = document.querySelectorAll('.timeline-marker');
    markers.forEach((m, i) => {
        m.classList.toggle('active', i === currentSnapshotIndex);
    });

    // Update progress bar
    const snaps = timelineData.snapshots;
    const pct = snaps.length <= 1 ? 100 : (currentSnapshotIndex / (snaps.length - 1)) * 100;
    document.getElementById('timeline-progress').style.width = pct + '%';
}

// ─── Change Cards Builder ──────────────────────────────────────────────────

function buildChangeCards() {
    const list = document.getElementById('changes-list');
    list.innerHTML = '';

    if (!timelineData.diffs || timelineData.diffs.length === 0) {
        list.innerHTML = '<p class="placeholder">No diffs available (need 2+ snapshots).</p>';
        return;
    }

    timelineData.diffs.forEach((diff, i) => {
        if (!diff.summary || diff.summary.total_changes === 0) return;

        const card = document.createElement('div');
        card.className = 'change-card';
        card.dataset.diffIndex = i;

        const header = document.createElement('div');
        header.className = 'change-card-header';

        const title = document.createElement('span');
        title.className = 'change-card-title';
        title.textContent = diff.to_label || `Change ${i + 1}`;

        const time = document.createElement('span');
        time.className = 'change-card-time';
        time.textContent = formatTimestamp(diff.to_timestamp);

        header.appendChild(title);
        header.appendChild(time);
        card.appendChild(header);

        const badges = document.createElement('div');
        badges.className = 'change-badges';

        if (diff.summary.nodes_added > 0) {
            badges.appendChild(makeBadge(`+${diff.summary.nodes_added} nodes`, 'added'));
        }
        if (diff.summary.nodes_removed > 0) {
            badges.appendChild(makeBadge(`−${diff.summary.nodes_removed} nodes`, 'removed'));
        }
        if (diff.summary.edges_added > 0) {
            badges.appendChild(makeBadge(`+${diff.summary.edges_added} edges`, 'added'));
        }
        if (diff.summary.edges_removed > 0) {
            badges.appendChild(makeBadge(`−${diff.summary.edges_removed} edges`, 'removed'));
        }

        card.appendChild(badges);

        // Detail items
        const detailLimit = 4;
        const items = [];
        (diff.new_nodes || []).slice(0, detailLimit).forEach(n => {
            items.push({ text: `${n.name} [${n.type}]`, cls: 'added' });
        });
        (diff.removed_nodes || []).slice(0, detailLimit).forEach(n => {
            items.push({ text: `${n.name} [${n.type}]`, cls: 'removed' });
        });

        if (items.length > 0) {
            const detail = document.createElement('div');
            detail.className = 'change-detail';
            items.forEach(item => {
                const el = document.createElement('div');
                el.className = `change-detail-item ${item.cls}`;
                el.textContent = item.text;
                detail.appendChild(el);
            });
            card.appendChild(detail);
        }

        // Click to jump to this snapshot
        card.addEventListener('click', () => {
            currentSnapshotIndex = i + 1; // diff[i] = between snap[i] and snap[i+1]
            renderSnapshot(currentSnapshotIndex);
            updateTimelineUI();
        });

        list.appendChild(card);
    });

    if (list.children.length === 0) {
        list.innerHTML = '<p class="placeholder">No changes detected between snapshots.</p>';
    }
}

function makeBadge(text, cls) {
    const badge = document.createElement('span');
    badge.className = `change-badge ${cls}`;
    badge.textContent = text;
    return badge;
}

// ─── Snapshot Rendering ────────────────────────────────────────────────────

function renderSnapshot(index) {
    const snap = timelineData.snapshots[index];
    if (!snap) return;

    // Update header
    document.getElementById('current-nodes').textContent = snap.nodes.length;
    document.getElementById('current-edges').textContent = snap.edges.length;

    // Update snapshot info overlay
    const infoEl = document.getElementById('snapshot-info');
    infoEl.classList.remove('hidden');
    document.getElementById('snapshot-badge').textContent =
        `Snapshot ${index + 1}/${timelineData.snapshots.length}`;
    document.getElementById('snapshot-label').textContent =
        snap.label || '';
    document.getElementById('snapshot-time').textContent =
        formatTimestamp(snap.timestamp);

    // Get diff data for overlay
    let diff = null;
    if (showDiffOverlay && index > 0 && timelineData.diffs && timelineData.diffs[index - 1]) {
        diff = timelineData.diffs[index - 1];
    }

    renderGraph(snap, diff);
    updateTimelineUI();
}

function renderGraph(snap, diff) {
    // Prepare node/edge data
    const nodes = snap.nodes.map(n => ({
        ...n,
        id: n.id,
        radius: getNodeRadius(n),
        color: getNodeColor(n),
        diffStatus: getDiffStatus(n.id, diff, 'node'),
    }));

    const nodeIds = new Set(nodes.map(n => n.id));
    const edges = snap.edges
        .filter(e => nodeIds.has(e.source) && nodeIds.has(e.target))
        .map(e => ({
            ...e,
            source: e.source,
            target: e.target,
            diffStatus: getDiffStatusEdge(e, diff),
        }));

    // Clear
    g.selectAll('*').remove();

    // Create simulation
    if (simulation) simulation.stop();

    simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(edges).id(d => d.id).distance(80))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.radius + 4));

    // Edges
    edgeElements = g.append('g')
        .attr('class', 'edges')
        .selectAll('line')
        .data(edges)
        .join('line')
        .attr('class', d => {
            let cls = 'edge-line';
            if (d.diffStatus === 'added') cls += ' edge-added';
            if (d.diffStatus === 'removed') cls += ' edge-removed';
            return cls;
        })
        .attr('stroke', d => d.diffStatus === 'added' ? '#10b981' :
                          d.diffStatus === 'removed' ? '#ef4444' :
                          'rgba(255,255,255,0.15)')
        .attr('stroke-width', d => d.diffStatus ? 2 : 1)
        .attr('marker-end', 'url(#arrowhead)');

    // Nodes
    nodeElements = g.append('g')
        .attr('class', 'nodes')
        .selectAll('circle')
        .data(nodes)
        .join('circle')
        .attr('class', d => {
            let cls = 'node-circle';
            if (d.diffStatus === 'added') cls += ' node-added';
            if (d.diffStatus === 'removed') cls += ' node-removed';
            return cls;
        })
        .attr('r', d => d.radius)
        .attr('fill', d => d.color)
        .attr('stroke', d => {
            if (d.diffStatus === 'added') return '#10b981';
            if (d.diffStatus === 'removed') return '#ef4444';
            if (d.is_source) return '#2ECC71';
            if (d.is_sink) return '#E74C3C';
            return 'rgba(255,255,255,0.1)';
        })
        .attr('stroke-width', d => d.diffStatus ? 3 : (d.is_source || d.is_sink ? 2.5 : 1))
        .attr('filter', d => {
            if (d.diffStatus === 'added') return 'url(#glow-green)';
            if (d.diffStatus === 'removed') return 'url(#glow-red)';
            return null;
        })
        .call(drag(simulation))
        .on('mouseover', showTooltip)
        .on('mouseout', hideTooltip)
        .on('click', showNodeDetail);

    // Labels
    labelElements = g.append('g')
        .attr('class', 'labels')
        .selectAll('text')
        .data(nodes)
        .join('text')
        .attr('class', 'node-label')
        .attr('dy', d => d.radius + 14)
        .text(d => d.name)
        .style('display', showLabels ? 'block' : 'none');

    // Tick
    simulation.on('tick', () => {
        edgeElements
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        nodeElements
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);

        labelElements
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });
}

// ─── Diff Status Helpers ───────────────────────────────────────────────────

function getDiffStatus(nodeId, diff, type) {
    if (!diff) return null;
    if (diff.new_nodes && diff.new_nodes.some(n => n.id === nodeId)) return 'added';
    if (diff.removed_nodes && diff.removed_nodes.some(n => n.id === nodeId)) return 'removed';
    return null;
}

function getDiffStatusEdge(edge, diff) {
    if (!diff) return null;
    if (diff.new_edges && diff.new_edges.some(e =>
        e.source === edge.source && e.target === edge.target
    )) return 'added';
    if (diff.removed_edges && diff.removed_edges.some(e =>
        e.source === edge.source && e.target === edge.target
    )) return 'removed';
    return null;
}

// ─── Node Helpers ──────────────────────────────────────────────────────────

function getNodeColor(node) {
    const type = (node.type || '').toLowerCase();
    return NODE_COLORS[type] || '#95A5A6';
}

function getNodeRadius(node) {
    const type = (node.type || '').toLowerCase();
    let base = NODE_RADIUS[type] || 6;
    if (node.is_source || node.is_sink) base += 2;
    return base;
}

// ─── Drag Behavior ─────────────────────────────────────────────────────────

function drag(sim) {
    function dragstarted(event, d) {
        if (!event.active) sim.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    function dragended(event, d) {
        if (!event.active) sim.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
    return d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended);
}

// ─── Tooltip ───────────────────────────────────────────────────────────────

function showTooltip(event, d) {
    const tooltip = document.getElementById('tooltip');
    tooltip.classList.remove('hidden');

    document.getElementById('tooltip-name').textContent = d.name;
    document.getElementById('tooltip-type').textContent = d.type;
    document.getElementById('tooltip-namespace').textContent = d.namespace || '—';
    document.getElementById('tooltip-risk').textContent = (d.risk_score || 0).toFixed(1);

    let status = '—';
    if (d.diffStatus === 'added') status = '✅ Added';
    if (d.diffStatus === 'removed') status = '❌ Removed';
    if (d.is_source) status = '🟢 Source (Entry Point)';
    if (d.is_sink) status = '🔴 Sink (Target)';
    document.getElementById('tooltip-status').textContent = status;

    const container = document.getElementById('graph-container');
    const rect = container.getBoundingClientRect();
    tooltip.style.left = (event.clientX - rect.left + 16) + 'px';
    tooltip.style.top = (event.clientY - rect.top - 10) + 'px';
}

function hideTooltip() {
    document.getElementById('tooltip').classList.add('hidden');
}

// ─── Node Detail Panel ─────────────────────────────────────────────────────

function showNodeDetail(event, d) {
    const panel = document.getElementById('detail-panel');
    panel.classList.remove('hidden');

    document.getElementById('detail-title').textContent = d.name;

    const content = document.getElementById('detail-content');
    content.innerHTML = `
        <div style="margin-bottom: 16px;">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                <span style="width: 12px; height: 12px; border-radius: 50%; background: ${d.color};"></span>
                <span style="font-size: 13px; color: #9ca3af;">${d.type}</span>
            </div>
            <div style="font-size: 12px; color: #6b7280; margin-bottom: 4px;">
                Namespace: <span style="color: #f0f4ff;">${d.namespace || '—'}</span>
            </div>
            <div style="font-size: 12px; color: #6b7280; margin-bottom: 4px;">
                Risk Score: <span style="color: ${d.risk_score > 7 ? '#ef4444' : d.risk_score > 4 ? '#f59e0b' : '#10b981'}; font-weight: 600;">${(d.risk_score || 0).toFixed(1)}</span>
            </div>
            ${d.is_source ? '<div style="font-size: 12px; color: #10b981; margin-top: 6px;">🟢 Attack Entry Point</div>' : ''}
            ${d.is_sink ? '<div style="font-size: 12px; color: #ef4444; margin-top: 6px;">🔴 High-Value Target</div>' : ''}
            ${d.diffStatus === 'added' ? '<div style="font-size: 12px; color: #10b981; margin-top: 6px;">✅ Added in this snapshot</div>' : ''}
            ${d.diffStatus === 'removed' ? '<div style="font-size: 12px; color: #ef4444; margin-top: 6px;">❌ Removed in this snapshot</div>' : ''}
        </div>
        <div style="font-size: 12px; font-family: \'JetBrains Mono\', monospace; color: #6b7280; background: rgba(0,0,0,0.3); padding: 8px; border-radius: 6px; word-break: break-all;">
            ${d.id}
        </div>
    `;
}

// ─── Playback Controls ─────────────────────────────────────────────────────

function prevSnapshot() {
    if (!timelineData || timelineData.snapshots.length === 0) return;
    currentSnapshotIndex = Math.max(0, currentSnapshotIndex - 1);
    renderSnapshot(currentSnapshotIndex);
}

function nextSnapshot() {
    if (!timelineData || timelineData.snapshots.length === 0) return;
    currentSnapshotIndex = Math.min(
        timelineData.snapshots.length - 1,
        currentSnapshotIndex + 1
    );
    renderSnapshot(currentSnapshotIndex);
}

function togglePlayback() {
    if (isPlaying) {
        stopPlayback();
    } else {
        startPlayback();
    }
}

function startPlayback() {
    if (!timelineData || timelineData.snapshots.length <= 1) return;

    isPlaying = true;
    const btn = document.getElementById('btn-play');
    btn.classList.add('active');
    document.getElementById('play-icon').innerHTML =
        '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';

    const speed = parseInt(document.getElementById('playback-speed').value);

    function advance() {
        if (!isPlaying) return;
        currentSnapshotIndex++;
        if (currentSnapshotIndex >= timelineData.snapshots.length) {
            currentSnapshotIndex = 0; // Loop
        }
        renderSnapshot(currentSnapshotIndex);
        playbackTimer = setTimeout(advance, speed);
    }

    playbackTimer = setTimeout(advance, speed);
}

function stopPlayback() {
    isPlaying = false;
    if (playbackTimer) {
        clearTimeout(playbackTimer);
        playbackTimer = null;
    }
    const btn = document.getElementById('btn-play');
    btn.classList.remove('active');
    document.getElementById('play-icon').innerHTML = '<path d="M8 5v14l11-7z"/>';
}

// ─── Utilities ─────────────────────────────────────────────────────────────

function formatTimestamp(ts) {
    if (!ts) return '—';
    try {
        const d = new Date(ts);
        return d.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    } catch {
        return ts;
    }
}
