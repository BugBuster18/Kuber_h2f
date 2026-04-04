/**
 * KubeAttackViz — D3.js Force-Directed Attack Graph Visualization
 *
 * Renders the Kubernetes attack graph with:
 *   - Color-coded nodes by resource type
 *   - Animated attack path edges (red dashes)
 *   - Animated cycle edges (orange dashes)
 *   - Critical node highlighting (gold glow)
 *   - Hover tooltips with full metadata
 *   - Click-to-highlight reachable nodes
 *   - Toggle controls for paths, cycles, labels, critical nodes
 *   - Smooth force simulation tuned for 100+ nodes
 */

// ─── Constants ──────────────────────────────────────────────────────────────

const NODE_COLORS = {
    pod:                  '#4A90D9',
    service:              '#2ECC71',
    serviceaccount:       '#E8833A',
    role:                 '#9B59B6',
    clusterrole:          '#8E44AD',
    rolebinding:          '#F39C12',
    clusterrolebinding:   '#E67E22',
    secret:               '#E74C3C',
    configmap:            '#1ABC9C',
    database:             '#E74C3C',
    node:                 '#34495E',
    ingress:              '#3498DB',
};

const DEFAULT_NODE_COLOR = '#95A5A6';
const ATTACK_PATH_COLOR  = '#ff4757';
const CYCLE_EDGE_COLOR   = '#ffa502';
const CRITICAL_NODE_COLOR = '#FFD700';

const BASE_RADIUS     = 8;
const SOURCE_RADIUS   = 12;
const SINK_RADIUS     = 11;
const CRITICAL_RADIUS = 16;

// ─── State ──────────────────────────────────────────────────────────────────

let graphData      = null;
let simulation     = null;
let svg            = null;
let gMain          = null;
let linkGroup      = null;
let nodeGroup      = null;
let labelGroup     = null;
let activePathIdx  = null;
let selectedNode   = null;
let zoom           = null;

// Sets for efficient lookup
let attackPathEdges = new Set();
let cycleEdges      = new Set();
let criticalNodeIds = new Set();

// ─── Initialization ─────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initSVG();
    initControls();
});

function initSVG() {
    const container = document.getElementById('graph-container');
    svg = d3.select('#graph-svg');

    // Zoom & pan
    zoom = d3.zoom()
        .scaleExtent([0.1, 6])
        .wheelDelta(event => {
            // NORMALIZATION: Make wheel/trackpad zooming 3x smoother
            // We reduce the jump size on every scroll tick.
            return -event.deltaY * (event.deltaMode === 1 ? 0.05 : event.deltaMode === 2 ? 1 : 0.001) * (event.ctrlKey ? 10 : 1);
        })
        .on('zoom', (event) => {
            gMain.attr('transform', event.transform);
        });

    svg.call(zoom);

    gMain = svg.append('g').attr('class', 'main-group');

    // Arrow marker definitions
    const defs = svg.append('defs');

    // Default arrow
    defs.append('marker')
        .attr('id', 'arrowhead')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('markerWidth', 8)
        .attr('markerHeight', 8)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('class', 'arrowhead');

    // Attack path arrow
    defs.append('marker')
        .attr('id', 'arrowhead-attack')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('markerWidth', 8)
        .attr('markerHeight', 8)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('class', 'arrowhead attack-path-arrow');

    // Cycle arrow
    defs.append('marker')
        .attr('id', 'arrowhead-cycle')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('markerWidth', 8)
        .attr('markerHeight', 8)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('class', 'arrowhead cycle-arrow');

    // Glow filter for critical nodes
    const glowFilter = defs.append('filter')
        .attr('id', 'glow')
        .attr('x', '-50%')
        .attr('y', '-50%')
        .attr('width', '200%')
        .attr('height', '200%');

    glowFilter.append('feGaussianBlur')
        .attr('stdDeviation', '4')
        .attr('result', 'coloredBlur');

    const feMerge = glowFilter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    linkGroup  = gMain.append('g').attr('class', 'links');
    nodeGroup  = gMain.append('g').attr('class', 'nodes');
    labelGroup = gMain.append('g').attr('class', 'labels');
}

function initControls() {
    // File drop zone
    const dropZone  = document.getElementById('file-drop-zone');
    const fileInput = document.getElementById('file-input');

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) loadFile(file);
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files[0]) loadFile(e.target.files[0]);
    });

    // Demo button
    document.getElementById('btn-load-demo').addEventListener('click', loadDemoData);

    // Toggles
    document.getElementById('toggle-paths').addEventListener('change', updateVisibility);
    document.getElementById('toggle-cycles').addEventListener('change', updateVisibility);
    document.getElementById('toggle-labels').addEventListener('change', updateVisibility);
    document.getElementById('toggle-critical').addEventListener('change', updateVisibility);

    // Close detail panel
    document.getElementById('btn-close-detail').addEventListener('click', () => {
        document.getElementById('detail-panel').classList.add('hidden');
        clearHighlight();
    });

    // Zoom Buttons
    document.getElementById('btn-zoom-in').addEventListener('click', zoomIn);
    document.getElementById('btn-zoom-out').addEventListener('click', zoomOut);
    document.getElementById('btn-zoom-reset').addEventListener('click', resetZoom);
}

// ─── Data Loading ───────────────────────────────────────────────────────────

function loadFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const data = JSON.parse(e.target.result);
            loadGraphData(data);
        } catch (err) {
            alert('Invalid JSON file: ' + err.message);
        }
    };
    reader.readAsText(file);
}

async function loadDemoData() {
    try {
        const resp = await fetch('graph-data.json');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        loadGraphData(data);
    } catch (err) {
        alert('Could not load demo data. Run:\n  python main.py export-frontend --input mock-cluster-graph.json\nto generate visualizer/graph-data.json\n\nError: ' + err.message);
    }
}

function loadGraphData(data) {
    graphData = data;

    // Populate stats
    document.getElementById('node-count').textContent  = (data.nodes || []).length;
    document.getElementById('edge-count').textContent   = (data.edges || []).length;
    document.getElementById('path-count').textContent   = (data.attack_paths || []).length;
    document.getElementById('cycle-count').textContent   = (data.cycles || []).length;

    // Build lookup sets
    buildLookups(data);

    // Render path cards
    renderPathCards(data.attack_paths || []);

    // Render graph
    renderGraph(data);
}

function buildLookups(data) {
    attackPathEdges.clear();
    cycleEdges.clear();
    criticalNodeIds.clear();

    // Attack path edges
    for (const path of (data.attack_paths || [])) {
        const nodes = path.path_nodes || [];
        for (let i = 0; i < nodes.length - 1; i++) {
            attackPathEdges.add(`${nodes[i]}|${nodes[i + 1]}`);
        }
    }

    // Cycle edges
    for (const cycle of (data.cycles || [])) {
        const ids = cycle.node_ids || [];
        for (let i = 0; i < ids.length; i++) {
            const src = ids[i];
            const tgt = ids[(i + 1) % ids.length];
            cycleEdges.add(`${src}|${tgt}`);
        }
    }

    // Critical nodes
    if (data.critical_node && data.critical_node.top_nodes) {
        for (const n of data.critical_node.top_nodes) {
            criticalNodeIds.add(n.id);
        }
    }
}

// ─── Path Cards ─────────────────────────────────────────────────────────────

function renderPathCards(paths) {
    const list = document.getElementById('paths-list');
    list.innerHTML = '';

    if (paths.length === 0) {
        list.innerHTML = '<p class="placeholder">No attack paths detected.</p>';
        return;
    }

    paths.forEach((path, idx) => {
        const card = document.createElement('div');
        card.className = 'path-card';
        card.dataset.index = idx;

        const names = (path.path_names || []).join(' → ');
        const severity = path.severity || 'LOW';

        card.innerHTML = `
            <div class="path-card-header">
                <span class="path-card-title">Path #${idx + 1}</span>
                <span class="severity-badge severity-${severity}">${severity}</span>
            </div>
            <div class="path-card-route">${names}</div>
        `;

        card.addEventListener('click', () => togglePathHighlight(idx));
        list.appendChild(card);
    });
}

function togglePathHighlight(idx) {
    const cards = document.querySelectorAll('.path-card');

    if (activePathIdx === idx) {
        // Deselect
        activePathIdx = null;
        cards.forEach(c => c.classList.remove('active'));
        clearHighlight();
        return;
    }

    activePathIdx = idx;
    cards.forEach(c => c.classList.remove('active'));
    cards[idx].classList.add('active');

    // Highlight the specific path
    const path = graphData.attack_paths[idx];
    const pathNodeSet = new Set(path.path_nodes || []);
    const pathEdgeSet = new Set();
    const nodes = path.path_nodes || [];
    for (let i = 0; i < nodes.length - 1; i++) {
        pathEdgeSet.add(`${nodes[i]}|${nodes[i + 1]}`);
    }

    // Dim everything, then highlight path
    d3.selectAll('.node-circle')
        .classed('dimmed', d => !pathNodeSet.has(d.id));
    d3.selectAll('.node-label')
        .classed('dimmed', d => !pathNodeSet.has(d.id));
    d3.selectAll('.link-line')
        .classed('dimmed', d => !pathEdgeSet.has(`${d.source.id || d.source}|${d.target.id || d.target}`));
}

function clearHighlight() {
    activePathIdx = null;
    d3.selectAll('.dimmed').classed('dimmed', false);
    document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
}

// ─── Graph Rendering ────────────────────────────────────────────────────────

function renderGraph(data) {
    const width  = document.getElementById('graph-container').clientWidth;
    const height = document.getElementById('graph-container').clientHeight;

    // Clear previous
    linkGroup.selectAll('*').remove();
    nodeGroup.selectAll('*').remove();
    labelGroup.selectAll('*').remove();

    if (simulation) simulation.stop();

    const nodes = data.nodes.map(d => ({ ...d }));
    const edges = data.edges.map(d => ({ ...d }));

    // ── Force Simulation ────────────────────────────────────────────────────
    simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(edges)
            .id(d => d.id)
            .distance(d => 80 + (d.weight || 1) * 10)
            .strength(0.4)
        )
        .force('charge', d3.forceManyBody()
            .strength(-300)
            .distanceMax(500)
        )
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(25))
        .force('x', d3.forceX(width / 2).strength(0.05))
        .force('y', d3.forceY(height / 2).strength(0.05))
        .alphaDecay(0.02)
        .velocityDecay(0.4);

    // ── Edges ───────────────────────────────────────────────────────────────
    const links = linkGroup.selectAll('line')
        .data(edges)
        .enter()
        .append('line')
        .attr('class', d => {
            const key = `${d.source.id || d.source}|${d.target.id || d.target}`;
            let cls = 'link-line';
            if (attackPathEdges.has(key)) cls += ' attack-path-edge';
            if (cycleEdges.has(key)) cls += ' cycle-edge';
            return cls;
        })
        .attr('marker-end', d => {
            const key = `${d.source.id || d.source}|${d.target.id || d.target}`;
            if (attackPathEdges.has(key)) return 'url(#arrowhead-attack)';
            if (cycleEdges.has(key)) return 'url(#arrowhead-cycle)';
            return 'url(#arrowhead)';
        });

    // ── Nodes ───────────────────────────────────────────────────────────────
    const circles = nodeGroup.selectAll('circle')
        .data(nodes)
        .enter()
        .append('circle')
        .attr('class', d => {
            let cls = 'node-circle';
            if (d.is_source) cls += ' source-node';
            if (d.is_sink) cls += ' sink-node';
            if (criticalNodeIds.has(d.id)) cls += ' critical-node';
            return cls;
        })
        .attr('r', d => getNodeRadius(d))
        .attr('fill', d => NODE_COLORS[d.type] || DEFAULT_NODE_COLOR)
        .attr('stroke', d => {
            if (criticalNodeIds.has(d.id)) return CRITICAL_NODE_COLOR;
            if (d.is_source) return '#3FB950';
            if (d.is_sink) return '#F85149';
            return 'rgba(255,255,255,0.15)';
        })
        .style('filter', d => criticalNodeIds.has(d.id) ? 'url(#glow)' : 'none')
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded)
        )
        .on('mouseover', showTooltip)
        .on('mousemove', moveTooltip)
        .on('mouseout', hideTooltip)
        .on('click', onNodeClick);

    // ── Labels ──────────────────────────────────────────────────────────────
    const labels = labelGroup.selectAll('text')
        .data(nodes)
        .enter()
        .append('text')
        .attr('class', 'node-label')
        .attr('dy', d => getNodeRadius(d) + 14)
        .text(d => d.name);

    // ── Tick ────────────────────────────────────────────────────────────────
    simulation.on('tick', () => {
        links
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        circles
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);

        labels
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });

    // Initial visibility
    updateVisibility();

    // Smooth entry: Zoom to fit after a small delay to allow for positioning
    setTimeout(zoomToFit, 100);
}

// ─── Smooth Zoom Logic ──────────────────────────────────────────────────────

function zoomIn() {
    svg.transition()
        .duration(350)
        .call(zoom.scaleBy, 1.4);
}

function zoomOut() {
    svg.transition()
        .duration(350)
        .call(zoom.scaleBy, 0.7);
}

function resetZoom() {
    zoomToFit();
}

function zoomToFit() {
    if (!graphData || !graphData.nodes) return;
    
    const bounds = gMain.node().getBBox();
    const parent = svg.node();
    const fullWidth = parent.clientWidth;
    const fullHeight = parent.clientHeight;
    
    const width = bounds.width;
    const height = bounds.height;
    const midX = bounds.x + width / 2;
    const midY = bounds.y + height / 2;
    
    if (width === 0 || height === 0) return;
    
    const scale = 0.85 / Math.max(width / fullWidth, height / fullHeight);
    const translate = [fullWidth / 2 - scale * midX, fullHeight / 2 - scale * midY];

    svg.transition()
        .duration(750)
        .ease(d3.easeCubicInOut)
        .call(zoom.transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale));
}

function getNodeRadius(d) {
    if (criticalNodeIds.has(d.id)) return CRITICAL_RADIUS;
    if (d.is_source) return SOURCE_RADIUS;
    if (d.is_sink) return SINK_RADIUS;
    return BASE_RADIUS;
}

// ─── Drag Handlers ──────────────────────────────────────────────────────────

function dragStarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragEnded(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

// ─── Tooltip ────────────────────────────────────────────────────────────────

function showTooltip(event, d) {
    const tooltip = document.getElementById('tooltip');
    tooltip.classList.remove('hidden');

    document.getElementById('tooltip-name').textContent      = d.name;
    document.getElementById('tooltip-type').textContent       = d.type;
    document.getElementById('tooltip-namespace').textContent  = d.namespace || '—';
    document.getElementById('tooltip-risk').textContent       = (d.risk_score || 0).toFixed(1);
    document.getElementById('tooltip-cves').textContent       = (d.cves && d.cves.length > 0) ? d.cves.join(', ') : 'None';

    let role = [];
    if (d.is_source) role.push('🟢 Source');
    if (d.is_sink) role.push('🔴 Sink');
    if (criticalNodeIds.has(d.id)) role.push('⭐ Critical');
    document.getElementById('tooltip-role').textContent = role.length > 0 ? role.join(', ') : 'Intermediate';
}

function moveTooltip(event) {
    const tooltip = document.getElementById('tooltip');
    const rect = document.getElementById('graph-container').getBoundingClientRect();
    let x = event.clientX - rect.left + 15;
    let y = event.clientY - rect.top + 15;

    // Prevent overflow
    if (x + 250 > rect.width) x = event.clientX - rect.left - 250;
    if (y + 180 > rect.height) y = event.clientY - rect.top - 180;

    tooltip.style.left = x + 'px';
    tooltip.style.top  = y + 'px';
}

function hideTooltip() {
    document.getElementById('tooltip').classList.add('hidden');
}

// ─── Node Click — Highlight Reachable ───────────────────────────────────────

function onNodeClick(event, d) {
    event.stopPropagation();

    if (selectedNode === d.id) {
        selectedNode = null;
        clearHighlight();
        document.getElementById('detail-panel').classList.add('hidden');
        return;
    }

    selectedNode = d.id;
    clearHighlight();

    // Find reachable nodes (BFS in edge data)
    const reachable = bfsReachable(d.id);
    reachable.add(d.id);

    // Dim non-reachable
    d3.selectAll('.node-circle')
        .classed('dimmed', n => !reachable.has(n.id));
    d3.selectAll('.node-label')
        .classed('dimmed', n => !reachable.has(n.id));
    d3.selectAll('.link-line')
        .classed('dimmed', e => {
            const srcId = e.source.id || e.source;
            return !reachable.has(srcId);
        });

    // Show detail panel
    showDetailPanel(d);
}

function bfsReachable(startId) {
    const visited = new Set();
    const queue = [startId];
    visited.add(startId);

    const adjList = {};
    for (const edge of (graphData.edges || [])) {
        if (!adjList[edge.source]) adjList[edge.source] = [];
        adjList[edge.source].push(edge.target);
    }

    while (queue.length > 0) {
        const current = queue.shift();
        for (const neighbor of (adjList[current] || [])) {
            if (!visited.has(neighbor)) {
                visited.add(neighbor);
                queue.push(neighbor);
            }
        }
    }

    return visited;
}

// ─── Detail Panel ───────────────────────────────────────────────────────────

function showDetailPanel(d) {
    const panel   = document.getElementById('detail-panel');
    const title   = document.getElementById('detail-title');
    const content = document.getElementById('detail-content');

    panel.classList.remove('hidden');
    title.textContent = d.name;

    const isCritical = criticalNodeIds.has(d.id);
    let criticalInfo = '';
    if (isCritical && graphData.critical_node) {
        const cn = graphData.critical_node.top_nodes.find(n => n.id === d.id);
        if (cn) {
            criticalInfo = `
                <div class="detail-section">
                    <div class="detail-section-title">⭐ Critical Node Impact</div>
                    <div class="detail-row">
                        <span class="detail-row-key">Paths Eliminated</span>
                        <span class="detail-row-value" style="color: var(--accent-gold)">${cn.paths_eliminated} / ${graphData.critical_node.baseline_paths}</span>
                    </div>
                </div>
            `;
        }
    }

    // Find edges from this node
    const outEdges = (graphData.edges || []).filter(e => e.source === d.id);
    const inEdges  = (graphData.edges || []).filter(e => e.target === d.id);

    // Find paths through this node
    const pathsThrough = (graphData.attack_paths || []).filter(
        p => (p.path_nodes || []).includes(d.id)
    );

    const riskPct = Math.min((d.risk_score / 10) * 100, 100);
    const riskColor = d.risk_score > 7 ? 'var(--accent-red)' :
                      d.risk_score > 4 ? 'var(--accent-orange)' : 'var(--accent-green)';

    content.innerHTML = `
        <div class="detail-section">
            <div class="detail-section-title">Properties</div>
            <div class="detail-row">
                <span class="detail-row-key">Type</span>
                <span class="detail-row-value">${d.type}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-key">Namespace</span>
                <span class="detail-row-value">${d.namespace || '—'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-key">ID</span>
                <span class="detail-row-value" style="font-size:0.72rem; word-break:break-all">${d.id}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-key">Risk Score</span>
                <span class="detail-row-value" style="color:${riskColor}">${d.risk_score.toFixed(1)} / 10</span>
            </div>
            <div class="risk-bar">
                <div class="risk-bar-fill" style="width:${riskPct}%; background:${riskColor}"></div>
            </div>
            <div class="detail-row">
                <span class="detail-row-key">Role</span>
                <span class="detail-row-value">${d.is_source ? '🟢 Source' : ''} ${d.is_sink ? '🔴 Sink' : ''} ${!d.is_source && !d.is_sink ? 'Intermediate' : ''}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-key">CVEs</span>
                <span class="detail-row-value">${d.cves && d.cves.length > 0 ? d.cves.join(', ') : 'None'}</span>
            </div>
        </div>

        ${criticalInfo}

        <div class="detail-section">
            <div class="detail-section-title">Connections (${outEdges.length} out, ${inEdges.length} in)</div>
            <ul class="detail-list">
                ${outEdges.map(e => {
                    const targetNode = graphData.nodes.find(n => n.id === e.target);
                    const targetName = targetNode ? targetNode.name : e.target;
                    return `<li><strong>→ ${targetName}</strong> (${e.relationship})</li>`;
                }).join('')}
                ${inEdges.map(e => {
                    const sourceNode = graphData.nodes.find(n => n.id === e.source);
                    const sourceName = sourceNode ? sourceNode.name : e.source;
                    return `<li><strong>← ${sourceName}</strong> (${e.relationship})</li>`;
                }).join('')}
            </ul>
        </div>

        <div class="detail-section">
            <div class="detail-section-title">Attack Paths Through (${pathsThrough.length})</div>
            <ul class="detail-list">
                ${pathsThrough.map((p, i) => {
                    const names = (p.path_names || []).join(' → ');
                    return `<li><span class="severity-badge severity-${p.severity}" style="margin-right:6px">${p.severity}</span> ${names}</li>`;
                }).join('') || '<li>No attack paths pass through this node.</li>'}
            </ul>
        </div>
    `;
}

// ─── Toggle Visibility ──────────────────────────────────────────────────────

function updateVisibility() {
    const showPaths    = document.getElementById('toggle-paths').checked;
    const showCycles   = document.getElementById('toggle-cycles').checked;
    const showLabels   = document.getElementById('toggle-labels').checked;
    const showCritical = document.getElementById('toggle-critical').checked;

    // Attack path edges
    d3.selectAll('.attack-path-edge')
        .style('visibility', showPaths ? 'visible' : 'hidden');

    // Cycle edges
    d3.selectAll('.cycle-edge')
        .style('visibility', showCycles ? 'visible' : 'hidden');

    // Labels
    d3.selectAll('.node-label')
        .style('display', showLabels ? 'block' : 'none');

    // Critical node styling
    d3.selectAll('.critical-node')
        .style('filter', showCritical ? 'url(#glow)' : 'none')
        .attr('stroke', d => {
            if (!showCritical && criticalNodeIds.has(d.id)) return 'rgba(255,255,255,0.15)';
            if (criticalNodeIds.has(d.id)) return CRITICAL_NODE_COLOR;
            if (d.is_source) return '#3FB950';
            if (d.is_sink) return '#F85149';
            return 'rgba(255,255,255,0.15)';
        })
        .attr('r', d => {
            if (!showCritical && criticalNodeIds.has(d.id)) return BASE_RADIUS;
            return getNodeRadius(d);
        });
}

// ─── SVG Click to deselect ──────────────────────────────────────────────────

document.addEventListener('click', (e) => {
    if (e.target.id === 'graph-svg' || e.target.closest('#graph-svg') === document.getElementById('graph-svg')) {
        if (e.target.tagName !== 'circle') {
            clearHighlight();
            selectedNode = null;
        }
    }
});
