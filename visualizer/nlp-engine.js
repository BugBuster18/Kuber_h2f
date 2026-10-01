/**
 * KubeAttackViz — Client-Side NLP Security Reasoning Engine
 *
 * Translates attack graph paths, blast radiuses, and critical chokepoints
 * into deep, plain-English security narratives for both technical teams
 * and non-technical stakeholders ("Think Longer" deep analysis).
 */

const NLP_REL_VERBS = {
    'runs_as': 'authenticates as the identity of',
    'binds_to': 'is bound via role binding to',
    'grants': 'grants elevated permissions through',
    'accesses': 'has network access to',
    'mounts': 'has directly mounted into its filesystem',
    'exposes': 'publicly or internally exposes',
    'connects_to': 'establishes an outbound network connection to',
    'uses': 'consumes configuration data from',
    'escalates_to': 'escalates privileges directly to',
    'has_secret': 'contains credential tokens for',
    'reads': 'can read sensitive secrets from',
    'writes': 'has permission to overwrite data in',
};

const NLP_TYPE_ARTICLES = {
    'pod': 'the pod',
    'service': 'the service',
    'serviceaccount': 'the ServiceAccount',
    'role': 'the RBAC Role',
    'clusterrole': 'the cluster-wide ClusterRole',
    'rolebinding': 'the RoleBinding',
    'clusterrolebinding': 'the ClusterRoleBinding',
    'secret': 'the sensitive Secret',
    'configmap': 'the ConfigMap',
    'database': 'the database backend',
    'node': 'the Kubernetes worker node',
    'ingress': 'the public Ingress controller',
};

function getNlpArticle(type) {
    return NLP_TYPE_ARTICLES[type?.toLowerCase()] || `the ${type || 'resource'}`;
}

function getNlpVerb(rel) {
    return NLP_REL_VERBS[rel] || `has a '${rel}' relationship with`;
}

// ─── Core NLP Explanation Generators ────────────────────────────────────────

/**
 * Generates an in-depth security narrative for an Attack Path ("Think Longer").
 */
function explainAttackPathNLP(path, graphData) {
    if (!path) return null;

    const pathNodes = path.path_nodes || [];
    const pathNames = path.path_names || [];
    const rels = path.relationships || [];
    const cves = path.cves || [];
    const cvss = path.cvss_scores || [];
    const hopCount = path.hop_count || (pathNodes.length - 1);
    const severity = path.severity || 'LOW';
    const totalRisk = (path.total_risk || 0).toFixed(2);
    const categories = (path.categories || []).length > 0 ? path.categories.join(', ') : 'Privilege Escalation & Lateral Movement';

    const sourceName = pathNames[0] || 'Entrypoint';
    const targetName = pathNames[pathNames.length - 1] || 'Target';

    const sourceNode = (graphData?.nodes || []).find(n => n.id === pathNodes[0]);
    const targetNode = (graphData?.nodes || []).find(n => n.id === pathNodes[pathNodes.length - 1]);

    const sourceType = sourceNode?.type || 'pod';
    const targetType = targetNode?.type || 'database';

    // 1. Executive Summary
    const executiveSummary = `An attacker who secures an initial foothold in ${getNlpArticle(sourceType)} <strong>"${sourceName}"</strong> can systematically traverse the cluster to compromise ${getNlpArticle(targetType)} <strong>"${targetName}"</strong> within <strong>${hopCount} hop(s)</strong>. This attack chain is rated <strong>${severity}</strong> severity (Risk Score: ${totalRisk}) and represents an active threat to cluster integrity and data confidentiality.`;

    // 2. Step-by-Step Traversal Breakdown
    const steps = [];
    for (let i = 0; i < rels.length; i++) {
        const uId = pathNodes[i];
        const vId = pathNodes[i + 1];
        const uName = pathNames[i];
        const vName = pathNames[i + 1];
        const uNode = (graphData?.nodes || []).find(n => n.id === uId);
        const vNode = (graphData?.nodes || []).find(n => n.id === vId);
        const uType = uNode?.type || 'resource';
        const vType = vNode?.type || 'resource';
        const verb = getNlpVerb(rels[i]);
        const cve = cves[i];
        const cveScore = cvss[i];

        let hopDetail = `<strong>Hop ${i + 1}:</strong> ${getNlpArticle(uType)} <em>"${uName}"</em> ${verb} ${getNlpArticle(vType)} <em>"${vName}"</em>.`;
        if (cve) {
            hopDetail += ` <span class="nlp-cve-pill">⚠ Exploits ${cve} ${cveScore ? `(CVSS ${cveScore.toFixed(1)})` : ''}</span>`;
        }
        steps.push({
            stepNum: i + 1,
            from: uName,
            to: vName,
            rel: rels[i],
            text: hopDetail,
            cve: cve,
            cvss: cveScore
        });
    }

    // 3. Technical Reasoning ("Think Longer")
    const reasoningPoints = [];

    // Check for ServiceAccount / RBAC escalation
    const hasSA = pathNodes.some((id, idx) => {
        const n = (graphData?.nodes || []).find(x => x.id === id);
        return n && (n.type === 'serviceaccount' || n.type === 'rolebinding' || n.type === 'clusterrolebinding');
    });
    if (hasSA) {
        reasoningPoints.push(`<strong>Identity Hijacking:</strong> The attack chain leverages overprivileged Kubernetes identities or role bindings, allowing the attacker to assume cluster authorization tokens and circumvent pod boundary isolation.`);
    }

    // Check for Secret exposure
    const hasSecret = pathNodes.some(id => {
        const n = (graphData?.nodes || []).find(x => x.id === id);
        return n && (n.type === 'secret' || n.type === 'configmap');
    });
    if (hasSecret) {
        reasoningPoints.push(`<strong>Credential Harvesting:</strong> Static credentials or configuration secrets are stored in cleartext or mounted without least-privilege scoping, providing lateral bridge credentials to downstream storage.`);
    }

    // Check for CVE involvement
    const activeCves = cves.filter(Boolean);
    if (activeCves.length > 0) {
        reasoningPoints.push(`<strong>Known Vulnerability Exploitation:</strong> Intermediate components contain publicly known CVEs (${activeCves.join(', ')}). Remote code execution or privilege escalation exploits exist that simplify traversal.`);
    } else {
        reasoningPoints.push(`<strong>Misconfiguration Over Vulnerabilities:</strong> This attack path requires zero zero-day exploits. It succeeds purely by abusing legitimate architectural connections and overly permissive Kubernetes RBAC configurations.`);
    }

    // 4. Concrete Remediation Recommendations
    const remediations = [];
    if (hasSA) {
        remediations.push(`Set <code>automountServiceAccountToken: false</code> on pods that do not require cluster API communication.`);
        remediations.push(`Audit RoleBindings associated with this chain and prune wildcard verbs (<code>*</code>) to strict, minimal read-only verbs.`);
    }
    if (hasSecret) {
        remediations.push(`Migrate static Kubernetes Secrets to a dedicated secrets manager (e.g. HashiCorp Vault or AWS Secrets Manager) with short-lived STS tokens.`);
    }
    remediations.push(`Enforce a default-deny Kubernetes <code>NetworkPolicy</code> to sever lateral ingress between <em>"${sourceName}"</em> and downstream namespaces.`);
    if (activeCves.length > 0) {
        remediations.push(`Patch container base images for vulnerable workloads to resolve CVEs ${activeCves.join(', ')}.`);
    }

    return {
        title: `Attack Path Narrative: ${sourceName} → ${targetName}`,
        severity,
        totalRisk,
        hopCount,
        categories,
        sourceName,
        targetName,
        executiveSummary,
        steps,
        reasoningPoints,
        remediations,
        pathNodes,
    };
}

/**
 * Generates an in-depth explanation for Critical Chokepoints.
 */
function explainCriticalNodeNLP(cnData, graphData) {
    if (!cnData || !cnData.top_nodes || cnData.top_nodes.length === 0) {
        return {
            title: 'Critical Chokepoint Analysis',
            summary: 'No critical bottleneck nodes were identified in this cluster topology.',
            details: []
        };
    }

    const top = cnData.top_nodes[0];
    const baseline = cnData.baseline_paths || 1;
    const pct = ((top.paths_eliminated / baseline) * 100).toFixed(1);
    const nodeObj = (graphData?.nodes || []).find(n => n.id === top.id);
    const nodeType = nodeObj?.type || 'resource';

    const executiveSummary = `The primary security chokepoint in this cluster is ${getNlpArticle(nodeType)} <strong>"${top.name}"</strong>. Hardening or isolating this single asset eliminates <strong>${top.paths_eliminated} out of ${baseline} total attack paths (${pct}%)</strong> across the entire cluster.`;

    const reasoning = [
        `<strong>High Return on Mitigation:</strong> Because "${top.name}" sits at the intersection of multiple ingress corridors, remediation here breaks the kill chain for the majority of external threats simultaneously.`,
        `<strong>Centralized Transit Hub:</strong> This resource functions as a transitive bridge. Rather than attempting to patch every edge workload, severing permissions at this junction collapses downstream lateral attack vectors.`
    ];

    const secondary = (cnData.top_nodes.slice(1) || []).map(n => ({
        name: n.name,
        eliminated: n.paths_eliminated,
        pct: ((n.paths_eliminated / baseline) * 100).toFixed(1)
    }));

    return {
        title: `Critical Chokepoint: ${top.name}`,
        executiveSummary,
        reasoning,
        secondary,
        topNodeId: top.id,
        remediations: [
            `Audit all incoming edges and RBAC bindings connected to "${top.name}".`,
            `Split responsibilities: replace monolithic roles with namespace-scoped, single-purpose service accounts.`,
            `Apply admission control rules (OPA Gatekeeper / Kyverno) to prevent pods from binding directly to this identity.`
        ]
    };
}

/**
 * Generates an in-depth explanation of Blast Radius for a given source node.
 */
function explainBlastRadiusNLP(sourceNodeId, graphData) {
    const blastList = graphData?.blast_radius || [];
    let entry = blastList.find(b => b.source === sourceNodeId || b.source_name === sourceNodeId);

    if (!entry && blastList.length > 0) {
        entry = blastList[0];
    }
    if (!entry) return null;

    const sourceName = entry.source_name || entry.source;
    const totalAffected = entry.total_affected;
    const maxDepth = entry.max_depth || 3;
    const layers = entry.layers || {};

    const executiveSummary = `If <strong>"${sourceName}"</strong> is compromised by an adversary, the immediate potential blast radius encompasses <strong>${totalAffected} cluster resources</strong> within ${maxDepth} network and privilege hops.`;

    const layerBreakdown = Object.keys(layers).map(k => {
        const nodes = layers[k] || [];
        return {
            depth: k,
            count: nodes.length,
            names: nodes.slice(0, 5).join(', ') + (nodes.length > 5 ? ` (+${nodes.length - 5} more)` : '')
        };
    });

    return {
        title: `Blast Radius Assessment: ${sourceName}`,
        executiveSummary,
        totalAffected,
        maxDepth,
        layerBreakdown,
        sourceNodeId: entry.source,
        remediations: [
            `Deploy zero-trust network policies restricting egress from "${sourceName}" to strictly required endpoints.`,
            `Enforce read-only root filesystems and drop <code>ALL</code> Linux capabilities on container specs for this workload.`,
            `Continuously monitor API server audit logs for anomalous outbound calls originating from this pod's identity.`
        ]
    };
}

// ─── Natural Language Query Parser ──────────────────────────────────────────

/**
 * Parses user input in plain English and matches intent with graph data.
 */
function parseNaturalLanguageQuery(query, graphData) {
    if (!query || !query.trim() || !graphData) return null;

    const q = query.toLowerCase().trim();
    const nodes = graphData.nodes || [];
    const attackPaths = graphData.attack_paths || [];

    // Helper: fuzzy search node name
    function findNodeMatch(str) {
        return nodes.find(n => {
            const name = (n.name || '').toLowerCase();
            const id = (n.id || '').toLowerCase();
            return str.includes(name) || str.includes(id) || name.includes(str);
        });
    }

    // 1. Critical Chokepoint Intent
    if (q.includes('chokepoint') || q.includes('bottleneck') || q.includes('critical node') || q.includes('most critical')) {
        const explanation = explainCriticalNodeNLP(graphData.critical_node, graphData);
        return {
            type: 'critical_node',
            data: explanation,
            highlightNodeId: explanation.topNodeId
        };
    }

    // 2. Cycles / Lateral Movement Intent
    if (q.includes('cycle') || q.includes('loop') || q.includes('lateral movement') || q.includes('circular')) {
        const cycles = graphData.cycles || [];
        if (cycles.length === 0) {
            return {
                type: 'generic_message',
                title: 'Cycle Analysis',
                text: 'No circular lateral movement paths were found in this cluster snapshot.'
            };
        }
        const firstCycle = cycles[0];
        const cycleNames = (firstCycle.node_names || []).join(' ➔ ');
        return {
            type: 'cycle',
            title: `Lateral Movement Loop Detected (${cycles.length} found)`,
            cycleNames,
            cycleNodes: firstCycle.node_ids || [],
            executiveSummary: `An attacker can move laterally in a loop through: <strong>${cycleNames}</strong>. This allows persistent lateral mobility without triggering typical boundary alarms.`,
            remediations: [
                'Break circular trust relationships between ServiceAccounts and workloads.',
                'Disallow bidirectional network ingress between these tiers using NetworkPolicies.'
            ]
        };
    }

    // 3. Blast Radius Intent
    if (q.includes('blast') || q.includes('radius') || q.includes('impact of') || q.includes('if compromised')) {
        // Try to find if a specific node was mentioned
        let matchedNode = null;
        for (const n of nodes) {
            if (q.includes((n.name || '').toLowerCase())) {
                matchedNode = n;
                break;
            }
        }
        const explanation = explainBlastRadiusNLP(matchedNode ? matchedNode.id : null, graphData);
        if (explanation) {
            return {
                type: 'blast_radius',
                data: explanation,
                highlightNodeId: explanation.sourceNodeId
            };
        }
    }

    // 4. CVE / Vulnerability Intent
    if (q.includes('cve') || q.includes('vulnerab') || q.includes('exploit') || q.includes('cvss')) {
        const pathWithCve = attackPaths.find(p => (p.cves || []).some(Boolean));
        if (pathWithCve) {
            const explanation = explainAttackPathNLP(pathWithCve, graphData);
            return {
                type: 'attack_path',
                data: explanation,
                highlightPath: pathWithCve
            };
        }
    }

    // 5. Source → Target or Reachability Intent
    // e.g. "path from web-frontend to prod-database" or "how to reach database" or "how can frontend compromise db"
    let targetCandidate = null;
    let sourceCandidate = null;

    // Look for target indicator keywords
    if (q.includes('to ') || q.includes('reach ') || q.includes('compromise ') || q.includes('target ')) {
        // Search nodes
        for (const n of nodes) {
            const name = (n.name || '').toLowerCase();
            if (name && q.includes(name)) {
                if (!targetCandidate && (n.is_sink || n.type === 'database' || n.type === 'secret')) {
                    targetCandidate = n;
                } else if (!sourceCandidate) {
                    sourceCandidate = n;
                }
            }
        }
    }

    // Search attack paths matching candidates
    let bestPath = null;
    if (targetCandidate && sourceCandidate) {
        bestPath = attackPaths.find(p => {
            const pNodes = p.path_nodes || [];
            return pNodes[0] === sourceCandidate.id && pNodes[pNodes.length - 1] === targetCandidate.id;
        });
    }

    if (!bestPath && targetCandidate) {
        bestPath = attackPaths.find(p => {
            const pNodes = p.path_nodes || [];
            return pNodes[pNodes.length - 1] === targetCandidate.id;
        });
    }

    if (!bestPath && sourceCandidate) {
        bestPath = attackPaths.find(p => {
            const pNodes = p.path_nodes || [];
            return pNodes[0] === sourceCandidate.id;
        });
    }

    // Fallback: check if any path contains any mentioned keyword
    if (!bestPath) {
        for (const p of attackPaths) {
            const joinedNames = (p.path_names || []).join(' ').toLowerCase();
            if (joinedNames.split(' ').some(part => part.length > 3 && q.includes(part))) {
                bestPath = p;
                break;
            }
        }
    }

    // If still no path, pick the highest risk or first path
    if (!bestPath && attackPaths.length > 0) {
        bestPath = attackPaths[0];
    }

    if (bestPath) {
        const explanation = explainAttackPathNLP(bestPath, graphData);
        return {
            type: 'attack_path',
            data: explanation,
            highlightPath: bestPath
        };
    }

    return {
        type: 'generic_message',
        title: 'Query Assistance',
        text: `We analyzed your query "${query}", but could not correlate it with an active path. Try searching for specific workloads like <strong>"web-frontend"</strong>, <strong>"prod-database"</strong>, or ask <strong>"What are the critical chokepoints?"</strong>`
    };
}

// ─── Modal / Drawer UI Controller ───────────────────────────────────────────

function openNlpExplanationModal(result) {
    let modal = document.getElementById('nlp-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'nlp-modal';
        modal.className = 'nlp-modal-backdrop hidden';
        modal.innerHTML = `
            <div class="nlp-modal-card">
                <div class="nlp-modal-header">
                    <div class="nlp-modal-title-group">
                        <span class="nlp-badge-orange">Security Reasoning</span>
                        <h3 id="nlp-modal-title" class="nlp-modal-title"></h3>
                    </div>
                    <button id="nlp-modal-close" class="btn-close" aria-label="Close">&times;</button>
                </div>
                <div class="nlp-modal-body" id="nlp-modal-content"></div>
                <div class="nlp-modal-footer">
                    <button class="btn btn-outline" id="nlp-btn-highlight">Focus on Graph</button>
                    <button class="btn btn-primary" id="nlp-btn-dismiss">Close</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        document.getElementById('nlp-modal-close').addEventListener('click', closeNlpModal);
        document.getElementById('nlp-btn-dismiss').addEventListener('click', closeNlpModal);
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeNlpModal();
        });
    }

    const titleEl = document.getElementById('nlp-modal-title');
    const contentEl = document.getElementById('nlp-modal-content');
    const highlightBtn = document.getElementById('nlp-btn-highlight');
    const currentGraphData = window.graphData;

    // Populate based on result type
    if (result.type === 'attack_path') {
        const d = result.data;
        titleEl.textContent = d.title;
        contentEl.innerHTML = `
            <div class="nlp-meta-strip">
                <span class="sev sev-${d.severity}">${d.severity} Severity</span>
                <span class="nlp-meta-item"><strong>Risk Score:</strong> ${d.totalRisk}</span>
                <span class="nlp-meta-item"><strong>Hops:</strong> ${d.hopCount}</span>
                <span class="nlp-meta-item"><strong>Classification:</strong> ${d.categories}</span>
            </div>

            <section class="nlp-section">
                <h4 class="nlp-section-head">Executive Briefing</h4>
                <p class="nlp-lead-text">${d.executiveSummary}</p>
            </section>

            <section class="nlp-section">
                <h4 class="nlp-section-head">Attack Chain Traversal (Hop by Hop)</h4>
                <div class="nlp-steps-list">
                    ${d.steps.map(s => `
                        <div class="nlp-step-card">
                            <span class="nlp-step-badge">${s.stepNum}</span>
                            <div class="nlp-step-text">${s.text}</div>
                        </div>
                    `).join('')}
                </div>
            </section>

            <section class="nlp-section">
                <h4 class="nlp-section-head">Security Reasoning & Exploitation Vectors</h4>
                <ul class="nlp-bullet-list">
                    ${d.reasoningPoints.map(r => `<li>${r}</li>`).join('')}
                </ul>
            </section>

            <section class="nlp-section">
                <h4 class="nlp-section-head">Actionable Remediation & Hardening</h4>
                <ul class="nlp-bullet-list nlp-remedy-list">
                    ${d.remediations.map(rem => `<li>${rem}</li>`).join('')}
                </ul>
            </section>
        `;

        highlightBtn.onclick = () => {
            closeNlpModal();
            // Switch to graph tab if needed
            document.querySelector('.tab-btn[data-view="graph"]')?.click();
            // Highlight path in script.js
            if (typeof togglePathHighlight === 'function' && currentGraphData?.attack_paths) {
                const idx = currentGraphData.attack_paths.indexOf(result.highlightPath);
                if (idx >= 0) togglePathHighlight(idx);
            }
        };
        highlightBtn.style.display = 'inline-flex';

    } else if (result.type === 'critical_node') {
        const d = result.data;
        titleEl.textContent = d.title;
        contentEl.innerHTML = `
            <section class="nlp-section">
                <h4 class="nlp-section-head">Executive Briefing</h4>
                <p class="nlp-lead-text">${d.executiveSummary}</p>
            </section>

            <section class="nlp-section">
                <h4 class="nlp-section-head">Architectural Reasoning</h4>
                <ul class="nlp-bullet-list">
                    ${d.reasoning.map(r => `<li>${r}</li>`).join('')}
                </ul>
            </section>

            ${d.secondary && d.secondary.length > 0 ? `
                <section class="nlp-section">
                    <h4 class="nlp-section-head">Secondary Chokepoints</h4>
                    <ul class="nlp-bullet-list">
                        ${d.secondary.map(s => `<li><strong>${s.name}</strong> — eliminates ${s.eliminated} paths (${s.pct}% of baseline)</li>`).join('')}
                    </ul>
                </section>
            ` : ''}

            <section class="nlp-section">
                <h4 class="nlp-section-head">Recommended Mitigations</h4>
                <ul class="nlp-bullet-list nlp-remedy-list">
                    ${d.remediations.map(r => `<li>${r}</li>`).join('')}
                </ul>
            </section>
        `;

        highlightBtn.onclick = () => {
            closeNlpModal();
            document.querySelector('.tab-btn[data-view="graph"]')?.click();
            if (result.highlightNodeId && typeof onNodeClick === 'function') {
                const nodeObj = (currentGraphData?.nodes || []).find(n => n.id === result.highlightNodeId);
                if (nodeObj) onNodeClick(new MouseEvent('click'), nodeObj);
            }
        };
        highlightBtn.style.display = 'inline-flex';

    } else if (result.type === 'blast_radius') {
        const d = result.data;
        titleEl.textContent = d.title;
        contentEl.innerHTML = `
            <section class="nlp-section">
                <h4 class="nlp-section-head">Executive Briefing</h4>
                <p class="nlp-lead-text">${d.executiveSummary}</p>
            </section>

            <section class="nlp-section">
                <h4 class="nlp-section-head">Impact Propagation by Depth</h4>
                <div class="nlp-steps-list">
                    ${d.layerBreakdown.map(l => `
                        <div class="nlp-step-card">
                            <span class="nlp-step-badge">Hop ${l.depth}</span>
                            <div class="nlp-step-text"><strong>${l.count} affected resources:</strong> ${l.names}</div>
                        </div>
                    `).join('')}
                </div>
            </section>

            <section class="nlp-section">
                <h4 class="nlp-section-head">Isolation Countermeasures</h4>
                <ul class="nlp-bullet-list nlp-remedy-list">
                    ${d.remediations.map(r => `<li>${r}</li>`).join('')}
                </ul>
            </section>
        `;

        highlightBtn.onclick = () => {
            closeNlpModal();
            document.querySelector('.tab-btn[data-view="graph"]')?.click();
            if (result.highlightNodeId && typeof onNodeClick === 'function') {
                const nodeObj = (currentGraphData?.nodes || []).find(n => n.id === result.highlightNodeId);
                if (nodeObj) onNodeClick(new MouseEvent('click'), nodeObj);
            }
        };
        highlightBtn.style.display = 'inline-flex';

    } else if (result.type === 'cycle') {
        titleEl.textContent = result.title;
        contentEl.innerHTML = `
            <section class="nlp-section">
                <h4 class="nlp-section-head">Executive Briefing</h4>
                <p class="nlp-lead-text">${result.executiveSummary}</p>
            </section>
            <section class="nlp-section">
                <h4 class="nlp-section-head">Hardening Measures</h4>
                <ul class="nlp-bullet-list nlp-remedy-list">
                    ${result.remediations.map(r => `<li>${r}</li>`).join('')}
                </ul>
            </section>
        `;
        highlightBtn.style.display = 'none';

    } else {
        titleEl.textContent = result.title || 'Assistant';
        contentEl.innerHTML = `<p class="nlp-lead-text">${result.text}</p>`;
        highlightBtn.style.display = 'none';
    }

    modal.classList.remove('hidden');
}

function closeNlpModal() {
    const modal = document.getElementById('nlp-modal');
    if (modal) modal.classList.add('hidden');
}

// ─── Initialize NLP Input Bar in Visualizer ─────────────────────────────────

function initNlpAssistantUI() {
    const nlpForm = document.getElementById('nlp-search-form');
    const nlpInput = document.getElementById('nlp-search-input');
    const promptChips = document.querySelectorAll('.nlp-chip');

    if (nlpForm && nlpInput) {
        nlpForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const q = nlpInput.value.trim();
            if (!q) return;
            const result = parseNaturalLanguageQuery(q, window.graphData);
            if (result) openNlpExplanationModal(result);
        });
    }

    promptChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const promptText = chip.dataset.query || chip.textContent.trim();
            if (nlpInput) nlpInput.value = promptText;
            const result = parseNaturalLanguageQuery(promptText, window.graphData);
            if (result) openNlpExplanationModal(result);
        });
    });
}

document.addEventListener('DOMContentLoaded', () => {
    initNlpAssistantUI();
});
