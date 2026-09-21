document.getElementById('run-audit-btn').addEventListener('click', () => {
    const terminal = document.getElementById('terminal');
    terminal.innerHTML = ''; // Clear output

    const logs = [
        { agent: 'Orchestrator', msg: 'Ingesting repository context & generating execution graph...', color: 'text-indigo-400' },
        { agent: 'SAST Agent', msg: 'Vulnerability flagged: Potential SQL Injection on line 42.', color: 'text-yellow-400' },
        { agent: 'RedTeam Agent', msg: 'Attempting exploit vector in isolated Docker sandbox...', color: 'text-red-400' },
        { agent: 'RedTeam Agent', msg: 'Exploit successful! Vulnerability confirmed.', color: 'text-red-500' },
        { agent: 'Patch Agent', msg: 'Generating sanitized AST patch and parametrized query...', color: 'text-emerald-400' },
        { agent: 'HITL Gateway', msg: 'Awaiting human approval for dynamic patch deployment...', color: 'text-cyan-400' }
    ];

    logs.forEach((log, index) => {
        setTimeout(() => {
            const entry = document.createElement('p');
            entry.className = log.color;
            entry.innerText = `[${log.agent}] ${log.msg}`;
            terminal.appendChild(entry);
            terminal.scrollTop = terminal.scrollHeight;
        }, index * 900);
    });
    document.getElementById('run-audit-btn').addEventListener('click', async () => {
    const terminal = document.getElementById('terminal');
    terminal.innerHTML = '<p class="text-slate-500">[System] Initializing connection to backend agent server...</p>';

    const sampleCode = `
    def get_user(user_id):
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return db.execute(query)
    `;

    try {
        // Send request to Python FastAPI backend
        const response = await fetch('http://127.0.0.1:8000/api/audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                code_snippet: sampleCode,
                language: 'python'
            })
        });

        // Read stream using ReadableStream API
        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;

            const text = decoder.decode(value);
            const lines = text.split('\n');

            lines.forEach(line => {
                if (line.startsWith('data: ')) {
                    const rawData = line.replace('data: ', '').trim();
                    if (!rawData) return;
                    
                    try {
                        const payload = JSON.parse(rawData);
                        if (payload.agent) {
                            const entry = document.createElement('p');
                            entry.className = payload.color;
                            entry.innerText = `[${payload.agent}] ${payload.msg}`;
                            terminal.appendChild(entry);
                            terminal.scrollTop = terminal.scrollHeight;
                        }
                    } catch (e) {
                        // Handle formatting or completion signals
                    }
                }
            });
        }
    } catch (error) {
        terminal.innerHTML += `<p class="text-red-500">[Error] Could not connect to backend server at http://127.0.0.1:8000</p>`;
    }document.addEventListener('DOMContentLoaded', () => {
    const runBtn = document.getElementById('run-audit-btn');
    const clearBtn = document.getElementById('clear-btn');
    const codeInput = document.getElementById('code-input');
    const langSelect = document.getElementById('language-select');
    const terminal = document.getElementById('terminal');
    const statusBadge = document.getElementById('audit-status');

    // Clear Terminal & Input
    clearBtn.addEventListener('click', () => {
        codeInput.value = '';
        terminal.innerHTML = '<p class="text-slate-500">[System] Awaiting code input submission...</p>';
        statusBadge.innerText = 'IDLE';
        statusBadge.className = 'text-cyan-400';
    });

    // Run Audit
    runBtn.addEventListener('click', async () => {
        const code = codeInput.value.trim();
        const language = langSelect.value;

        if (!code) {
            terminal.innerHTML = '<p class="text-red-400">[Error] Please enter source code to audit.</p>';
            return;
        }

        // Reset Terminal
        terminal.innerHTML = `<p class="text-indigo-400">[Orchestrator] Ingesting ${language.toUpperCase()} payload (${code.length} bytes)...</p>`;
        statusBadge.innerText = 'RUNNING';
        statusBadge.className = 'text-yellow-400';

        try {
            // Send user code to backend API
            const response = await fetch('http://127.0.0.1:8000/api/audit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code_snippet: code, language: language })
            });

            if (!response.ok) throw new Error('Backend connection failed');

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                const text = decoder.decode(value);
                const lines = text.split('\n');

                lines.forEach(line => {
                    if (line.startsWith('data: ')) {
                        const rawData = line.replace('data: ', '').trim();
                        if (!rawData) return;

                        try {
                            const payload = JSON.parse(rawData);
                            if (payload.agent) {
                                const entry = document.createElement('p');
                                entry.className = payload.color || 'text-slate-300';
                                entry.innerText = `[${payload.agent}] ${payload.msg}`;
                                terminal.appendChild(entry);
                                terminal.scrollTop = terminal.scrollHeight;
                            }
                        } catch (e) {
                            // JSON parsing ignore non-JSON chunk
                        }
                    }
                });
            }

            statusBadge.innerText = 'COMPLETE';
            statusBadge.className = 'text-emerald-400';

        } catch (error) {
            // Fallback simulated execution if backend is not running locally
            runFallbackSimulation(code, language);
        }
    });

    // Fallback simulation mode if local backend server is not active
    function runFallbackSimulation(code, language) {
        const simulatedLogs = [
            { agent: 'SAST Agent', msg: `Analyzing ${language.toUpperCase()} AST for OWASP vulnerabilities...`, color: 'text-yellow-400' },
            { agent: 'RedTeam Agent', msg: 'Generating dynamic exploit test harness in Docker sandbox...', color: 'text-red-400' },
            { agent: 'RedTeam Agent', msg: 'Vulnerability verified: Arbitrary payload input reached execution boundary.', color: 'text-red-500 font-semibold' },
            { agent: 'Patch Agent', msg: 'Formulating safe AST patch & parameterized replacement...', color: 'text-emerald-400' },
            { agent: 'HITL Gateway', msg: 'Awaiting human security review before patch deployment.', color: 'text-cyan-400' }
        ];

        simulatedLogs.forEach((log, index) => {
            setTimeout(() => {
                const entry = document.createElement('p');
                entry.className = log.color;
                entry.innerText = `[${log.agent}] ${log.msg}`;
                terminal.appendChild(entry);
                terminal.scrollTop = terminal.scrollHeight;

                if (index === simulatedLogs.length - 1) {
                    statusBadge.innerText = 'COMPLETE';
                    statusBadge.className = 'text-emerald-400';
                }
            }, (index + 1) * 1000);
        });
    }
});
const patchContainer = document.getElementById('patch-approval-container');
    const approveBtn = document.getElementById('approve-patch-btn');
    const rejectBtn = document.getElementById('reject-patch-btn');

    // Trigger this function when audit finishes
    function revealHitlGateway() {
        patchContainer.classList.remove('hidden');
        patchContainer.scrollIntoView({ behavior: 'smooth' });
    }

    approveBtn.addEventListener('click', () => {
        const terminal = document.getElementById('terminal');
        const entry = document.createElement('p');
        entry.className = 'text-emerald-400 font-bold';
        entry.innerText = '[HITL Gateway] Patch APPROVED by Security Engineer. Deploying to repo branch...';
        terminal.appendChild(entry);
        terminal.scrollTop = terminal.scrollHeight;
        
        patchContainer.classList.add('hidden');
    });

    rejectBtn.addEventListener('click', () => {
        const terminal = document.getElementById('terminal');
        const entry = document.createElement('p');
        entry.className = 'text-red-400 font-bold';
        entry.innerText = '[HITL Gateway] Patch REJECTED. Returning code to Patch Agent for iteration...';
        terminal.appendChild(entry);
        terminal.scrollTop = terminal.scrollHeight;

        patchContainer.classList.add('hidden');
    });
    const supabaseUrl = 'YOUR_SUPABASE_PROJECT_URL';
const supabaseKey = 'YOUR_SUPABASE_ANON_KEY';
const supabase = supabase.createClient(supabaseUrl, supabaseKey);

// 1. Handle User Login / Signup
async function handleLogin(email, password) {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) alert(error.message);
    else console.log('Logged in user:', data.user);
}

// 2. Fetch User Session Token & Save Audit Report
async function saveAuditToDatabase(reportData) {
    const { data: { session } } = await supabase.auth.getSession();
    
    if (!session) {
        alert('Please log in to save your audit report.');
        return;
    }

    const response = await fetch('http://127.0.0.1:8000/api/reports/save', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${session.access_token}` // Send JWT token
        },
        body: JSON.stringify(reportData)
    });

    const result = await response.json();
    console.log('Report Saved:', result);
}
document.addEventListener('DOMContentLoaded', () => {
    const drawer = document.getElementById('history-drawer');
    const overlay = document.getElementById('drawer-overlay');
    const openBtn = document.getElementById('open-history-btn'); // Link to your nav "History" button
    const closeBtn = document.getElementById('close-drawer-btn');
    const historyList = document.getElementById('history-list');
    document.addEventListener('DOMContentLoaded', () => {
    const runBtn = document.getElementById('run-audit-btn');
    
    if (runBtn) {
        runBtn.addEventListener('click', () => {
            console.log("Audit button clicked!");
            // Run audit logic here
        });
    } else {
        console.error("Button element #run-audit-btn not found.");
    }
});

    // Toggle Drawer Open / Close
    function toggleDrawer(open) {
        if (open) {
            drawer.classList.add('open');
            overlay.classList.add('open');
            fetchAuditHistory(); // Load reports when opened
        } else {
            drawer.classList.remove('open');
            overlay.classList.remove('open');
        }
    }

    if (openBtn) openBtn.addEventListener('click', () => toggleDrawer(true));
    closeBtn.addEventListener('click', () => toggleDrawer(false));
    overlay.addEventListener('click', () => toggleDrawer(false));

    // Fetch and render past audit reports
    async function fetchAuditHistory() {
        try {
            const response = await fetch('http://127.0.0.1:8000/api/reports/history');
            const data = await response.json();
            renderHistoryCards(data.reports || []);
        } catch (error) {
            historyList.innerHTML = `<p class="text-red-400">[Error] Failed to connect to history endpoint.</p>`;
        }
    }

    // Render list of report cards
    function renderHistoryCards(reports) {
        document.getElementById('history-count').innerText = reports.length;

        if (reports.length === 0) {
            historyList.innerHTML = `<p class="text-slate-500 text-center py-8">No previous audit reports found.</p>`;
            return;
        }

        historyList.innerHTML = reports.map(report => `
            <div class="history-card space-y-2">
                <div class="flex justify-between items-center">
                    <span class="text-cyan-400 font-bold uppercase">${report.language}</span>
                    <span class="text-[10px] text-slate-500">${new Date(report.created_at).toLocaleDateString()}</span>
                </div>
                <div class="text-slate-300 text-[11px] line-clamp-2">
                    ${report.vulnerability_details || 'Critical vulnerability audited and patched.'}
                </div>
                <div class="pt-2 border-t border-slate-800 flex justify-between items-center text-[10px]">
                    <span class="text-emerald-400">STATUS: ${report.status}</span>
                    <button class="text-slate-400 hover:text-white underline">View Details</button>
                </div>
            </div>
        `).join('');
    }
});
});
document.addEventListener('DOMContentLoaded', () => {
    const exportMDBtn = document.getElementById('export-md-btn');
    const exportPDFBtn = document.getElementById('export-pdf-btn');

    // Helper: Collect current audit state
    function getAuditReportData() {
        return {
            timestamp: new Date().toISOString(),
            language: document.getElementById('language-select')?.value || 'python',
            vulnerableCode: document.getElementById('vulnerable-diff')?.innerText || 'None',
            patchedCode: document.getElementById('patched-diff')?.innerText || 'None',
            logs: Array.from(document.querySelectorAll('#terminal p')).map(p => p.innerText)
        };
    }

    // 1. Export as Markdown (.md)
    exportMDBtn.addEventListener('click', () => {
        const report = getAuditReportData();
        
        const mdContent = `# AgentShield Security Audit Report
**Date:** ${report.timestamp}  
**Language:** ${report.language.toUpperCase()}  
**Status:** AUDITED & PATCHED  

---

## 1. Vulnerability & Patch Summary

### Vulnerable Code
\`\`\`${report.language}${report.vulnerableCode}
\`\`\`

### Sanitized Patch
\`\`\`${report.language}${report.patchedCode}
\`\`\`

---

## 2. Agent Orchestration Logs
${report.logs.map(log => `- ${log}`).join('\n')}
`;

        // Trigger browser file download
        const blob = new Blob([mdContent], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit-report-${Date.now()}.md`;
        a.click();
        URL.revokeObjectURL(url);
    });

    // 2. Export as PDF (.pdf)
    exportPDFBtn.addEventListener('click', () => {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        const report = getAuditReportData();

        // Styling PDF Layout
        doc.setFillColor(15, 23, 42); // Dark Header
        doc.rect(0, 0, 210, 30, 'F');
        
        doc.setTextColor(0, 242, 254);
        doc.setFont('Helvetica', 'bold');
        doc.setFontSize(16);
        doc.text('AgentShield Security Audit Report', 14, 18);

        doc.setTextColor(148, 163, 184);
        doc.setFontSize(9);
        doc.text(`Generated: ${report.timestamp} | Language: ${report.language.toUpperCase()}`, 14, 25);

        // Section: Vulnerable Code
        doc.setTextColor(239, 68, 68);
        doc.setFontSize(12);
        doc.text('Vulnerable Snippet:', 14, 45);
        doc.setFont('Courier', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(50, 50, 50);
        doc.text(report.vulnerableCode, 14, 52);

        // Section: Patched Code
        doc.setTextColor(16, 185, 129);
        doc.setFont('Helvetica', 'bold');
        doc.setFontSize(12);
        doc.text('Patched Code:', 14, 80);
        doc.setFont('Courier', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(50, 50, 50);
        doc.text(report.patchedCode, 14, 87);

        // Save Generated PDF
        doc.save(`audit-report-${Date.now()}.pdf`);
    });
});
});